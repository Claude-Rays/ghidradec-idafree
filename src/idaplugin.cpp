/**
 * @file idaplugin.cpp
 * @brief Plugin entry point (IDA Free/Pro 9.4+ port, IDA C++ SDK 9.4).
 * @copyright (c) 2017 Avast Software, (c) 2019-2026 Gregory Morse,
 *            (c) 2026 ClaudeMonkey (Claude-Rays/ghidradec-idafree), MIT license.
 *
 * Runtime dependency: a Ghidra installation (decompile.exe in
 * Ghidra/Features/Decompiler/os/win_x86_64 and the .sla/.ldefs/.pspec/.cspec
 * files in Ghidra/Processors). No JDK is needed.
 */

#include <windows.h>

#include <cstdint>
#include <ctime>
#include <fstream>
#include <iostream>

#include "api.h"
#include "code_viewer.h"
#include "decompiler.h"
#include "defs.h"
#include "ghidradec_icon.h"
#include "plugin_config.h"
#include "sleighinterface.h"
#include "idaplugin.h"

namespace idaplugin {

static const char MENU_ID[] = "GhidraDec";
static const char MENU_PATH[] = "GhidraDec/";

struct MenuItem
{
	const char* name;
	const char* label;
	const char* hotkey;
	size_t arg;
};

static const MenuItem MENU_ITEMS[] =
{
	{ "ghidradec:Decompile",    "Decompile function",           PLUGIN_HOTKEY,  0 },
	{ "ghidradec:DecompileAll", "Decompile all to file...",     "Ctrl-Shift-G", 1 },
	{ "ghidradec:Settings",     "Settings...",                  nullptr,        2 },
	{ "ghidradec:About",        "About GhidraDec",              nullptr,        3 },
};

static bool hasValidNavigationPosition(const RdGlobalInfo* decompInfo)
{
	return decompInfo != nullptr
			&& !decompInfo->navigationList.empty()
			&& decompInfo->navigationActual != decompInfo->navigationList.end();
}

static bool shouldBackupIdbBeforeDecompile(const RdGlobalInfo* decompInfo)
{
	return decompInfo != nullptr
			&& (decompInfo->viewFeatures & VIEW_FEATURE_BACKUP_IDB) != 0;
}

static bool fileExists(const std::string& path)
{
	return !path.empty() && qfileexist(path.c_str());
}

static std::string dirName(const std::string& path)
{
	char buf[QMAXPATH];
	qstrncpy(buf, path.c_str(), sizeof(buf));
	qdirname(buf, sizeof(buf), buf);
	return buf;
}

GhidraDec::GhidraDec()
{
	move_backward_ah.pm = this;
	move_forward_ah.pm = this;
	change_fnc_comment_ah.pm = this;
	change_fnc_global_name_ah.pm = this;
	open_xrefs_ah.pm = this;
	open_calls_ah.pm = this;
	change_fnc_type_ah.pm = this;
	jump_to_asm_ah.pm = this;
	viewListener.pm = this;

	init();
}

GhidraDec::~GhidraDec()
{
	term();
}

/**
 * Kill old thread if still running.
 */
void GhidraDec::killDecompilation(bool bTerminate)
{
	if (decompInfo->decompRunning)
	{
		INFO_MSG("Unfinished decompilation was KILLED !!! Only one decompilation can run at a time.\n");
		{ // must be a locked unit otherwise race condition can occur
			qmutex_locker_t lock(decompInfo->qm);
			decompInfo->exiting = true;
			if (decompInfo->uiExecutingTask != -1) {
				if (cancel_exec_request(decompInfo->uiExecutingTask)) {
					qsem_post(decompInfo->termSem);
				}
			}
		}
		stopDecompilation(decompInfo, false, false, false); // first kill only the decompilation process
		qthread_join(decompInfo->decompThread);
		qthread_free(decompInfo->decompThread);
		decompInfo->decompThread = nullptr;

		stopDecompilation(decompInfo, false, false, true);
		decompInfo->uiExecutingTask = -1;
		decompInfo->exiting = false;
		decompInfo->decompRunning = false;
	} else {
		if (decompInfo->decompThread != nullptr) {
			qthread_join(decompInfo->decompThread);
			qthread_free(decompInfo->decompThread);
			decompInfo->decompThread = nullptr;
		}
		if (bTerminate) stopDecompilation(decompInfo, true, false, true);
		else stopDecompilation(decompInfo, false, true, true); // make sure did not exit before starting again
	}
}

/**
 * Save IDA database before decompilation to protect it if something goes wrong.
 * @param inSitu If true, DB is saved with the same name as IDA default database.
 * @param suffix If @p inSitu is false, use this suffix to distinguish DBs.
 */
void GhidraDec::saveIdaDatabase(bool inSitu, const std::string &suffix)
{
	INFO_MSG("Saving IDA database ...\n");

	std::string workIdb = decompInfo->workIdb;

	auto dotPos = workIdb.find_last_of(".");
	if (dotPos != std::string::npos)
	{
		workIdb.erase(dotPos, std::string::npos);
	}

	if (!inSitu)
	{
		workIdb += suffix;
	}

	workIdb += std::string(".") + IDB_EXT;

	save_database(workIdb.c_str(), DBFL_COMP);

	INFO_MSG("IDA database saved into :  " << workIdb << "\n");
}

/**
 * Refresh the function/global name index used by the code viewer.
 * (Upstream generated a full RetDec JSON config database here.)
 */
void GhidraDec::generatePluginDatabase()
{
	decompInfo->names.rebuild();
}

/**
 * Find out if input file is relocatable -- object file.
 * @return @c True if file relocatable, @c false otherwise.
 */
bool GhidraDec::isRelocatable()
{
	if (inf_filetype == f_COFF && inf_start_ea == BADADDR)
	{
		return true;
	}
	else if (inf_filetype == f_ELF)
	{
		std::ifstream infile(decompInfo->inputPath, std::ios::binary);
		if (infile.good())
		{
			// relocatable -- constant 0x1 at <0x10-0x11>
			infile.seekg(0x10, std::ios::beg);
			char b1 = 0;
			char b2 = 0;
			if (infile.get(b1) && infile.get(b2)
					&& std::size_t(b1) + std::size_t(b2) == 1)
			{
				return true;
			}
		}
	}

	// f_BIN || f_PE || f_HEX || other
	return false;
}

/**
 * Decompile only provided function or if nothing provided then the current function under focus.
 * @param fnc2decomp Function to decompile.
 * @param force      If @c true, decompilation is always performed.
 */
void GhidraDec::runSelectiveDecompilation(func_t *fnc2decomp, bool force)
{
	apiSessionEnd(decompInfo);
	if (decompInfo->decompThread != nullptr) {
		if (!decompInfo->decompRunning) killDecompilation(false);
		else if (ask_buttons("Yes", "No", nullptr, ASKBTN_YES, "A prior decompilation is still running, would you like to terminate it to process the new request?") == ASKBTN_YES) {
			killDecompilation(true);
		} else return;
	}
	// A viewer restored with the desktop follows functions before the plugin
	// ran (run() prepares it): prepare it when something is decompiled.
	const bool alreadyShown = fnc2decomp != nullptr && !force
			&& decompInfo->fnc2code.find(fnc2decomp) != decompInfo->fnc2code.end();
	if (!alreadyShown && (decompInfo->decompilerExePath.empty() || decompInfo->workIdb.empty()))
	{
		if (!auto_is_ok())
		{
			INFO_MSG("GhidraDec plugin cannot run because the initial autoanalysis has not been finished.\n");
			return;
		}
		if (!prepareDecompilation())
		{
			return;
		}
	}
	if (isRelocatable() && inf_min_ea != 0)
	{
		WARNING_GUI(decompInfo->pluginName << " version " << decompInfo->pluginVersion
				<< " can selectively decompile only relocatable objects loaded at 0x0.\n"
				"Rebase the program to 0x0 or use full decompilation.");
		return;
	}

	// Decompilation triggered by double click.
	//
	if (fnc2decomp)
	{
		if (hasValidNavigationPosition(decompInfo))
		{
			auto eraseFrom = decompInfo->navigationActual;
			++eraseFrom;
			decompInfo->navigationList.erase(eraseFrom, decompInfo->navigationList.end());
		}
		else
		{
			decompInfo->navigationList.clear();
		}
		decompInfo->navigationList.push_back(fnc2decomp);
		decompInfo->navigationActual = decompInfo->navigationList.end();
		decompInfo->navigationActual--;

		// Show existing function.
		//
		auto fit = decompInfo->fnc2code.find(fnc2decomp);
		if (!force && fit != decompInfo->fnc2code.end())
		{
			decompInfo->decompiledFunction = fnc2decomp;

			qstring fncName;
			get_func_name(&fncName, fnc2decomp->start_ea);
			INFO_MSG("Show already decompiled function: " << fncName.c_str()
					<< " @ " << std::hex << fnc2decomp->start_ea << "\n");

			ShowOutput show(decompInfo);
			show.execute();

			return;
		}
		// Decompile new function.
		//
		else
		{
			createRangesFromSelectedFunction(*decompInfo, fnc2decomp);
		}
	}
	// Decompilation run from our viewer.
	//
	else if (get_current_viewer() == decompInfo->custViewer
			|| get_current_viewer() == decompInfo->codeViewer)
	{
		// Re-decompile current function.
		//
		if (decompInfo->decompiledFunction)
		{
			createRangesFromSelectedFunction(
					*decompInfo,
					decompInfo->decompiledFunction);

			if (hasValidNavigationPosition(decompInfo))
			{
				decompInfo->navigationList.erase(
						decompInfo->navigationActual,
						decompInfo->navigationList.end());
			}
			else
			{
				decompInfo->navigationList.clear();
			}
			decompInfo->navigationList.push_back(decompInfo->decompiledFunction);
			decompInfo->navigationActual = decompInfo->navigationList.end();
			decompInfo->navigationActual--;
		}
		// No current function -> something went wrong.
		//
		else
		{
			return;
		}
	}
	// Decompilation run from some other window.
	//
	else
	{
		ea_t addr = get_screen_ea();
		func_t *fnc = get_func(addr);

		// Decompilation run from IDA disasm window (or some other window that allows it).
		//
		if (fnc)
		{
			createRangesFromSelectedFunction(*decompInfo, fnc);
			decompInfo->decompiledFunction = fnc;

			decompInfo->navigationList.clear();
			decompInfo->navigationList.push_back( decompInfo->decompiledFunction );
			decompInfo->navigationActual = decompInfo->navigationList.end();
			decompInfo->navigationActual--;
		}
		// Bad window or bad position in disasm code.
		//
		else
		{
			WARNING_GUI("Function must be selected by the cursor.\n");
			return;
		}
	}

	INFO_MSG("Running Ghidra decompiler plugin:\n");

	if (shouldBackupIdbBeforeDecompile(decompInfo))
	{
		saveIdaDatabase();
	}
	generatePluginDatabase();
	decompileInput(*decompInfo);
}

/**
 * Decompile everything, but do not show it in viewer, instead dump it into file.
 */
void GhidraDec::runAllDecompilation()
{
	// Batch mode (see batchTimer): write to GHIDRADEC_BATCH_OUTPUT without
	// dialogs. The decompilation still runs on its worker thread because the
	// protocol thread needs the main thread to answer IDA database queries.
	qstring batchOutput;
	if (qgetenv("GHIDRADEC_BATCH_OUTPUT", &batchOutput) && !batchOutput.empty())
	{
		decompInfo->outputFile = batchOutput.c_str();
		decompInfo->ranges.clear();
		decompInfo->decompiledFunction = nullptr;
		INFO_MSG("Batch decompilation into " << decompInfo->outputFile << "\n");
		generatePluginDatabase();
		decompInfo->decompRunning = true;
		decompileInput(*decompInfo);
		if (decompInfo->decompThread == nullptr)
			decompInfo->decompRunning = false;
		return;
	}

	std::string defaultOut = decompInfo->inputPath + ".c";
	char* tmp;
	int iChoice;
	do {
		tmp = ask_file(true, defaultOut.c_str(), "%s", "Save decompiled file");
		if (tmp == nullptr) // canceled
		{
			return;
		}
		if (qfileexist(tmp)) {
			iChoice = ask_yn(ASKBTN_YES, "Overwrite existing file '%s'?", tmp);
			if (iChoice == ASKBTN_CANCEL) return;
		} else iChoice = ASKBTN_YES;
	} while (iChoice == ASKBTN_NO);

	decompInfo->outputFile = tmp;
	decompInfo->ranges.clear();
	decompInfo->decompiledFunction = nullptr;

	INFO_MSG("Selected file: " << decompInfo->outputFile << "\n");

	if (shouldBackupIdbBeforeDecompile(decompInfo))
	{
		saveIdaDatabase();
	}
	generatePluginDatabase();
	decompileInput(*decompInfo);
}

/**
 * Locate the input binary and the working directory of the database.
 */
bool GhidraDec::setInputPath()
{
	char buff[QMAXPATH];

	get_root_filename(buff, sizeof(buff));
	std::string inName = buff;

	get_input_file_path(buff, sizeof(buff));
	std::string inPath = buff;

	std::string idb = get_path(PATH_TYPE_IDB);
	std::string id0 = get_path(PATH_TYPE_ID0);
	std::string workIdb = !idb.empty() ? idb : id0;
	std::string workDir = workIdb.empty() ? std::string() : dirName(workIdb);
	if (workIdb.empty() || workDir.empty())
	{
		WARNING_GUI("Cannot decompile this input file, IDB and ID0 are not set.\n");
		return false;
	}

	// The input file is only needed for ELF relocatable detection and as the
	// default name of the decompile-all output, so a missing file is not fatal.
	if (!fileExists(inPath))
	{
		char candidate[QMAXPATH];
		qmakepath(candidate, sizeof(candidate), workDir.c_str(), inName.c_str(), nullptr);
		if (fileExists(candidate))
		{
			INFO_MSG("Input not found at its original location, using \"" << candidate << "\".\n");
			inPath = candidate;
		}
		else
		{
			inPath = candidate;
		}
	}

	decompInfo->inputName = inName;
	decompInfo->inputPath = inPath;
	decompInfo->workDir = workDir;
	decompInfo->workIdb = workIdb;

	DBG_MSG("Input Path : " << decompInfo->inputPath << "\n");
	DBG_MSG("Work dir   : " << decompInfo->workDir << "\n");
	return true;
}

/**
 * Perform startup check that determines, if plugin can decompile IDA's input file:
 * a Ghidra language (.ldefs) must declare an IDA-PRO external name for the
 * current IDA processor module.
 */
bool GhidraDec::canDecompileInput()
{
	if (!setInputPath())
	{
		return false;
	}

	decompInfo->li.clear();
	decompInfo->toolMap.clear();
	DecompInterface::getLangFiles(decompInfo->ghidraPath + "/Ghidra/Processors", "IDA-PRO", decompInfo->toolMap, decompInfo->li);
	// metapc is reported for 16-bit but not reported in Ghidra
	for (size_t i = 0; i < decompInfo->li.size(); i++) {
		if (decompInfo->li[i].processor == "x86" && decompInfo->li[i].size == 16) {
			decompInfo->toolMap["metapc"].push_back((int)i); break;
		}
	}
	auto addProcessorAlias = [this](const std::string& processor, const std::string& alias) {
		for (size_t i = 0; i < decompInfo->li.size(); i++) {
			if (decompInfo->li[i].processor != processor) continue;
			auto& matches = decompInfo->toolMap[alias];
			const int index = (int)i;
			if (std::find(matches.begin(), matches.end(), index) == matches.end())
				matches.push_back(index);
		}
	};
	for (size_t i = 0; i < decompInfo->li.size(); i++) {
		if (decompInfo->li[i].processor == "AARCH64") {
			decompInfo->toolMap[decompInfo->li[i].bigEndian ? "armb" : "arm"].push_back((int)i);
			decompInfo->toolMap["aarch64"].push_back((int)i);
		}
	}
	addProcessorAlias("RISCV", "riscv");
	addProcessorAlias("Dalvik", "dalvik");
	addProcessorAlias("SuperH4", "sh3");
	addProcessorAlias("SuperH4", "sh3b");
	addProcessorAlias("SuperH4", "sh4");
	addProcessorAlias("SuperH4", "sh4b");
	addProcessorAlias("SuperH4", "sh2a");
	std::string pname = inf_procname;
	std::transform(pname.begin(), pname.end(), pname.begin(), [](unsigned char c) { return std::tolower(c); });
	return decompInfo->toolMap.find(pname) != decompInfo->toolMap.end();
}

/**
 * Find decompile.exe and the Ghidra language of the database.
 * @return @c false (after telling the user) if nothing can be decompiled.
 */
bool GhidraDec::prepareDecompilation()
{
	if (decompInfo->configureDecompilation())
	{
		return false;
	}

	if (!canDecompileInput() && decompInfo->customSlafile.empty())
	{
		WARNING_GUI("No Ghidra language matches the IDA processor \"" << inf_procname << "\".\n"
				"Check the Ghidra folder in GhidraDec settings or set the sleigh/pspec/cspec files manually.");
		return false;
	}
	return true;
}

/**
 * Plugin run function.
 * @param arg 0 = decompile current function, 1 = decompile all into a file,
 *            2 = settings dialog.
 */
bool idaapi GhidraDec::run(size_t arg)
{
	if (arg == 2)
	{
		if (!pluginConfigurationMenu(*decompInfo)) {
			killDecompilation(true); // settings do not take effect without restarting process
		}
		return true;
	}
	if (arg == 3)
	{
		info("GhidraDec %s by ClaudeMonkey (Claude-Rays/ghidradec-idafree)\n\n"
			"Ghidra decompiler for IDA Free/Pro 9.4+\n"
			"Port of GhidraDec by Gregory Morse (GregoryMorse/GhidraDec).\n\n"
			"Ghidra in use: %s",
			decompInfo->pluginVersion.c_str(),
			decompInfo->ghidraPath.empty() ? "<not found yet>" : decompInfo->ghidraPath.c_str());
		return true;
	}

	apiSessionEnd(decompInfo);
	if (!auto_is_ok())
	{
		INFO_MSG("GhidraDec plugin cannot run because the initial autoanalysis has not been finished.\n");
		return false;
	}
	if (decompInfo->decompThread != nullptr) {
		if (!decompInfo->decompRunning) killDecompilation(false);
		else if (ask_buttons(nullptr, nullptr, nullptr, ASKBTN_YES, "HIDECANCEL\nA prior decompilation is still running, would you like to terminate it to process the new request?") == ASKBTN_YES) {
			killDecompilation(true);
		}
		else return false;
	}

	if (!prepareDecompilation())
	{
		return false;
	}

	if (arg == 0)
	{
		runSelectiveDecompilation();
	}
	else if (arg == 1)
	{
		runAllDecompilation();
	}
	else
	{
		WARNING_GUI(decompInfo->pluginName << " cannot handle argument '" << arg << "'.\n");
		return false;
	}
	return true;
}

/**
 * HT_UI: context menus of our viewer and of the disassembly.
 */
ssize_t idaapi GhidraDec::on_event(ssize_t notification_code, va_list va)
{
	// the viewer is saved with the desktop and restored when the database opens
	if (notification_code == ui_get_widget_config)
	{
		const TWidget* widget = va_arg(va, const TWidget*);
		jobj_t* cfg = va_arg(va, jobj_t*);
		viewGetDesktopConfig(decompInfo, widget, cfg);
		return 0;
	}
	if (notification_code == ui_set_widget_config)
	{
		const TWidget* widget = va_arg(va, const TWidget*);
		const jobj_t* cfg = va_arg(va, const jobj_t*);
		viewSetDesktopConfig(decompInfo, widget, cfg);
		return 0;
	}
	if (notification_code == ui_create_desktop_widget)
	{
		const char* title = va_arg(va, const char*);
		const jobj_t* cfg = va_arg(va, const jobj_t*);
		return ssize_t(viewCreateForDesktop(decompInfo, title, cfg));
	}
	if (notification_code != ui_populating_widget_popup)
		return 0;

	va_list copy;
	va_copy(copy, va);
	TWidget* view = va_arg(copy, TWidget*);
	TPopupMenu* popup = va_arg(copy, TPopupMenu*);
	va_end(copy);

	if (get_widget_type(view) == BWN_DISASM)
	{
		attach_action_to_popup(view, popup, MENU_ITEMS[0].name, "GhidraDec/");
		return 0;
	}
	return ui_callback(decompInfo, static_cast<int>(notification_code), va);
}

/**
 * HT_VIEW: forget our widgets when IDA closes them.
 */
ssize_t idaapi GhidraDec::view_listener_t::on_event(ssize_t code, va_list va)
{
	if (code == view_close && pm != nullptr)
	{
		TWidget* view = va_arg(va, TWidget*);
		if (view != nullptr)
			pm->onViewClose(view);
	}
	return 0;
}

void GhidraDec::onViewClose(TWidget* view)
{
	if (decompInfo->codeViewer == view) {
		decompInfo->codeViewer = nullptr;
	} else if (decompInfo->custViewer == view) {
		decompInfo->custViewer = nullptr;
		if (decompInfo->codeViewer) {
			close_widget(decompInfo->codeViewer, 0);
			decompInfo->codeViewer = nullptr;
		}
	}
}

void GhidraDec::registerMenu()
{
	create_menu(MENU_ID, "GhidraDec", "Help");
	for (size_t i = 0; i < qnumber(MENU_ITEMS); ++i)
	{
		const MenuItem& item = MENU_ITEMS[i];
		menuHandlers[i].pm = this;
		menuHandlers[i].arg = item.arg;
		action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(
				item.name, item.label, &menuHandlers[i], this,
				item.hotkey, item.label, decompInfo->pluginIconId);
		if (register_action(desc))
			attach_action_to_menu(MENU_PATH, item.name, SETMENU_APP);
	}
}

void GhidraDec::unregisterMenu()
{
	for (const MenuItem& item : MENU_ITEMS)
	{
		detach_action_from_menu(MENU_PATH, item.name);
		unregister_action(item.name);
	}
	delete_menu(MENU_ID);
}

/**
 * Plugin initialization (called once per database).
 */
void GhidraDec::init()
{
	decompInfo = new RdGlobalInfo(this);
	decompInfo->pluginIconId = load_custom_icon(
		ghidradec_icon_png,
		sizeof(ghidradec_icon_png),
		"png");

	readConfig(*decompInfo);
	// found now if it is not where the settings (or the build) say; asked
	// for when it is first needed
	bool ghidraFound = ensureGhidraFolder(*decompInfo, false);

	decompInfo->qm = qmutex_create();
	decompInfo->termSem = qsem_create(nullptr, 0);
	hook_event_listener(HT_UI, this);
	hook_event_listener(HT_VIEW, &viewListener);
	registerPermanentActions();
	registerMenu();
	apiAttach(this);

	INFO_MSG(decompInfo->pluginName << " " << decompInfo->pluginVersion
			<< " by ClaudeMonkey (Claude-Rays/ghidradec-idafree)"
			<< " loaded ("<< PLUGIN_HOTKEY << " decompiles the current function, "
			"menu GhidraDec for the rest). Ghidra: "
			<< (ghidraFound ? decompInfo->ghidraPath : std::string("<not found, asked for when it is needed>")) << "\n");

	// Batch mode (IDA Free has no -S scripts): GHIDRADEC_BATCH_OUTPUT=<file.c>
	// decompiles everything once the database is ready and exits IDA.
	qstring batchOutput;
	if (qgetenv("GHIDRADEC_BATCH_OUTPUT", &batchOutput) && !batchOutput.empty())
		register_timer(500, batchTimer, this);
}

int idaapi GhidraDec::batchTimer(void* ud)
{
	GhidraDec* self = static_cast<GhidraDec*>(ud);
	RdGlobalInfo* di = self->decompInfo;
	if (!self->batchStarted)
	{
		auto_wait();
		if (!auto_is_ok())
			return 500; // FLIRT signatures applied late queue more analysis
		self->batchStarted = true;
		di->decompSuccess = false;
		self->run(1);
		return 250;
	}
	if (di->decompRunning)
		return 250; // keep the main thread free for the worker's requests
	self->killDecompilation(true);
	INFO_MSG("Batch decompilation " << (di->decompSuccess ? "succeeded" : "FAILED") << "\n");
	// In the GUI (IDA Free has no batch mode) qexit() from a timer may hang,
	// so ask the UI to quit instead (QuitIDA action). QuitIDA
	// closes the database and unloads this plugin before it returns, so the
	// DLL is pinned first: the return goes back into this function.
	HMODULE self_module = nullptr;
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
		reinterpret_cast<LPCWSTR>(&GhidraDec::batchTimer), &self_module);
	int code = di->decompSuccess ? 0 : 1;
	if (!process_ui_action("QuitIDA"))
		qexit(code);
	return -1;
}

/**
 * Plugin termination (database closed or IDA exits).
 */
void GhidraDec::term()
{
	if (decompInfo == nullptr)
	{
		return;
	}
	apiDetach(this);
	killDecompilation(true);
	if (decompInfo->idacb != nullptr) {
		delete decompInfo->idacb;
		decompInfo->idacb = nullptr;
	}
	unhook_event_listener(HT_VIEW, &viewListener);
	unhook_event_listener(HT_UI, this);
	if (decompInfo->retitleTimer != nullptr) {
		unregister_timer(decompInfo->retitleTimer);
		decompInfo->retitleTimer = nullptr;
	}
	if (decompInfo->codeViewer) {
		close_widget(decompInfo->codeViewer, 0);
		decompInfo->codeViewer = nullptr;
	}
	if (decompInfo->custViewer) {
		close_widget(decompInfo->custViewer, 0);
		decompInfo->custViewer = nullptr;
	}
	unregisterMenu();
	unregister_action("ghidradec:ActionJumpToAsm");
	unregister_action("ghidradec:ActionChangeFncGlobName");
	unregister_action("ghidradec:ActionOpenXrefs");
	unregister_action("ghidradec:ActionOpenCalls");
	unregister_action("ghidradec:ActionChangeFncType");
	unregister_action("ghidradec:ActionChangeFncComment");
	unregister_action("ghidradec:ActionMoveForward");
	unregister_action("ghidradec:ActionMoveBackward");
	if (decompInfo->pluginIconId >= 0)
	{
		free_custom_icon(decompInfo->pluginIconId);
		decompInfo->pluginIconId = -1;
	}
	qsem_free(decompInfo->termSem);
	qmutex_free(decompInfo->qm);
	delete decompInfo;
	decompInfo = nullptr;
}

} // namespace idaplugin

using namespace idaplugin;

static plugmod_t* idaapi init()
{
	return new GhidraDec();
}

/**
 * Plugin interface definition.
 */
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,          // one GhidraDec instance per database
	init,
	nullptr,               // terminate (PLUGIN_MULTI)
	nullptr,               // invoke (PLUGIN_MULTI)
	"Ghidra decompiler for IDA Free/Pro. " PLUGIN_COPYRIGHT,
	"Decompiles the current function with Ghidra's decompile.exe",
	"GhidraDec",
	"",                    // the hotkey is bound to the GhidraDec/Decompile action
};
