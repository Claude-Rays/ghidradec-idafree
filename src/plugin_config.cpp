/**
 * @file plugin_config.cpp
 * @brief GhidraDec plugin configuration.
 * @copyright (c) 2017 Avast Software, (c) 2019-2026 Gregory Morse, MIT license.
 *
 * This port: settings live in IDA's registry (subkey "GhidraDec") instead of
 * ghidradec-config.json, so jsoncpp is no longer needed. The per-database
 * processor/compiler/sleigh overrides stay in the "GhidraConfig" netnode.
 *
 * The Ghidra folder is checked before Ghidra is used (ensureGhidraFolder): a
 * prebuilt plugin only knows the folder of the machine it was built on, so
 * the usual places are searched (ghidra_locate.cpp), and if Ghidra is not
 * found the user is asked for it once.
 */

#include <cstdint>
#include <algorithm>

#include "plugin_config.h"
#include "decompiler.h"
#include "ghidra_locate.h"
#include "sleighinterface.h"
#include "idaplugin.h"
#include <registry.hpp>

#ifndef GHIDRADEC_DEFAULT_GHIDRA_DIR
#define GHIDRADEC_DEFAULT_GHIDRA_DIR ""
#endif
// the Ghidra whose decompiler sources were compiled in (CMakeLists.txt)
#ifndef GHIDRADEC_GHIDRA_VERSION
#define GHIDRADEC_GHIDRA_VERSION ""
#endif

namespace {

const char REG_SUBKEY[] = "GhidraDec";

void applyEnvironmentConfig(idaplugin::RdGlobalInfo& rdgi)
{
	if (rdgi.ghidraPath.empty())
	{
		qstring ghidraDir;
		if (qgetenv("GHIDRADEC_GHIDRA_DIR", &ghidraDir))
		{
			rdgi.ghidraPath = ghidraDir.c_str();
		}
		else if (qgetenv("GHIDRA_INSTALL_DIR", &ghidraDir))
		{
			rdgi.ghidraPath = ghidraDir.c_str();
		}
		else
		{
			rdgi.ghidraPath = GHIDRADEC_DEFAULT_GHIDRA_DIR;
		}
	}

	qstring value;
	if (qgetenv("GHIDRADEC_PSPEC", &value))
	{
		rdgi.customPspec = value.c_str();
	}
	if (qgetenv("GHIDRADEC_CSPEC", &value))
	{
		rdgi.customCspec = value.c_str();
	}
	if (qgetenv("GHIDRADEC_SLEIGH", &value))
	{
		rdgi.customSlafile = value.c_str();
	}
	if (qgetenv("GHIDRADEC_CALL_STYLE", &value))
	{
		rdgi.customCallStyle = value.c_str();
	}
}

sval_t regSval(const char* name, sval_t def)
{
	return (sval_t)reg_read_int(name, (int)def, REG_SUBKEY);
}

int regInt(const char* name, int def)
{
	return reg_read_int(name, def, REG_SUBKEY);
}

void regWrite(const char* name, sval_t value)
{
	reg_write_int(name, (int)value, REG_SUBKEY);
}

} // anonymous namespace


namespace idaplugin {

/**
 * Read the settings from IDA's registry and the per-database netnode.
 */
void readConfig(RdGlobalInfo& rdgi)
{
	qstring path;
	if (reg_read_string(&path, "ghidraPath", REG_SUBKEY))
		rdgi.ghidraPath = path.c_str();
	rdgi.viewFeatures = (ushort)regInt("viewFeatures", ghidradec_default_view_features()) & VIEW_FEATURES_MASK;
	rdgi.cacheSize = regSval("cacheSize", 10);
	rdgi.maxPayload = regSval("maxPayload", 50);
	rdgi.timeout = regSval("timeout", 30);
	rdgi.cmtLevel = regSval("cmtLevel", 20);
	rdgi.alysChecks = (ushort)regInt("alysChecks", GHIDRADEC_DEFAULT_ANALYSIS_CHECKS);
	rdgi.dispChecks = (ushort)regInt("dispChecks", GHIDRADEC_DEFAULT_DISPLAY_CHECKS);
	rdgi.maxChars = regSval("maxChars", 100);
	rdgi.numChars = regSval("numChars", 2);
	rdgi.comStyle = regInt("comStyle", 0);
	rdgi.intFormat = regInt("intFormat", 2);
	rdgi.behaviorChecks = (ushort)regInt("behaviorChecks", GHIDRADEC_DEFAULT_BEHAVIOR_CHECKS);
	rdgi.splitDatatypeChecks = (ushort)regInt("splitDatatypeChecks", GHIDRADEC_DEFAULT_SPLIT_DATATYPE_CHECKS);
	rdgi.maxJumpTableSize = regSval("maxJumpTableSize", 4096);
	rdgi.maxInstructions = regSval("maxInstructions", 100000);
	rdgi.aliasBlock = regInt("aliasBlock", 2);
	rdgi.namespaceStrategy = regInt("namespaceStrategy", 0);
	rdgi.nanIgnore = regInt("nanIgnore", 1);
	rdgi.braceFormatFunction = regInt("braceFormatFunction", 2);
	rdgi.braceFormatIfElse = regInt("braceFormatIfElse", 0);
	rdgi.braceFormatLoop = regInt("braceFormatLoop", 0);
	rdgi.braceFormatSwitch = regInt("braceFormatSwitch", 0);

	readDatabaseConfig(rdgi);
}

/**
 * The Ghidra version this plugin was built with ("" if unknown).
 */
const char* ghidraBuildVersion()
{
	return GHIDRADEC_GHIDRA_VERSION;
}

static std::string versionText(const std::string& v)
{
	return v.empty() ? std::string("an unknown version") : "Ghidra " + v;
}

// a warning, once per IDA session, when the Ghidra folder is not the version
// the plugin was built with
static void checkGhidraVersion(const RdGlobalInfo& rdgi, bool interactive)
{
	static bool warned = false;
	std::string built = ghidraBuildVersion();
	std::string found = ghidraFolderVersion(rdgi.ghidraPath);
	if (built.empty() || found == built || warned)
		return;
	std::string text = "GhidraDec was built with Ghidra " + built + ", but the Ghidra folder " + rdgi.ghidraPath
		+ " has " + versionText(found) + ".\n"
		"Ghidra's decompiler (decompile.exe) and its processor files (.sla) must match the version GhidraDec "
		"was built with: with another one the decompilation may fail or stop.\n"
		"Use Ghidra " + built + " (GhidraDec > Settings, Ghidra folder), or build GhidraDec with your Ghidra.";
	msg("GhidraDec: %s\n", text.c_str());
	if (interactive) {
		warned = true;
		warning("%s", text.c_str());
	}
}

// asks for the Ghidra folder until it is a valid one; false if cancelled
static bool askGhidraFolder(RdGlobalInfo& rdgi)
{
	static const char form[] =
		"GhidraDec: Ghidra folder\n"
		"\n"
		"Ghidra was not found. GhidraDec runs Ghidra's decompiler and reads its processor files,\n"
		"so it needs a Ghidra installation (it was built with %A).\n"
		"\n"
		"Select the folder where Ghidra is unpacked (the one with ghidraRun.bat).\n"
		"It is saved for your user (GhidraDec > Settings changes it).\n"
		"\n"
		"<Ghidra folder:F::64::>\n"
		"\n";
	std::string built = versionText(ghidraBuildVersion());
	char path[QMAXPATH];
	qstrncpy(path, rdgi.ghidraPath.c_str(), sizeof(path));
	for (;;) {
		if (ask_form(form, built.c_str(), path) != ASKBTN_YES)
			return false;
		std::string dir = normalizeGhidraFolder(path);
		if (!dir.empty()) {
			rdgi.ghidraPath = dir;
			reg_write_string("ghidraPath", dir.c_str(), REG_SUBKEY);
			msg("GhidraDec: Ghidra folder set to %s (%s).\n", dir.c_str(), versionText(ghidraFolderVersion(dir)).c_str());
			return true;
		}
		warning("No Ghidra installation in\n%s\n\n"
			"The folder must contain Ghidra\\Features\\Decompiler\\os\\win_x86_64\\decompile.exe.", path);
	}
}

/**
 * Make sure rdgi.ghidraPath is a Ghidra installation before it is used: the
 * configured folder, else one found in the usual places (for this session
 * only), else (interactive) the one the user selects (saved). A Ghidra of
 * another version than the build gives a warning, once.
 * @return @c false, with *err, if there is no Ghidra (or the user cancelled).
 */
bool ensureGhidraFolder(RdGlobalInfo& rdgi, bool interactive, std::string* err)
{
	std::string dir = normalizeGhidraFolder(rdgi.ghidraPath);
	if (dir.empty()) {
		std::vector<std::string> found = findGhidraFolders(GHIDRADEC_DEFAULT_GHIDRA_DIR, ghidraBuildVersion());
		if (!found.empty()) {
			dir = found.front();
			std::string what = rdgi.ghidraPath.empty() ? std::string("no Ghidra folder is configured")
				: "Ghidra is not in " + rdgi.ghidraPath;
			msg("GhidraDec: %s; using the one found in %s (%s).\n", what.c_str(), dir.c_str(),
				versionText(ghidraFolderVersion(dir)).c_str());
		}
	}
	if (!dir.empty()) {
		rdgi.ghidraPath = dir;
	} else if (!interactive || !askGhidraFolder(rdgi)) {
		if (err != nullptr)
			*err = "Ghidra was not found: set the Ghidra installation folder in GhidraDec > Settings.";
		return false;
	}
	checkGhidraVersion(rdgi, interactive);
	return true;
}

/**
 * Per-database overrides (processor spec, compiler spec, sleigh file, prototype).
 * Called again whenever a database is opened.
 */
void readDatabaseConfig(RdGlobalInfo& rdgi)
{
	rdgi.customPspec.clear();
	rdgi.customCspec.clear();
	rdgi.customSlafile.clear();
	rdgi.customCallStyle.clear();

	netnode nn("GhidraConfig");
	qstring qs;
	if (nn != BADNODE && nn.valstr(&qs) > 0) {
		std::vector<std::string> split({ std::string() });
		for (char ch : qs) {
			if (ch == ';') split.push_back(std::string());
			else if (ch != 0) split.back().push_back(ch);
		}
		split.resize(4);
		rdgi.customPspec = split[0];
		rdgi.customCspec = split[1];
		rdgi.customSlafile = split[2];
		rdgi.customCallStyle = split[3];
	}

	applyEnvironmentConfig(rdgi);
}

/**
 * Save the settings into IDA's registry and the per-database netnode.
 */
void saveConfig(RdGlobalInfo& rdgi)
{
	reg_write_string("ghidraPath", rdgi.ghidraPath.c_str(), REG_SUBKEY);
	regWrite("viewFeatures", rdgi.viewFeatures);
	regWrite("cacheSize", rdgi.cacheSize);
	regWrite("maxPayload", rdgi.maxPayload);
	regWrite("timeout", rdgi.timeout);
	regWrite("cmtLevel", rdgi.cmtLevel);
	regWrite("alysChecks", rdgi.alysChecks);
	regWrite("dispChecks", rdgi.dispChecks);
	regWrite("maxChars", rdgi.maxChars);
	regWrite("numChars", rdgi.numChars);
	regWrite("comStyle", rdgi.comStyle);
	regWrite("intFormat", rdgi.intFormat);
	regWrite("behaviorChecks", rdgi.behaviorChecks);
	regWrite("splitDatatypeChecks", rdgi.splitDatatypeChecks);
	regWrite("maxJumpTableSize", rdgi.maxJumpTableSize);
	regWrite("maxInstructions", rdgi.maxInstructions);
	regWrite("aliasBlock", rdgi.aliasBlock);
	regWrite("namespaceStrategy", rdgi.namespaceStrategy);
	regWrite("nanIgnore", rdgi.nanIgnore);
	regWrite("braceFormatFunction", rdgi.braceFormatFunction);
	regWrite("braceFormatIfElse", rdgi.braceFormatIfElse);
	regWrite("braceFormatLoop", rdgi.braceFormatLoop);
	regWrite("braceFormatSwitch", rdgi.braceFormatSwitch);

	netnode nn("GhidraConfig", 0, true);
	nn.set((rdgi.customPspec + ";" + rdgi.customCspec + ";" + rdgi.customSlafile + ";" + rdgi.customCallStyle).c_str());
}

int idaapi sleighCB(int button_code, form_actions_t& fa)
{
	RdGlobalInfo* decompInfo = (RdGlobalInfo*)fa.get_ud();
	qstring formGhidraDecPluginSettings =
		"BUTTON YES Compile\n"
		"GhidraDec Sleigh Pcode Snippet Compiler\n"
		"\n"
		"\n"
		"Enter Pcode snippet here and use the compile button to see the output.\n"
		"\n"
		"<Editor:t1:0:40::>\n"
		"<Output:t2:0:40::>\n"
		"\n";
	textctrl_info_t tinfo, toutinfo;
	tinfo.flags |= TXTF_AUTOINDENT | TXTF_ACCEPTTABS | TXTF_LINENUMBERS | TXTF_FIXEDFONT;
	tinfo.tabsize = 2;
	tinfo.text = "";
	toutinfo.flags |= TXTF_READONLY | TXTF_FIXEDFONT;
	toutinfo.tabsize = 0;
	toutinfo.text = "";
	int ok;
	std::string pspec, cspec, sleighfilename;
	if (decompInfo->customSlafile.empty() &&
		decompInfo->pm->canDecompileInput() &&
		detectProcCompiler(decompInfo, pspec, cspec, sleighfilename)) {
	}
	if (!decompInfo->customSlafile.empty()) sleighfilename = decompInfo->customSlafile;
	do {
		if (tinfo.text.size() != 0) {
			try {
				toutinfo.text = DecompInterface::compilePcodeSnippet(sleighfilename,
					tinfo.text.c_str(), std::vector<std::pair<std::string, int>>(), std::vector<std::pair<std::string, int>>()).c_str();
			} catch (DecompError& err) {
				toutinfo.text = err.explain.c_str();
			}
		}
		ok = ask_form(formGhidraDecPluginSettings.c_str(), &tinfo, &toutinfo);
	} while (ok == ASKBTN_YES);

	if (ok == 0) {
		// ESC or CANCEL
		return true;
	}
	return false;
}

int idaapi displayCB(int button_code, form_actions_t& fa)
{
	RdGlobalInfo* decompInfo = (RdGlobalInfo*)fa.get_ud();
	sval_t cmtLevel = decompInfo->cmtLevel, maxChars = decompInfo->maxChars, numChars = decompInfo->numChars;
	int comStyle = decompInfo->comStyle, intFormat = decompInfo->intFormat;
	int namespaceStrategy = decompInfo->namespaceStrategy;
	int braceFormatFunction = decompInfo->braceFormatFunction;
	int braceFormatIfElse = decompInfo->braceFormatIfElse;
	int braceFormatLoop = decompInfo->braceFormatLoop;
	int braceFormatSwitch = decompInfo->braceFormatSwitch;
	ushort dispChecks = decompInfo->dispChecks;
	qstring formGhidraDecPluginSettings =
		"GhidraDec Plugin Settings\n"
		"\n"
		"\n"
		"Settings will be permanently stored and you will not have to fill them each time you run decompilation.\n"
		"\n"
		"<Display printing of type casts:C>\n"
		"<Display EOL comments:C>\n"
		"<Display Header comment:C>\n"
		"<Display Line Numbers (future):C>\n"
		"<Legacy namespace checkbox (unused):C>\n"
		"<Display PLATE comments:C>\n"
		"<Display POST comments:C>\n"
		"<Display PRE comments:C>\n"
		"<Display Warning comments:C>\n"
		"<Print 'NULL' for null pointers:C>\n"
		"<Print calling convention name:C>\n"
		"<Hide implied extension casts:C>\n"
		"<Canonical local names (v1, v2...):C>>\n"
		"<Comment line indent level:D::::>\n"
		"<Maximum characters in a code line:D::::>\n"
		"<Number of characters per indent level:D::::>\n"
		"<Comment style:b:0:18::>\n"
		"<Integer format:b:0:12::>\n"
		"<Namespace display:b:0:12::>\n"
		"<Function brace style:b:0:12::>\n"
		"<If/else brace style:b:0:12::>\n"
		"<Loop brace style:b:0:12::>\n"
		"<Switch brace style:b:0:12::>\n"
		"\n";
	qstrvec_t cstyles, iformats, namespaceStyles;
	qstrvec_t braceFunctionStyles, braceIfElseStyles, braceLoopStyles, braceSwitchStyles;
	cstyles.push_back("C /* */");
	cstyles.push_back("C++ //");
	iformats.push_back("Hex");
	iformats.push_back("Dec");
	iformats.push_back("Best");
	namespaceStyles.push_back("Minimal");
	namespaceStyles.push_back("None");
	namespaceStyles.push_back("All");
	for (qstrvec_t* styles : { &braceFunctionStyles, &braceIfElseStyles, &braceLoopStyles, &braceSwitchStyles }) {
		styles->push_back("Same");
		styles->push_back("Next");
		styles->push_back("Blank");
	}

	int ok = ask_form(formGhidraDecPluginSettings.c_str(),
		&dispChecks,
		&cmtLevel, &maxChars, &numChars,
		&cstyles, &comStyle, &iformats, &intFormat,
		&namespaceStyles, &namespaceStrategy,
		&braceFunctionStyles, &braceFormatFunction,
		&braceIfElseStyles, &braceFormatIfElse,
		&braceLoopStyles, &braceFormatLoop,
		&braceSwitchStyles, &braceFormatSwitch
	);

	if (ok != ASKBTN_YES) {
		// ESC or CANCEL
		return true;
	} else {
		decompInfo->cmtLevel = cmtLevel;
		decompInfo->dispChecks = dispChecks;
		decompInfo->maxChars = maxChars;
		decompInfo->numChars = numChars;
		decompInfo->comStyle = comStyle;
		decompInfo->intFormat = intFormat;
		decompInfo->namespaceStrategy = namespaceStrategy;
		decompInfo->braceFormatFunction = braceFormatFunction;
		decompInfo->braceFormatIfElse = braceFormatIfElse;
		decompInfo->braceFormatLoop = braceFormatLoop;
		decompInfo->braceFormatSwitch = braceFormatSwitch;
	}
	return false;
}

int idaapi behaviorCB(int button_code, form_actions_t& fa)
{
	RdGlobalInfo* decompInfo = (RdGlobalInfo*)fa.get_ud();
	ushort alysChecks = decompInfo->alysChecks;
	ushort behaviorChecks = decompInfo->behaviorChecks;
	ushort splitDatatypeChecks = decompInfo->splitDatatypeChecks;
	sval_t maxJumpTableSize = decompInfo->maxJumpTableSize;
	sval_t maxInstructions = decompInfo->maxInstructions;
	int aliasBlock = decompInfo->aliasBlock;
	int nanIgnore = decompInfo->nanIgnore;

	qstring formGhidraDecPluginSettings =
		"GhidraDec Decompiler Behavior Options\n"
		"\n"
		"\n"
		"Settings will be permanently stored and you will not have to fill them each time you run decompilation.\n"
		"\n"
		"<Eliminate unreachable code:C>\n"
		"<Ignore unimplemented instructions:C>\n"
		"<Infer constant pointers:C>\n"
		"<Respect readonly flags:C>\n"
		"<Simplify extended integer operations:C>\n"
		"<Simplify predication:C>\n"
		"<Use inplace assignment operators:C>>\n"
		"<Analyze for loops:C>\n"
		"<Allow processor context changes during disassembly:C>\n"
		"<Treat unimplemented instructions as fatal:C>\n"
		"<Treat reinterpreted bytes as fatal:C>\n"
		"<Treat too many instructions as fatal:C>\n"
		"<Record jump-table load data:C>>\n"
		"<Maximum jump table entries:D::::>\n"
		"<Maximum instructions per function:D::::>\n"
		"<Alias blocking:b:0:12::>\n"
		"<Split structure assignments:C>\n"
		"<Split array assignments:C>\n"
		"<Split pointer load/store assignments:C>>\n"
		"<NaN handling:b:0:12::>\n"
		"\n";

	qstrvec_t aliasBlocks, nanIgnores;
	aliasBlocks.push_back("None");
	aliasBlocks.push_back("Struct");
	aliasBlocks.push_back("Array");
	aliasBlocks.push_back("All");
	nanIgnores.push_back("None");
	nanIgnores.push_back("Compare");
	nanIgnores.push_back("All");

	int ok = ask_form(formGhidraDecPluginSettings.c_str(),
		&alysChecks,
		&behaviorChecks,
		&maxJumpTableSize, &maxInstructions,
		&aliasBlocks, &aliasBlock,
		&splitDatatypeChecks,
		&nanIgnores, &nanIgnore
	);

	if (ok != ASKBTN_YES) {
		return true;
	} else {
		decompInfo->alysChecks = alysChecks;
		decompInfo->behaviorChecks = behaviorChecks;
		decompInfo->splitDatatypeChecks = splitDatatypeChecks;
		decompInfo->maxJumpTableSize = maxJumpTableSize;
		decompInfo->maxInstructions = maxInstructions;
		decompInfo->aliasBlock = aliasBlock;
		decompInfo->nanIgnore = nanIgnore;
	}
	return false;
}

/**
 * Present plugin configuration form to developer.
 * @param rdgi Plugin's global information.
 * @return @c True if cancelled, @c false otherwise.
 */
bool askUserToConfigurePlugin(RdGlobalInfo& rdgi)
{
	char cGhidraPath[QMAXPATH], cPspecPath[QMAXPATH],
		cCspecPath[QMAXPATH], cSlaPath[QMAXPATH];

	if (rdgi.ghidraPath.empty())
	{
		std::string pattern = rdgi.ghidraPath;
		qstrncpy(cGhidraPath, pattern.c_str(), QMAXPATH);
	}
	else
	{
		qstrncpy(cGhidraPath, rdgi.ghidraPath.c_str(), QMAXPATH);
	}

	qstring formGhidraDecPluginSettings =
		//"BUTTON NO Refresh Prototype (must if Compiler Spec changed)\n"
		"GhidraDec Plugin Settings\n"
		"%*\n"
		"\n"
		"Settings will be permanently stored and you will not have to fill them each time you run decompilation.\n"
		"\n"
		"Ghidra installation folder (GhidraDec was built with %A; empty: find it in the usual places):\n"
		"<Ghidra Folder:F1::60::>\n"
		"<Use Extra Parameter Identification Phase:C>\n"
		"<Back up IDA database before decompilation:C>>\n"
		"<Cache Size (Functions):D::::>\n"
		"<Decompiler Max-Payload (MBytes):D::::>\n"
		"<Decompiler Timeout (seconds):D::::>\n"
		"<Display Options:B::::>\n"
		"\n"
		"<Decompiler Behavior Options:B::::>\n"
		"\n"
		"<Sleigh Pcode Snippet Compiler:B::::>\n"
		"\n"
		"Following Settings are per database and stored in the .idb/.i64 file (IDA reports %A-bit processor %A).\n"
		"<Processor Spec:f2::60::>\n"
		"<Compiler Spec:f3::60::>\n"
		"<Sleigh file:f4::60::>\n"
		"<Prototype Evaluation:b:0:24::>\n"
		"\n";
	int curProto = -1;
	std::string cspec, pspec, sleighfilename, protoeval;
	if ((rdgi.customCspec.empty() || rdgi.customPspec.empty() || rdgi.customSlafile.empty()) &&
		rdgi.pm->canDecompileInput() &&
		detectProcCompiler(&rdgi, pspec, cspec, sleighfilename)) {
	}
	if (!rdgi.customCspec.empty()) cspec = rdgi.customCspec;
	if (!rdgi.customPspec.empty()) pspec = rdgi.customPspec;
	if (!rdgi.customSlafile.empty()) sleighfilename = rdgi.customSlafile;
	qstrncpy(cPspecPath, pspec.c_str(), QMAXPATH);
	qstrncpy(cCspecPath, cspec.c_str(), QMAXPATH);
	qstrncpy(cSlaPath, sleighfilename.c_str(), QMAXPATH);
	int ok;
	sval_t cacheSize = rdgi.cacheSize, maxPayload = rdgi.maxPayload, timeout = rdgi.timeout;
	// the check boxes start at bit 1 (bit 0 was the removed graph view)
	ushort viewFeatures = ushort(rdgi.viewFeatures >> 1);
	std::vector<std::string> vec;
	do {
		qstrvec_t protoTypes;
		vec.clear();
		int defIdx = -1;
		if (!cspec.empty()) DecompInterface::getProtoEvals(cspec, vec, &defIdx);
		std::vector<std::string> protoValues;
		protoValues.push_back("default");
		std::string defaultLabel = "default";
		if (defIdx >= 0 && defIdx < (int)vec.size())
			defaultLabel += " (" + vec[defIdx] + ")";
		protoTypes.push_back(defaultLabel.c_str());
		for (const std::string& proto : vec) {
			if (proto.empty() || std::find(protoValues.begin(), protoValues.end(), proto) != protoValues.end())
				continue;
			protoValues.push_back(proto);
			protoTypes.push_back(proto.c_str());
		}
		if (!rdgi.customCallStyle.empty() && rdgi.customCallStyle != "unknown")
			protoeval = rdgi.customCallStyle;
		else
			protoeval = ccToStr(inf_cc_cm, 0, true);
		curProto = 0;
		for (size_t i = 0; i < protoValues.size(); i++)
			if (protoeval == protoValues[i])
				curProto = (int)i;
		if (curProto == -1) curProto = 0;

		ok = ask_form(formGhidraDecPluginSettings.c_str(),
			&rdgi,
			versionText(ghidraBuildVersion()).c_str(),
			cGhidraPath, &viewFeatures,
			&cacheSize, &maxPayload, &timeout,
			&displayCB, &behaviorCB, &sleighCB,
			inf_is_32bit() ? (inf_is_64bit() ? "32/64" : "32") : (inf_is_64bit() ? "64" : "?"),
			inf_procname.c_str(),
			cPspecPath, cCspecPath, cSlaPath,
			&protoTypes, &curProto
		);
		if (ok == ASKBTN_YES) {
			if (cspec != cCspecPath) {
				cspec = cCspecPath;
				warning("Since the compiler specification file was changed, please confirm the prototype in use");
			continue;
			}
		}
		vec = protoValues;
	} while (false);
	if (ok != ASKBTN_YES)
	{
		// ESC or CANCEL
		return true;
	}
	else
	{
		rdgi.ghidraPath = cGhidraPath;
		rdgi.viewFeatures = ushort(viewFeatures << 1);
		rdgi.cacheSize = cacheSize;
		rdgi.maxPayload = maxPayload;
		rdgi.timeout = timeout;
		
		//these are saved and loaded through the IDB
		rdgi.customPspec = cPspecPath;
		rdgi.customCspec = cCspecPath;
		rdgi.customSlafile = cSlaPath;
		rdgi.customCallStyle = curProto <= 0 ? "" : vec[curProto];
	}
	return false;
}

/**
 * @return @c True if cancelled, @c false otherwise.
 */
bool pluginConfigurationMenu(RdGlobalInfo& rdgi)
{
	std::string oldPath = rdgi.ghidraPath;
	for (;;)
	{
		if (askUserToConfigurePlugin(rdgi))
		{
			rdgi.ghidraPath = oldPath;
			return true;
		}
		// empty: found in the usual places when it is needed
		if (rdgi.ghidraPath.empty())
			break;
		std::string dir = normalizeGhidraFolder(rdgi.ghidraPath);
		if (!dir.empty())
		{
			rdgi.ghidraPath = dir;
			break;
		}
		warning("No Ghidra installation in\n%s\n\n"
			"The folder must contain Ghidra\\Features\\Decompiler\\os\\win_x86_64\\decompile.exe.",
			rdgi.ghidraPath.c_str());
	}
	saveConfig(rdgi);
	if (!rdgi.ghidraPath.empty())
		checkGhidraVersion(rdgi, true);
	return false;
}

} // namespace idaplugin
