/**
 * @file defs.cpp
 * @brief Plugin-global definitions: process launching, configuration checks,
 *        database name index.
 * @copyright (c) 2017 Avast Software, (c) 2019-2026 Gregory Morse, MIT license.
 */

#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <algorithm>

#include "defs.h"
#include "plugin_config.h"
#include "decompiler.h"
#include "sleighinterface.h"

namespace idaplugin {

void stopDecompilation(RdGlobalInfo* di, bool deregister, bool checkonly, bool closehandles)
{
	if (di->decompPid) {
		try {
			if (deregister) di->idacb->decInt->deregisterProgram();
		} catch (DecompError& e) {
			WARNING_GUI("Caught deregistration error: " << e.explain);
		}
		int rc = 0;
		if (check_process_exit(di->hDecomp, &rc, 0) != 0) {
			if (checkonly) return;
			term_process(di->hDecomp);
		}
		di->decompPid = 0;
	}
	if (closehandles) {
		if (di->rdHandle != -1) {
			_close(di->rdHandle); di->rdHandle = -1;
		}
		if (di->wrHandle != -1) {
			_close(di->wrHandle); di->wrHandle = -1;
		}
	}
}

/**
 * Run the Ghidra decompiler process with its stdin/stdout connected to pipes.
 * IDA has no console, so the child gets duplicated pipe ends as std handles.
 * @return 0 on success, 1 on failure.
 */
int runCommand(
		const std::string& cmd,
		const std::string& args,
		intptr_t* pid,
		void** hdl,
		int* readpipe,
		int* writepipe,
		bool showWarnings)
{
	launch_process_params_t procInf;
	procInf.path = cmd.c_str();
	procInf.args = args.empty() ? nullptr : args.c_str();
	procInf.flags = LP_HIDE_WINDOW;
	PROCESS_INFORMATION pi{};
	procInf.info = &pi;

	int rpipefd[2], wpipefd[2];
	if (_pipe(rpipefd, 4096, _O_BINARY | _O_NOINHERIT) < 0)
		WARNING_GUI("Pipe creation failed");
	if (_pipe(wpipefd, 4096, _O_BINARY | _O_NOINHERIT) < 0)
		WARNING_GUI("Pipe creation failed");

	// _dup() creates inheritable copies for the child's stdin/stdout.
	int fdStdIn = _dup(wpipefd[0]);
	int fdStdOut = _dup(rpipefd[1]);
	_close(rpipefd[1]);
	_close(wpipefd[0]);
	*readpipe = rpipefd[0];
	*writepipe = wpipefd[1];
	procInf.in_handle = _get_osfhandle(fdStdIn);
	procInf.out_handle = _get_osfhandle(fdStdOut);
	procInf.err_handle = procInf.out_handle;

	qstring errbuf;
	DBG_MSG("Launching: " << cmd << " " << args << "\n");
	void* p = launch_process(procInf, &errbuf);
	_close(fdStdOut);
	_close(fdStdIn);

	auto closePipes = [&]() {
		if (*readpipe != -1) {
			_close(*readpipe); *readpipe = -1;
		}
		if (*writepipe != -1) {
			_close(*writepipe); *writepipe = -1;
		}
	};

	if (p == nullptr)
	{
		closePipes();
		if (showWarnings)
		{
			WARNING_GUI("launch_process(" << cmd << ") failed to launch " << errbuf.c_str() << "\n");
		}
		return 1;
	}
	*hdl = p;
	if (pid)
	{
		*pid = pi.dwProcessId;
		if (pi.hThread != nullptr && pi.hThread != INVALID_HANDLE_VALUE)
			CloseHandle(pi.hThread);
	}

	int rc = 0;
	auto cpe = check_process_exit(p, &rc, 0);
	DBG_MSG("Launched Pid: " << p << " Exit code: " << cpe << " Return code: " << rc << "\n");

	if (pid && (cpe != 1 || rc != 0))
	{
		*pid = 0;
	}
	if (cpe != 1 || rc != 0)
	{
		closePipes();
		if (showWarnings)
		{
			WARNING_GUI("The decompiler process " << cmd << " exited prematurely (code " << rc << ")\n");
		}
		return 1;
	}

	return 0;
}

//------------------------------------------------------------------------------
// Names
//------------------------------------------------------------------------------
std::string demangledShortName(const std::string& name)
{
	if (name.empty())
		return "";
	std::string out = demangle_name(name.c_str(), MNG_SHORT_FORM).c_str();
	// Cut the argument list: the first '(' outside template arguments and
	// operator names (operator(), operator<, ...).
	int depth = 0;
	for (size_t i = 0; i < out.size(); ++i)
	{
		if (out.compare(i, 8, "operator") == 0)
		{
			i += 8;
			if (out.compare(i, 2, "()") == 0)
				i += 2;
			while (i < out.size() && strchr("<>=!+-*/%^&|~[],", out[i]) != nullptr)
				++i;
			--i;
		}
		else if (out[i] == '<')
			++depth;
		else if (out[i] == '>' && depth > 0)
			--depth;
		else if (out[i] == '(' && depth == 0)
		{
			out.resize(i);
			break;
		}
	}
	return out;
}

std::string functionDisplayName(ea_t ea)
{
	std::string raw = get_name(ea).c_str();
	std::string name = demangledShortName(raw);
	if (name.empty())
		name = raw;
	while (!name.empty() && name[0] == '.')
		name.erase(name.begin());
	std::replace(name.begin(), name.end(), '.', '_');
	std::replace(name.begin(), name.end(), '@', '_');
	return name;
}

//------------------------------------------------------------------------------
// NameIndex
//------------------------------------------------------------------------------
void NameIndex::rebuild()
{
	functions.clear();
	globals.clear();

	// Functions are found by their IDA name and by the name shown in the
	// output: "A::f" (demangled) and its last part "f", as the viewer
	// highlights it.
	for (size_t i = 0; i < get_func_qty(); ++i)
	{
		func_t* fnc = getn_func(i);
		qstring name;
		if (fnc == nullptr || get_func_name(&name, fnc->start_ea) <= 0)
			continue;
		functions[name.c_str()] = NameItem{ name.c_str(), fnc->start_ea, true };
	}
	for (size_t i = 0; i < get_func_qty(); ++i)
	{
		func_t* fnc = getn_func(i);
		if (fnc == nullptr)
			continue;
		std::string shown = functionDisplayName(fnc->start_ea);
		size_t sep = shown.rfind("::");
		for (const std::string& alias : { shown, sep == std::string::npos ? std::string() : shown.substr(sep + 2) })
		{
			if (!alias.empty() && functions.find(alias) == functions.end())
				functions[alias] = NameItem{ alias, fnc->start_ea, true };
		}
	}

	// Named data items. Imports (function typed data) count as functions,
	// so the viewer can jump to them.
	for (int i = 0; i < get_segm_qty(); ++i)
	{
		segment_t* seg = getnseg(i);
		if (seg == nullptr)
			continue;
		for (ea_t head = next_head(seg->start_ea - 1, seg->end_ea);
			head != BADADDR;
			head = next_head(head, seg->end_ea))
		{
			flags64_t f = get_flags(head);
			if (!is_data(f) || !has_any_name(f))
				continue;
			qstring name;
			if (get_name(&name, head) <= 0)
				continue;
			tinfo_t tif;
			if (get_tinfo(&tif, head) && tif.is_func())
			{
				if (functions.find(name.c_str()) == functions.end())
					functions[name.c_str()] = NameItem{ name.c_str(), head, true };
				continue;
			}
			globals[name.c_str()] = NameItem{ name.c_str(), head, false };
		}
	}
}

const NameItem* NameIndex::function(const std::string& name) const
{
	auto it = functions.find(name);
	return it == functions.end() ? nullptr : &it->second;
}

const NameItem* NameIndex::global(const std::string& name) const
{
	auto it = globals.find(name);
	return it == globals.end() ? nullptr : &it->second;
}

//------------------------------------------------------------------------------
// RdGlobalInfo
//------------------------------------------------------------------------------
RdGlobalInfo::RdGlobalInfo(GhidraDec* pm)
{
	this->pm = pm;
	navigationActual = navigationList.end();
}

bool RdGlobalInfo::isAllDecompilation()
{
	return !outputFile.empty();
}

bool RdGlobalInfo::isSelectiveDecompilation()
{
	return !isAllDecompilation();
}

bool RdGlobalInfo::isDecompilerInSpecifiedPath() const
{
	struct stat st;
	return stat((decompilerExePath + decompilerExeName).c_str(), &st) == 0;
}

bool RdGlobalInfo::isDecompilerInSystemPath()
{
	char buff[QMAXPATH];
	if (search_path(buff, sizeof(buff), decompilerExeName.c_str(), false))
	{
		std::string full = buff;
		auto slash = full.find_last_of("/\\");
		if (slash != std::string::npos)
		{
			decompilerExePath = full.substr(0, slash + 1);
			return isDecompilerInSpecifiedPath();
		}
	}
	return false;
}

bool RdGlobalInfo::isUseThreads() const
{
	return useThreads;
}

void RdGlobalInfo::setIsUseThreads(bool f)
{
	useThreads = f;
}

/**
 * Locate decompile.exe inside the Ghidra installation (found or asked for if
 * the configured one is not there).
 * @return @c True if canceled, @c false otherwise.
 */
bool RdGlobalInfo::configureDecompilation()
{
	if (!ensureGhidraFolder(*this, true))
		return true;
	decompilerExePath = ghidraPath + "/Ghidra/Features/Decompiler/os/win_x86_64/";
	if (!isDecompilerInSpecifiedPath())
		decompilerExePath = ghidraPath + "/Ghidra/Features/Decompiler/os/win64/";
	DBG_MSG("Found " << decompilerExeName << " at " << decompilerExePath << "\n");
	return false;
}

} // namespace idaplugin
