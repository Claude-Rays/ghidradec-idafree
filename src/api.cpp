/**
 * @file api.cpp
 * @brief C API for other plugins (Diaphora-ng).
 *
 * Found at run time with GetProcAddress: no link time dependency. Requests
 * and responses are UTF-8 JSON, so no C++ structure crosses the DLL boundary;
 * new optional fields keep the version. Main thread only: the decompilation
 * runs synchronously and the database queries of decompile.exe are answered
 * in place.
 *
 * ghidradec_diff_functions: the function of the open database and the one of
 *   the other version, both decompiled now, as an aligned line diff with the
 *   changed spans of each line (pairdiff.cpp). The other version is a binary
 *   on disk that GhidraDec loads and decompiles itself (filedec.cpp; kept
 *   loaded until ghidradec_session_end).
 *
 * Parameter identification is off: it writes the prototypes it finds into
 * the database, and both versions of a diff must be decompiled the same way.
 *
 * The two phases that make the diff of two builds readable are optional
 * fields of the request (both true when missing, as before they existed):
 * "canonical_names" names the locals v1, v2... on both sides (level 1,
 * localnames.cpp) and "rename_locals" renames the locals of NEW after OLD
 * (level 2, pairdiff.cpp). The response echoes what was applied.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "defs.h"
#include "api.h"
#include "decompiler.h"
#include "filedec.h"
#include "idaplugin.h"
#include "json.hpp"
#include "pairdiff.h"
#include "plugin_config.h"
#include "sleighinterface.h"

// 2: 'b' of ghidradec_diff_functions may be a binary on disk
// 3: 'b' is always a binary on disk; no stored decompilations
//    (ghidradec_decompile_function, "code" of 'a' and 'b') any more
#define GHIDRADEC_API_VERSION 3

namespace idaplugin {

using ghidradec_json::json_t;
using ghidradec_json::json_quote;

static GhidraDec* g_plugin = nullptr;

void apiAttach(GhidraDec* pm)
{
	g_plugin = pm;
}

void apiDetach(GhidraDec* pm)
{
	if (g_plugin == pm) {
		fileSessionEnd();
		g_plugin = nullptr;
	}
}

void apiSessionEnd(RdGlobalInfo* di)
{
	if (di == nullptr || !di->apiReady)
		return;
	di->apiReady = false;
	if (di->idacb != nullptr && di->idacb->decInt != nullptr)
		stopDecompilation(di, true, false, true);
}

//------------------------------------------------------------------------------
static std::string hexStr(uint64_t v)
{
	char buf[32];
	qsnprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
	return buf;
}

static uint64_t parseAddr(const std::string& s)
{
	return strtoull(s.c_str(), nullptr, 0);
}

static std::string errorJson(const std::string& err)
{
	return "{\"ok\":false,\"api\":" + std::to_string(GHIDRADEC_API_VERSION) + ",\"error\":" + json_quote(err) + "}";
}

static std::string strList(const std::vector<std::string>& v)
{
	std::string out = "[";
	for (size_t i = 0; i < v.size(); i++)
		out += (i == 0 ? "" : ",") + json_quote(v[i]);
	return out + "]";
}

//------------------------------------------------------------------------------
// the decompiler, ready for synchronous calls (what run() + decompileInput()
// + localDecompilation() do, without dialogs, thread or viewer)
//------------------------------------------------------------------------------
// a new decompiler process for each diff: the database may have changed
static bool prepare(std::string* err)
{
	GhidraDec* pm = g_plugin;
	if (pm == nullptr || pm->decompInfo == nullptr) {
		*err = "GhidraDec is not loaded for this database.";
		return false;
	}
	RdGlobalInfo* di = pm->decompInfo;
	if (di->decompRunning) {
		*err = "GhidraDec is busy with another decompilation; try again when it finishes.";
		return false;
	}
	if (di->decompThread != nullptr) {
		// a finished decompilation of the viewer: its process is gone
		pm->killDecompilation(false);
		di->apiReady = false;
	}
	if (!auto_is_ok()) {
		*err = "the initial autoanalysis has not finished.";
		return false;
	}
	apiSessionEnd(di);

	di->decompilerExePath = di->ghidraPath + "/Ghidra/Features/Decompiler/os/win_x86_64/";
	if (!di->isDecompilerInSpecifiedPath())
		di->decompilerExePath = di->ghidraPath + "/Ghidra/Features/Decompiler/os/win64/";
	if (!di->isDecompilerInSpecifiedPath()) {
		*err = "Ghidra was not found: set the Ghidra installation folder in GhidraDec > Settings.";
		return false;
	}
	di->decCmd = di->decompilerExePath + di->decompilerExeName;
	if (!pm->canDecompileInput() && di->customSlafile.empty()) {
		std::string proc = inf_procname;
		*err = "no Ghidra language matches the IDA processor \"" + proc + "\".";
		return false;
	}
	pm->generatePluginDatabase();
	if (di->idacb == nullptr)
		di->idacb = new IdaCallback(di);

	std::string sleigh, pspec, cspec;
	if ((di->customCspec.empty() || di->customPspec.empty() || di->customSlafile.empty())
		&& !detectProcCompiler(di, pspec, cspec, sleigh)) {
		*err = "no matching Ghidra processor found.";
		return false;
	}
	if (!di->customCspec.empty()) cspec = di->customCspec;
	if (!di->customPspec.empty()) pspec = di->customPspec;
	if (!di->customSlafile.empty()) sleigh = di->customSlafile;
	di->idacb->init(sleigh, pspec, cspec);

	if (di->idacb->decInt == nullptr)
		di->idacb->decInt = new DecompInterface();
	std::vector<CoreType> cts(&defaultCoreTypes[0], &defaultCoreTypes[numDefCoreTypes]);
	try {
		di->idacb->decInt->setup(di->idacb, di->idacb->sleighfilename, di->idacb->pspec, di->idacb->cspec, cts,
			di->idacb->getOpts(), (int)di->timeout, (int)di->maxPayload);
		if (di->decompPid == 0)
			di->idacb->decInt->registerProgram();
	} catch (DecompError& e) {
		*err = "cannot start Ghidra's decompiler: " + e.explain;
		stopDecompilation(di, false, false, true);
		return false;
	}
	di->apiReady = true;
	return true;
}

// one function: its C text and prototype
static bool decompile(ea_t ea, bool canonical, std::string* code, std::string* proto, std::string* name, ea_t* start,
	std::string* err)
{
	RdGlobalInfo* di = g_plugin->decompInfo;
	func_t* f = get_func(ea);
	if (f == nullptr) {
		*err = "no function at " + hexStr(ea) + ".";
		return false;
	}
	ea = f->start_ea;
	*start = ea;
	if (di->idacb->imports.find(ea) != di->idacb->imports.end()) {
		*err = "the function at " + hexStr(ea) + " is an import.";
		return false;
	}
	auto known = di->idacb->allFuncNames.find(ea);
	*name = known != di->idacb->allFuncNames.end() && !known->second.empty() ? known->second : functionDisplayName(ea);
	std::string display, e;
	bool saved = di->apiNoParamId, savedNames = di->apiCanonicalNames;
	di->apiNoParamId = true;
	di->apiCanonicalNames = canonical;
	*code = di->idacb->tryDecomp(defaultDecMode, ea, *name, display, e);
	di->apiNoParamId = saved;
	di->apiCanonicalNames = savedNames;
	if (!e.empty()) {
		while (!e.empty() && (e.back() == '\n' || e.back() == '\r'))
			e.pop_back();
		*err = e;
		return false;
	}
	auto p = di->idacb->funcProtos.find(ea);
	*proto = p != di->idacb->funcProtos.end() ? p->second : std::string();
	return true;
}

static std::string spansJson(const std::vector<ghidradec_diff::Span>& spans)
{
	std::string out = "[";
	for (size_t i = 0; i < spans.size(); i++)
		out += std::string(i == 0 ? "" : ",") + "[" + std::to_string(spans[i].start) + "," + std::to_string(spans[i].end)
			+ "," + json_quote(std::string(1, spans[i].kind)) + "]";
	return out + "]";
}

static std::string sideJson(const std::string& name, const std::string& address, const std::string& proto,
	const std::string& source, const std::vector<std::string>& lines)
{
	return "{\"name\":" + json_quote(name) + ",\"address\":" + json_quote(address)
		+ ",\"prototype\":" + json_quote(proto) + ",\"source\":" + json_quote(source)
		+ ",\"lines\":" + strList(lines) + "}";
}

// {"a": {"ea"}, "b": {"file", "address", "image_base", "name", "prototype",
//  "functions": [{"address", "name", "prototype"}]}, "a_is_new": bool}
// "b": the binary of the other version and the functions of its database that
//  the decompiler may meet (names and prototypes); optional "canonical_names"
//  and "rename_locals" (default true)
// -> {"ok", "api", "ghidra", "seconds", "old": side, "new": side,
//     "rows": [{"l", "r", "c", "n", "ls", "rs"}], "changes": [...],
//     "calls_added", "calls_removed", "constants_added", "constants_removed",
//     "normalized_rows", "identical", "canonical_names", "rename_locals", "warnings"}
// side: {"name", "address", "prototype", "source", "lines"}
// rows: l/r 1-based lines (0: none), c changed, n equal only once
// normalized, ls/rs [[start, end, kind]] byte spans, kind '+', '-' or '^'
static std::string diffFunctions(const std::string& request)
{
	json_t req;
	std::string perr;
	if (!ghidradec_json::json_parse(request, &req, &perr) || !req.is_obj())
		return errorJson("invalid request: " + perr);
	const json_t* a = req.get("a");
	const json_t* b = req.get("b");
	if (a == nullptr || b == nullptr || !a->is_obj() || !b->is_obj())
		return errorJson("invalid request: 'a' and 'b' are required.");
	const json_t* an = req.get("a_is_new");
	bool aIsNew = an != nullptr && an->type == json_t::JBOOL && an->b;
	auto flag = [&req](const char* key) {
		const json_t* v = req.get(key);
		return v == nullptr || v->type != json_t::JBOOL || v->b;
	};
	bool canonical = flag("canonical_names"), rename = flag("rename_locals");
	std::string bFile = b->str("file");
	if (bFile.empty())
		return errorJson("invalid request: 'b' has no binary ('file').");

	std::string err;
	if (g_plugin == nullptr || g_plugin->decompInfo == nullptr)
		return errorJson("GhidraDec is not loaded for this database.");
	// before the wait box: it may ask for the Ghidra folder
	if (!ensureGhidraFolder(*g_plugin->decompInfo, true, &err))
		return errorJson(err);

	time_t t0 = time(nullptr);
	std::vector<std::string> warnings;
	std::string aCode, aProto, aName;
	std::string aSource = "open database, decompiled now";
	ea_t aStart = (ea_t)parseAddr(a->str("ea"));
	show_wait_box("HIDECANCEL\nGhidraDec: decompiling %s...", hexStr(aStart).c_str());
	// the function of the viewer, if one was decompiled there, would make init()
	// prepare that function alone: then the one of the diff has no name
	// (FUN_0x...) nor ranges, and the result depends on what the viewer showed
	struct ViewerFunction
	{
		RdGlobalInfo* di;
		func_t* saved;
		ViewerFunction(RdGlobalInfo* d) : di(d), saved(d->decompiledFunction) { di->decompiledFunction = nullptr; }
		~ViewerFunction() { di->decompiledFunction = saved; }
	};
	bool ok;
	{
		ViewerFunction keep(g_plugin->decompInfo);
		ok = prepare(&err) && decompile(aStart, canonical, &aCode, &aProto, &aName, &aStart, &err);
	}
	hide_wait_box();
	if (!ok)
		return errorJson(err);

	// the other version from its binary
	std::string bName = b->str("name"), bProto, bCode;
	FileDecompRequest fr;
	fr.path = bFile;
	fr.address = parseAddr(b->str("address"));
	fr.imageBase = parseAddr(b->str("image_base"));
	fr.canonicalNames = canonical;
	fr.functions[fr.address] = FileFunc{ bName, b->str("prototype") };
	const json_t* funcs = b->get("functions");
	if (funcs != nullptr && funcs->type == json_t::JARRAY)
		for (const json_t& f : funcs->arr)
			if (f.is_obj() && !f.str("address").empty())
				fr.functions[parseAddr(f.str("address"))] = FileFunc{ f.str("name"), f.str("prototype") };
	show_wait_box("HIDECANCEL\nGhidraDec: decompiling %s of the other version...", hexStr(fr.address).c_str());
	std::string name, ferr;
	ok = fileDecompile(g_plugin->decompInfo, fr, &bCode, &bProto, &name, &warnings, &ferr);
	hide_wait_box();
	if (!ok)
		return errorJson("the other version (" + bFile + ") could not be decompiled: " + ferr);
	if (bName.empty())
		bName = name;
	std::string bSource = "other binary, decompiled now (" + bFile + ")";

	uint64_t aBase = (uint64_t)get_imagebase();
	uint64_t bBase = parseAddr(b->str("image_base"));
	std::vector<std::string> aLines = ghidradec_diff::splitLines(aCode);
	std::vector<std::string> bLines = ghidradec_diff::splitLines(bCode);
	const std::vector<std::string>& oldLines = aIsNew ? bLines : aLines;
	const std::vector<std::string>& newLines = aIsNew ? aLines : bLines;
	ghidradec_diff::Result r = ghidradec_diff::diffCode(oldLines, newLines, aIsNew ? bBase : aBase, aIsNew ? aBase : bBase,
		rename);

	// the new version with its locals renamed after the old one (if rename): the rows refer to it
	std::string aSide = sideJson(aName, hexStr(aStart), aProto, aSource, aIsNew ? r.newLines : aLines);
	std::string bSide = sideJson(bName, b->str("address"), bProto, bSource, aIsNew ? bLines : r.newLines);

	std::string rows = "[";
	for (size_t i = 0; i < r.rows.size(); i++) {
		const ghidradec_diff::Row& row = r.rows[i];
		rows += std::string(i == 0 ? "" : ",") + "{\"l\":" + std::to_string(row.lno) + ",\"r\":" + std::to_string(row.rno)
			+ ",\"c\":" + (row.changed ? "true" : "false") + ",\"n\":" + (row.normalized ? "true" : "false");
		if (!row.lspans.empty()) rows += ",\"ls\":" + spansJson(row.lspans);
		if (!row.rspans.empty()) rows += ",\"rs\":" + spansJson(row.rspans);
		rows += "}";
	}
	rows += "]";

	std::string changes = "[";
	for (size_t i = 0; i < r.changes.size(); i++) {
		const ghidradec_diff::Change& c = r.changes[i];
		changes += std::string(i == 0 ? "" : ",") + "{\"kind\":" + json_quote(c.kind)
			+ ",\"old_lines\":[" + std::to_string(c.oldFirst) + "," + std::to_string(c.oldLast) + "]"
			+ ",\"new_lines\":[" + std::to_string(c.newFirst) + "," + std::to_string(c.newLast) + "]"
			+ ",\"calls_added\":" + strList(c.callsAdded) + ",\"calls_removed\":" + strList(c.callsRemoved)
			+ ",\"constants_added\":" + strList(c.constantsAdded) + ",\"constants_removed\":" + strList(c.constantsRemoved)
			+ ",\"description\":" + json_quote(c.description) + "}";
	}
	changes += "]";

	return "{\"ok\":true,\"api\":" + std::to_string(GHIDRADEC_API_VERSION)
		+ ",\"ghidra\":" + json_quote(g_plugin->decompInfo->ghidraPath)
		+ ",\"version\":" + json_quote(g_plugin->decompInfo->pluginVersion)
		+ ",\"seconds\":" + std::to_string((long long)(time(nullptr) - t0))
		+ ",\"old\":" + (aIsNew ? bSide : aSide)
		+ ",\"new\":" + (aIsNew ? aSide : bSide)
		+ ",\"rows\":" + rows
		+ ",\"changes\":" + changes
		+ ",\"calls_added\":" + strList(r.callsAdded)
		+ ",\"calls_removed\":" + strList(r.callsRemoved)
		+ ",\"constants_added\":" + strList(r.constantsAdded)
		+ ",\"constants_removed\":" + strList(r.constantsRemoved)
		+ ",\"normalized_rows\":" + std::to_string(r.normalizedRows)
		+ ",\"identical\":" + (r.identical ? "true" : "false")
		+ ",\"canonical_names\":" + (canonical ? "true" : "false")
		+ ",\"rename_locals\":" + (rename ? "true" : "false")
		+ ",\"warnings\":" + strList(warnings) + "}";
}

static char* toC(const std::string& s)
{
	char* p = (char*)malloc(s.size() + 1);
	if (p != nullptr)
		memcpy(p, s.c_str(), s.size() + 1);
	return p;
}

} // namespace idaplugin

using namespace idaplugin;

extern "C" __declspec(dllexport) int ghidradec_api_version(void)
{
	return GHIDRADEC_API_VERSION;
}

// The result is always a JSON object; release it with ghidradec_free().
extern "C" __declspec(dllexport) char* ghidradec_diff_functions(const char* request_json)
{
	try {
		return toC(diffFunctions(request_json != nullptr ? request_json : ""));
	} catch (const std::exception& e) {
		hide_wait_box();
		return toC(errorJson(std::string("internal error: ") + e.what()));
	}
}

// the decompiler processes of the API are no longer needed (end of a diff
// session): also forgets the binary of the other version
extern "C" __declspec(dllexport) void ghidradec_session_end(void)
{
	fileSessionEnd();
	if (g_plugin != nullptr)
		apiSessionEnd(g_plugin->decompInfo);
}

extern "C" __declspec(dllexport) void ghidradec_free(char* p)
{
	free(p);
}
