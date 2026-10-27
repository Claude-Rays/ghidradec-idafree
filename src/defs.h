/**
 * @file defs.h
 * @brief Plugin-global definitions and includes (IDA SDK 9.4 only).
 * @copyright (c) 2017 Avast Software, (c) 2019-2026 Gregory Morse, MIT license.
 *            (c) 2026 ClaudeMonkey (Claude-Rays/ghidradec-idafree): IDA Free/Pro
 *            9.4+ port, retdec/jsoncpp removed, legacy SDK
 *            compatibility layers dropped.
 */

#ifndef IDAPLUGIN_DEFS_H
#define IDAPLUGIN_DEFS_H

#define _CRT_SECURE_NO_WARNINGS
#include <cstdint>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <vector>

// IDA SDK includes.
//
#define BYTES_SOURCE
#include <ida.hpp> // this must be included before other idasdk headers
#include <auto.hpp>
#include <bytes.hpp>
#include <demangle.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <fixup.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "sleighinterface.h"

//------------------------------------------------------------------------------
// Thin helpers kept from the original code base so that the (large)
// decompiler bridge can stay as close as possible to upstream GhidraDec.
//------------------------------------------------------------------------------
#define inf_is_32bit inf_is_32bit_or_higher
#define PLUGIN_SKIP 0
#define PLUGIN_KEEP 2
using udt_member_t = udm_t;
using enum_member_t = edm_t;

inline uint32 get_aflags0(ea_t ea) { return uint32(get_aflags(ea)); }
inline const char* get_reg_info(const char* regname, bitrange_t* bitrange)
{
	return get_ph()->get_reg_info(regname, bitrange);
}
inline bool is_funcarg_off(const func_t* pfn, uval_t frameoff)
{
	return get_ph()->is_funcarg_off(pfn, frameoff);
}
inline sval_t lvar_off(const func_t* pfn, uval_t frameoff)
{
	return get_ph()->lvar_off(pfn, frameoff);
}
inline std::string qstring_to_string(const qstring& qs) { return std::string(qs.c_str()); }
#define ph (*get_ph())
#define inf_filetype inf_get_filetype()
#define inf_start_ea inf_get_start_ea()
#define inf_min_ea inf_get_min_ea()
#define inf_max_ea inf_get_max_ea()
#define inf_procname qstring_to_string(inf_get_procname())
#define inf_cc_cm inf_get_cc_cm()

inline bool is_anonymous_udt(const tinfo_t& ti) { return ti.is_anonymous_udt(); }
inline sval_t get_stkarg_offset()
{
	stkarg_area_info_t sai = { sizeof(stkarg_area_info_t) };
	get_stkarg_area_info(&sai, inf_get_cc_cm());
	return sai.stkarg_offset;
}

#define GHIDRADEC_EXEC_RETURN ssize_t

#ifndef XREF_ALL
#define XREF_ALL XREF_FLOW
#endif
#ifndef XREF_FAR
#define XREF_FAR XREF_NOFLOW
#endif
#ifndef CM_CC_MANUAL
#define CM_CC_MANUAL CM_CC_SPECIAL
#endif
#define GHIDRADEC_FTD_CC(ftd) ((ftd).get_explicit_cc())
#define GHIDRADEC_SET_FTD_CC(ftd, cc) ((ftd).set_cc((callcnv_t)(cc)))

namespace idaplugin {

// General print msg macros.
//
#ifdef _DEBUG
#define PRINT_DEBUG   true
#else
#define PRINT_DEBUG   false
#endif
#define PRINT_ERROR   false
#define PRINT_WARNING true
#define PRINT_INFO    true

inline bool ghidradec_trace_enabled()
{
	qstring value;
	if (!qgetenv("GHIDRADEC_TRACE", &value))
		return PRINT_DEBUG;
	std::string flag = value.c_str();
	return !flag.empty() && flag != "0" && flag != "false" && flag != "FALSE";
}

#define DBG_MSG(body)     if (PRINT_DEBUG)   { std::stringstream ss; ss << std::showbase << body; msg("%s", ss.str().c_str()); }
/// Use this only for non-critical error messages.
#define ERROR_MSG(body)   if (PRINT_ERROR)   { std::stringstream ss; ss << std::showbase << "[GhidraDec error]  :\t" << body; msg("%s", ss.str().c_str()); }
/// Use this only for user info warnings.
#define WARNING_MSG(body) if (PRINT_WARNING) { std::stringstream ss; ss << std::showbase << "[GhidraDec warning]:\t" << body; msg("%s", ss.str().c_str()); }
/// Use this to inform user.
#define INFO_MSG(body)    if (PRINT_INFO)    { std::stringstream ss; ss << std::showbase << "[GhidraDec info]   :\t" << body; msg("%s", ss.str().c_str()); }
/// Use this for regression/debug diagnostics that should not appear in normal GUI use.
#define TRACE_MSG(body)   if (ghidradec_trace_enabled()) { std::stringstream ss; ss << std::showbase << "[GhidraDec trace]  :\t" << body; msg("%s", ss.str().c_str()); }

/// Use instead of IDA SDK's warning() function.
#define WARNING_GUI(body) { std::stringstream ss; ss << std::showbase << body; warning("%s", ss.str().c_str()); }

#ifndef RELEASE_VERSION
#define RELEASE_VERSION "1.0"
#endif

class FunctionInfo
{
	public:
		std::string code;
		strvec_t idaCode;
};

/**
 * Function / global names of the database. Replaces the retdec config database
 * the original plugin generated only to answer "is this word a function or a
 * global?" from the decompiled-code viewer.
 */
struct NameItem
{
	std::string name;
	ea_t ea = BADADDR;
	bool isFunction = false;
};

// IDA's demangled short name without its argument list ("CZoneIdentifier::GetNamedValue"),
// "" when the name is not mangled.
std::string demangledShortName(const std::string& name);
// Name of a function in the decompiler output: demangled short name or the plain name,
// with '.' and '@' replaced ("" when it has no name).
std::string functionDisplayName(ea_t ea);

class NameIndex
{
	public:
		void rebuild();
		const NameItem* function(const std::string& name) const;
		const NameItem* global(const std::string& name) const;

	private:
		std::map<std::string, NameItem> functions;
		std::map<std::string, NameItem> globals;
};

// Helper functions.
//
int runCommand(
		const std::string& cmd,
		const std::string& args,
		intptr_t* pid = nullptr,
		void** hdl = nullptr,
		int* readpipe = nullptr,
		int* writepipe = nullptr,
		bool showWarnings = false);

class RdGlobalInfo;
void stopDecompilation(RdGlobalInfo*, bool, bool, bool);

#define PLUGIN_NAME "GhidraDec"
#define PLUGIN_PRODUCER "Gregory Morse"
#define PLUGIN_COPYRIGHT "Copyright 2019-2026 " PLUGIN_PRODUCER ", 2026 ClaudeMonkey (IDA Free/Pro port)"
#define PLUGIN_URL "https://github.com/GregoryMorse/GhidraDec"
#define PLUGIN_HOTKEY "Ctrl-G"

class GhidraDec;
class IdaCallback;

enum ViewFeatureFlags : ushort
{
	// bit 0 was the control-flow graph view (removed); the saved settings
	// keep the other bits where they were
	VIEW_FEATURE_APPLY_PARAM_ID = 2,
	VIEW_FEATURE_BACKUP_IDB = 4,
	VIEW_FEATURES_MASK = VIEW_FEATURE_APPLY_PARAM_ID | VIEW_FEATURE_BACKUP_IDB,
};

// The original backs up the IDB before every decompilation. That is slow and
// IDA Free users usually work on a single .i64, so it is opt-in here.
inline ushort ghidradec_default_view_features()
{
	return VIEW_FEATURE_APPLY_PARAM_ID;
}

enum GhidraDecAnalysisOptionBits : ushort
{
	GHIDRADEC_ANALYSIS_UNREACHABLE = 1 << 0,
	GHIDRADEC_ANALYSIS_IGNORE_UNIMPLEMENTED = 1 << 1,
	GHIDRADEC_ANALYSIS_INFER_CONST_PTR = 1 << 2,
	GHIDRADEC_ANALYSIS_READONLY = 1 << 3,
	GHIDRADEC_ANALYSIS_DOUBLE_PRECISION = 1 << 4,
	GHIDRADEC_ANALYSIS_CONDITIONAL_EXECUTION = 1 << 5,
	GHIDRADEC_ANALYSIS_INPLACE_OPS = 1 << 6,
};

enum GhidraDecDisplayOptionBits : ushort
{
	GHIDRADEC_DISPLAY_NO_CASTS = 1 << 0,
	GHIDRADEC_DISPLAY_EOL_COMMENTS = 1 << 1,
	GHIDRADEC_DISPLAY_HEADER_COMMENTS = 1 << 2,
	GHIDRADEC_DISPLAY_LINE_NUMBERS = 1 << 3,
	GHIDRADEC_DISPLAY_NAMESPACES = 1 << 4,
	GHIDRADEC_DISPLAY_PLATE_COMMENTS = 1 << 5,
	GHIDRADEC_DISPLAY_POST_COMMENTS = 1 << 6,
	GHIDRADEC_DISPLAY_PRE_COMMENTS = 1 << 7,
	GHIDRADEC_DISPLAY_WARNING_COMMENTS = 1 << 8,
	GHIDRADEC_DISPLAY_NULL_PRINTING = 1 << 9,
	GHIDRADEC_DISPLAY_CONVENTION_PRINTING = 1 << 10,
	GHIDRADEC_DISPLAY_HIDE_EXTENSIONS = 1 << 11,
	// locals v1, v2... instead of uVar3, local_28 (localnames.h)
	GHIDRADEC_DISPLAY_CANONICAL_NAMES = 1 << 12,
};

enum GhidraDecBehaviorOptionBits : ushort
{
	GHIDRADEC_BEHAVIOR_ANALYZE_FOR_LOOPS = 1 << 0,
	GHIDRADEC_BEHAVIOR_ALLOW_CONTEXT_SET = 1 << 1,
	GHIDRADEC_BEHAVIOR_ERROR_UNIMPLEMENTED = 1 << 2,
	GHIDRADEC_BEHAVIOR_ERROR_REINTERPRETED = 1 << 3,
	GHIDRADEC_BEHAVIOR_ERROR_TOO_MANY_INSTRUCTIONS = 1 << 4,
	GHIDRADEC_BEHAVIOR_JUMP_LOAD = 1 << 5,
};

enum GhidraDecSplitDatatypeOptionBits : ushort
{
	GHIDRADEC_SPLIT_DATATYPE_STRUCT = 1 << 0,
	GHIDRADEC_SPLIT_DATATYPE_ARRAY = 1 << 1,
	GHIDRADEC_SPLIT_DATATYPE_POINTER = 1 << 2,
};

constexpr ushort GHIDRADEC_DEFAULT_ANALYSIS_CHECKS =
	GHIDRADEC_ANALYSIS_UNREACHABLE |
	GHIDRADEC_ANALYSIS_INFER_CONST_PTR |
	GHIDRADEC_ANALYSIS_READONLY |
	GHIDRADEC_ANALYSIS_DOUBLE_PRECISION |
	GHIDRADEC_ANALYSIS_CONDITIONAL_EXECUTION;

constexpr ushort GHIDRADEC_DEFAULT_DISPLAY_CHECKS =
	GHIDRADEC_DISPLAY_HEADER_COMMENTS |
	GHIDRADEC_DISPLAY_LINE_NUMBERS |
	GHIDRADEC_DISPLAY_PRE_COMMENTS |
	GHIDRADEC_DISPLAY_WARNING_COMMENTS |
	GHIDRADEC_DISPLAY_CONVENTION_PRINTING |
	GHIDRADEC_DISPLAY_HIDE_EXTENSIONS;

constexpr ushort GHIDRADEC_DEFAULT_BEHAVIOR_CHECKS =
	GHIDRADEC_BEHAVIOR_ANALYZE_FOR_LOOPS |
	GHIDRADEC_BEHAVIOR_ALLOW_CONTEXT_SET |
	GHIDRADEC_BEHAVIOR_ERROR_TOO_MANY_INSTRUCTIONS;

constexpr ushort GHIDRADEC_DEFAULT_SPLIT_DATATYPE_CHECKS =
	GHIDRADEC_SPLIT_DATATYPE_STRUCT |
	GHIDRADEC_SPLIT_DATATYPE_ARRAY |
	GHIDRADEC_SPLIT_DATATYPE_POINTER;

/**
 * General information used by this plugin.
 */
class RdGlobalInfo
{
	public:
		RdGlobalInfo(GhidraDec* pm);

	// General plugin information.
	//
	public:
		GhidraDec* pm;
		std::string pluginName             = PLUGIN_NAME;
		std::string pluginVersion          = RELEASE_VERSION;
		std::string pluginURL              = PLUGIN_URL;
		int pluginIconId            = -1;

	// General information common for all decompilations or viewers.
	//
	public:
		std::string workDir;
		std::string workIdb;
		std::string inputPath;
		std::string inputName;
		NameIndex names;

		std::map<func_t*, FunctionInfo> fnc2code;
		std::list<func_t*> navigationList;
		std::list<func_t*>::iterator navigationActual = navigationList.end();

	// One viewer information.
	//
	public:
		const std::string viewerName = "GhidraDec";
		// title of the open viewer ("GhidraDec: <function>"), and the timer
		// that replaces it when another function is shown
		std::string viewerTitle;
		qtimer_t retitleTimer = nullptr;
		TWidget* custViewer = nullptr;
		TWidget* codeViewer = nullptr;
		strvec_t viewerLines;

	// One decompilation information.
	//
	public:
		bool isAllDecompilation();
		bool isSelectiveDecompilation();

	public:
		std::string decCmd;
		std::string ranges;
		std::string outputFile;
		bool exiting = false;
		bool decompRunning          = false;
		bool decompSuccess          = false;
		bool decompiledAll          = false;
		bool skipParamIdentification = false;
		bool suppressViewer = false;
		// C API (api.cpp): no parameter identification (it changes the database),
		// and a decompiler process kept running between the calls
		bool apiNoParamId = false;
		// the diff always compares canonical names, whatever the viewer shows
		bool apiCanonicalNames = false;
		bool apiReady = false;
		IdaCallback* idacb = nullptr;
		int uiExecutingTask = -1;
		qsemaphore_t termSem = nullptr;
		qmutex_t qm = nullptr;
		qthread_t decompThread      = nullptr;
		func_t *decompiledFunction  = nullptr;
		// PID/Handle of launched decompilation process.
		intptr_t decompPid = 0;
		int rdHandle = -1;
		int wrHandle = -1;
		void* hDecomp = nullptr;

	// Plugin configuration information.
	//
	public:
		bool isDecompilerInSpecifiedPath() const;
		bool isDecompilerInSystemPath();

		bool configureDecompilation();

		bool isUseThreads() const;
		void setIsUseThreads(bool f);

	public:
		const std::string decompilerExeName = "decompile.exe";
		std::string decompilerExePath = "";
		/// Path to the Ghidra base folder set by user in configuration menu.
		std::string ghidraPath = "";
		sval_t cacheSize = 10, maxPayload = 50, timeout = 30, cmtLevel = 20, maxChars = 100, numChars = 2;
		sval_t maxJumpTableSize = 4096, maxInstructions = 100000;
		int comStyle = 0, intFormat = 2;
		int aliasBlock = 2, namespaceStrategy = 0, nanIgnore = 1;
		int braceFormatFunction = 2, braceFormatIfElse = 0, braceFormatLoop = 0, braceFormatSwitch = 0;
		ushort viewFeatures = ghidradec_default_view_features();
		ushort alysChecks = GHIDRADEC_DEFAULT_ANALYSIS_CHECKS, dispChecks = GHIDRADEC_DEFAULT_DISPLAY_CHECKS;
		ushort behaviorChecks = GHIDRADEC_DEFAULT_BEHAVIOR_CHECKS;
		ushort splitDatatypeChecks = GHIDRADEC_DEFAULT_SPLIT_DATATYPE_CHECKS;

		std::vector<LangInfo> li;
		std::map<std::string, std::vector<int>> toolMap;

		std::string customCallStyle;
		std::string customCspec;
		std::string customPspec;
		std::string customSlafile;

	private:
		bool useThreads = true;
};

} // namespace idaplugin

#endif
