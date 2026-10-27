/**
 * @file localnames.cpp
 * @brief Canonical names of the local variables of a decompilation (v1, v2...).
 */

#include "localnames.h"

#include <cctype>

namespace ghidradec_names {

static bool allOf(const std::string& s, size_t from, size_t to, int (*pred)(int))
{
	if (from >= to) return false;
	for (size_t i = from; i < to; i++)
		if (!pred((unsigned char)s[i])) return false;
	return true;
}

static int isTypeChar(int c) { return std::isalpha(c) || c == '_'; }

// without the suffix of ScopeInternal::makeNameUnique: _00 or _x00000
static std::string withoutUniqueSuffix(const std::string& s)
{
	size_t n = s.size();
	if (n > 3 && s[n - 3] == '_' && allOf(s, n - 2, n, std::isdigit))
		return s.substr(0, n - 3);
	if (n > 7 && s[n - 7] == '_' && s[n - 6] == 'x' && allOf(s, n - 5, n, std::isdigit))
		return s.substr(0, n - 7);
	return s;
}

// the prefix of the type of ScopeInternal::buildVariableName: 'p' and 'a' for
// pointers and arrays, then the first letter of the type (uVar, pcVar, ppHVar)
static bool typePrefix(const std::string& s, size_t len)
{
	return len <= 12 && (len == 0 || allOf(s, 0, len, isTypeChar));
}

static bool isAutoBase(const std::string& s)
{
	// uVar3, pcVar12, Var1
	size_t v = s.rfind("Var");
	if (v != std::string::npos && typePrefix(s, v) && allOf(s, v + 3, s.size(), std::isdigit))
		return true;
	// auStack_48, uStackX_8, StackY_10 (ScopeLocal::buildVariableName)
	size_t st = s.rfind("Stack");
	if (st != std::string::npos && typePrefix(s, st)) {
		size_t i = st + 5;
		if (i < s.size() && (s[i] == 'X' || s[i] == 'Y')) i++;
		if (i < s.size() && s[i] == '_' && allOf(s, i + 1, s.size(), std::isxdigit))
			return true;
	}
	// local_28, local_res8
	if (s.compare(0, 6, "local_") == 0) {
		size_t i = s.compare(6, 3, "res") == 0 ? 9 : 6;
		if (allOf(s, i, s.size(), std::isxdigit))
			return true;
	}
	// in_stack_00000028
	if (s.compare(0, 9, "in_stack_") == 0 && allOf(s, 9, s.size(), std::isxdigit))
		return true;
	// IDA frame members without a name: var_28, arg_18
	if ((s.compare(0, 4, "var_") == 0 || s.compare(0, 4, "arg_") == 0) && allOf(s, 4, s.size(), std::isxdigit))
		return true;
	// extraout_var: a register without a name, numbered by the suffix
	if (s == "extraout_var")
		return true;
	return false;
}

bool isAutoLocalName(const std::string& name)
{
	// local_28 also ends like a suffix
	return isAutoBase(name) || isAutoBase(withoutUniqueSuffix(name));
}

std::map<std::string, std::string> canonicalNames(const std::vector<Occurrence>& occurrences,
	const std::set<std::string>& reserved)
{
	std::vector<std::string> order;
	std::set<std::string> seen;
	for (int pass = 0; pass < 2; pass++)
		for (const Occurrence& o : occurrences)
			if (o.inDecl == (pass == 1) && isAutoLocalName(o.name) && seen.insert(o.name).second)
				order.push_back(o.name);

	// the names that stay as they are can not be produced
	std::set<std::string> taken(reserved);
	for (const Occurrence& o : occurrences)
		if (seen.count(o.name) == 0) taken.insert(o.name);

	std::map<std::string, std::string> out;
	int next = 1;
	for (const std::string& name : order) {
		std::string nn;
		do nn = "v" + std::to_string(next++); while (taken.count(nn) != 0);
		out[name] = nn;
	}
	return out;
}

} // namespace ghidradec_names
