/**
 * @file localnames.h
 * @brief Canonical names of the local variables of a decompilation (v1, v2...).
 *
 * Ghidra names a local by its position in its own lists (uVar3) or by its
 * stack offset (auStack_48, local_28), so two builds of the same function get
 * different names and their code does not line up in a diff. These names are
 * replaced, as IDA does, by v1, v2... in the order of their first use in the
 * body of the function: the same code gives the same names.
 *
 * No IDA or Ghidra headers: the module only works on names, so it can be
 * tested alone. sleighinterface.cpp walks the XML of the C code.
 */

#ifndef IDAPLUGIN_LOCALNAMES_H
#define IDAPLUGIN_LOCALNAMES_H

#include <map>
#include <set>
#include <string>
#include <vector>

namespace ghidradec_names {

	// a name chosen by Ghidra (uVar3, pcVar12, auStack_48, local_28,
	// in_stack_00000028, extraout_var_00) or by IDA for a frame member (var_28,
	// arg_18);
	// unaff_RBX, in_FS_OFFSET... keep their register and are not
	bool isAutoLocalName(const std::string& name);

	struct Occurrence
	{
		std::string name;
		bool inDecl;        // in the declaration of the local, not in the body
	};

	// old name -> new name of the automatic names among the occurrences (in the
	// order of the document), numbered by their first use in the body and then
	// by their declaration; 'reserved' are the other names of the function,
	// never produced
	std::map<std::string, std::string> canonicalNames(const std::vector<Occurrence>& occurrences,
		const std::set<std::string>& reserved);

} // namespace ghidradec_names

#endif
