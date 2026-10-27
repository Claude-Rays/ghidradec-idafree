/**
 * @file filedec.h
 * @brief Decompile a function of a binary on disk (PE or ELF), not of the
 *        open database: the other version of a Diaphora-ng diff.
 */

#ifndef IDAPLUGIN_FILEDEC_H
#define IDAPLUGIN_FILEDEC_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace idaplugin {

	class RdGlobalInfo;

	// a function of the other version known by the caller (Diaphora's export)
	struct FileFunc
	{
		std::string name;
		std::string prototype;	// IDA's C declaration, possibly without a name
	};

	struct FileDecompRequest
	{
		std::string path;
		uint64_t address = 0;		// in the other database
		uint64_t imageBase = 0;		// of the other database (0: unknown)
		std::map<uint64_t, FileFunc> functions;	// addresses of the other database
		bool canonicalNames = true;	// locals named v1, v2... ("level 1")
	};

	// Decompiles req.address of the binary req.path with the processor, the
	// compiler and the options of the open database (both versions are the
	// same program). The loaded binary and its decompiler process are kept
	// for the next calls until fileSessionEnd(). Main thread only. Needs the
	// decompiler of the open database set up (it gives the specs).
	bool fileDecompile(RdGlobalInfo* di, const FileDecompRequest& req, std::string* code, std::string* proto,
		std::string* name, std::vector<std::string>* warnings, std::string* err);

	// forget the loaded binary and stop its decompiler process
	void fileSessionEnd();

} // namespace idaplugin

#endif
