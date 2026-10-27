/**
 * @file ghidra_locate.h
 * @brief Finding the Ghidra installation (decompile.exe + processor files).
 *
 * No IDA headers: plain Win32, UTF-8 paths. A prebuilt ghidradec.dll knows
 * only the Ghidra folder of the machine it was built on, so the usual places
 * are searched too.
 */

#ifndef IDAPLUGIN_GHIDRA_LOCATE_H
#define IDAPLUGIN_GHIDRA_LOCATE_H

#include <string>
#include <vector>

namespace idaplugin {

/// 'dir' has Ghidra\Features\Decompiler\os\win_x86_64 (or win64)\decompile.exe
bool isGhidraFolder(const std::string& dir);

/// The Ghidra installation that 'dir' points to: 'dir' itself, its parent
/// (the user picked ...\Ghidra) or one of its ghidra* subfolders (the newest);
/// empty if there is none.
std::string normalizeGhidraFolder(const std::string& dir);

/// application.version of Ghidra\application.properties; empty if unknown.
std::string ghidraFolderVersion(const std::string& dir);

/// The Ghidra installations found, best first: GHIDRADEC_GHIDRA_DIR,
/// GHIDRA_INSTALL_DIR and 'builtIn' (in this order), then the ones in the
/// usual places, those of version 'preferVersion' first, then the newest.
std::vector<std::string> findGhidraFolders(const std::string& builtIn, const std::string& preferVersion);

} // namespace idaplugin

#endif
