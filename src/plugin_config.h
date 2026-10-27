/**
 * @file plugin_config.h
 * @brief GhidraDec plugin configuration (IDA registry + per-database netnode).
 * @copyright (c) 2017 Avast Software, (c) 2019-2026 Gregory Morse, MIT license.
 */

#ifndef IDAPLUGIN_PLUGIN_CONFIG_H
#define IDAPLUGIN_PLUGIN_CONFIG_H

#include "defs.h"

namespace idaplugin {

/// Show the settings dialog. @return @c True if cancelled.
bool pluginConfigurationMenu(RdGlobalInfo& rdgi);

void readConfig(RdGlobalInfo& rdgi);

/// The Ghidra folder, checked (and found or asked for) before Ghidra is used.
/// @return @c false, with *err, if there is no Ghidra.
bool ensureGhidraFolder(RdGlobalInfo& rdgi, bool interactive, std::string* err = nullptr);

/// The Ghidra version the plugin was built with ("" if unknown).
const char* ghidraBuildVersion();
void readDatabaseConfig(RdGlobalInfo& rdgi);
void saveConfig(RdGlobalInfo& rdgi);

} // namespace idaplugin

#endif
