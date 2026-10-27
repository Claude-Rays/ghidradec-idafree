/**
 * @file api.h
 * @brief C API for other plugins (Diaphora-ng): decompile a function of the
 *        open database and of another binary and diff them, without the viewer.
 */

#ifndef IDAPLUGIN_API_H
#define IDAPLUGIN_API_H

namespace idaplugin {

	class GhidraDec;
	class RdGlobalInfo;

	// the instance of the open database (PLUGIN_MULTI: one per database)
	void apiAttach(GhidraDec* pm);
	void apiDetach(GhidraDec* pm);
	// stop the decompiler process of the API before the viewer uses its own
	void apiSessionEnd(RdGlobalInfo* di);

} // namespace idaplugin

#endif
