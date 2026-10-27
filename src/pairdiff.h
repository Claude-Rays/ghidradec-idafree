/**
 * @file pairdiff.h
 * @brief Aligned diff of two decompilations of the same function (for Diaphora-ng).
 *
 * No IDA headers: the module only works on text, so it can be tested alone.
 *
 * The locals of NEW are first renamed after those of OLD: the locals (the
 * declarations at the top of the body) are matched by where they are used in
 * the lines that line up when the locals are masked, and NEW takes the name of
 * its match (v4 -> v3, pv -> pv_00). A real change of variable is then a change
 * of the line. The locals of NEW without a match keep their name, or get a new
 * one if OLD uses it.
 *
 * The lines are compared through a normalized key, so what moves between two
 * builds without changing the code never counts as a change:
 * - addresses: sub_180012340, DAT_180034000, LAB_..., 0x180012345 inside the
 *   image, and the hex numbers of the warning comments;
 * - the source line number of the WIL diagnostics (Return_Hr(..., 0x339,
 *   "file.cxx", hr)), which moves whenever the source file changes;
 * - indentation and spacing (new code around old code re-indents it).
 * OLD is shown as it is, NEW with its locals renamed (Result::newLines).
 */

#ifndef IDAPLUGIN_PAIRDIFF_H
#define IDAPLUGIN_PAIRDIFF_H

#include <cstdint>
#include <string>
#include <vector>

namespace ghidradec_diff {

	struct Span
	{
		int start;      // byte offsets in the line
		int end;
		char kind;      // '+' added, '-' deleted, '^' changed
	};

	struct Row
	{
		int lno = 0;                // 1-based line of OLD, 0: none
		int rno = 0;                // 1-based line of NEW, 0: none
		bool changed = false;
		bool normalized = false;    // equal only after the normalization
		std::vector<Span> lspans;
		std::vector<Span> rspans;
	};

	struct Change
	{
		std::string kind;           // added, removed, modified
		int oldFirst = 0, oldLast = 0;   // 1-based lines, 0 if none
		int newFirst = 0, newLast = 0;
		std::vector<std::string> callsAdded, callsRemoved;
		std::vector<std::string> constantsAdded, constantsRemoved;
		std::string description;
	};

	struct Result
	{
		std::vector<Row> rows;
		std::vector<Change> changes;
		// the whole function: calls with their count ("Foo", "Foo (1 -> 2)")
		std::vector<std::string> callsAdded, callsRemoved;
		std::vector<std::string> constantsAdded, constantsRemoved;
		int normalizedRows = 0;
		bool identical = false;
		// NEW with its locals renamed after OLD: the text of the rows and spans
		std::vector<std::string> newLines;
		std::vector<std::pair<std::string, std::string>> renamedLocals;	// NEW name -> OLD name
	};

	// the text in lines, without '\r' and without the trailing empty lines
	std::vector<std::string> splitLines(const std::string& text);

	// the comparison key of a line; imageBase masks the addresses of its image
	std::string normalizeLine(const std::string& line, uint64_t imageBase);

	// rename false: NEW keeps its names (no "level 2" renaming)
	Result diffCode(const std::vector<std::string>& oldLines, const std::vector<std::string>& newLines,
		uint64_t oldBase, uint64_t newBase, bool rename = true);

} // namespace ghidradec_diff

#endif
