/**
 * @file pairdiff.cpp
 * @brief Aligned diff of two decompilations of the same function (for Diaphora-ng).
 */

#include "pairdiff.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>

namespace ghidradec_diff {

//------------------------------------------------------------------------------
// tokens
//------------------------------------------------------------------------------
enum TokKind { T_SPACE, T_IDENT, T_NUMBER, T_STRING, T_COMMENT, T_PUNCT };

struct Token
{
	TokKind kind;
	int start;
	int end;
	std::string key;    // normalized text
};

// addresses inside the image: 'base' up to 256 MB above it
static const uint64_t IMAGE_SPAN = 0x10000000;

static bool isIdentStart(unsigned char c) { return std::isalpha(c) || c == '_' || c == '$' || c == '?' || c == '@'; }
static bool isIdentChar(unsigned char c) { return std::isalnum(c) || c == '_' || c == '$' || c == '?' || c == '@'; }

static bool allHex(const std::string& s, size_t from, size_t to)
{
	if (from >= to) return false;
	for (size_t i = from; i < to; i++)
		if (!std::isxdigit((unsigned char)s[i])) return false;
	return true;
}

static bool allDigits(const std::string& s, size_t from, size_t to)
{
	if (from >= to) return false;
	for (size_t i = from; i < to; i++)
		if (!std::isdigit((unsigned char)s[i])) return false;
	return true;
}

static bool hasDigit(const std::string& s, size_t from, size_t to)
{
	for (size_t i = from; i < to; i++)
		if (std::isdigit((unsigned char)s[i])) return true;
	return false;
}

// names that hold an address chosen by Ghidra; the locals it numbers by
// position (uVar3, local_28) are renamed after OLD instead (matchLocals)
static std::string identKey(const std::string& s)
{
	// code_r0x180012345 -> code_r0x#
	size_t r = s.find("_r0x");
	if (r != std::string::npos && allHex(s, r + 4, s.size()))
		return s.substr(0, r) + "_r0x#";
	// sub_180012340, DAT_180034000, LAB_..., PTR_FUN_..., switchD_... -> sub_#
	size_t u = s.rfind('_');
	if (u != std::string::npos && u > 0 && s.size() - u - 1 >= 6 && allHex(s, u + 1, s.size()) && hasDigit(s, u + 1, s.size()))
		return s.substr(0, u) + "_#";
	// FUN_0x180012340, name_0x180012340: the names GhidraDec gives (getFunctionSymbolName)
	if (u != std::string::npos && u > 0 && s.compare(u + 1, 2, "0x") == 0 && s.size() - u - 3 >= 6 && allHex(s, u + 3, s.size()))
		return s.substr(0, u) + "_#";
	return s;
}

static bool numberValue(const std::string& s, uint64_t* value)
{
	if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		size_t e = 2;
		while (e < s.size() && std::isxdigit((unsigned char)s[e])) e++;
		if (e == 2) return false;
		*value = strtoull(s.substr(2, e - 2).c_str(), nullptr, 16);
		return true;
	}
	size_t e = 0;
	while (e < s.size() && std::isdigit((unsigned char)s[e])) e++;
	if (e == 0) return false;
	*value = strtoull(s.substr(0, e).c_str(), nullptr, 10);
	return true;
}

static std::string numberKey(const std::string& s, uint64_t base)
{
	uint64_t v;
	if (base != 0 && numberValue(s, &v) && v >= base && v - base < IMAGE_SPAN)
		return "ADDR#";
	return s;
}

static std::vector<Token> tokenize(const std::string& line, uint64_t base, bool plainText = false);

// a comment with its addresses masked
static std::string commentKey(const std::string& text, uint64_t base)
{
	std::string key;
	for (const Token& t : tokenize(text, base, true))
		key += t.kind == T_SPACE ? std::string(" ") : t.key;
	return key;
}

// plainText: inside a comment (no strings, no nested comments)
static std::vector<Token> tokenize(const std::string& line, uint64_t base, bool plainText)
{
	std::vector<Token> out;
	size_t i = 0, n = line.size();
	while (i < n) {
		unsigned char c = (unsigned char)line[i];
		size_t s = i;
		Token t;
		if (c == ' ' || c == '\t') {
			while (i < n && (line[i] == ' ' || line[i] == '\t')) i++;
			t.kind = T_SPACE;
			t.key = " ";
		} else if (!plainText && c == '/' && i + 1 < n && (line[i + 1] == '/' || line[i + 1] == '*')) {
			if (line[i + 1] == '/') i = n;
			else {
				size_t e = line.find("*/", i + 2);
				i = e == std::string::npos ? n : e + 2;
			}
			t.kind = T_COMMENT;
			t.key = commentKey(line.substr(s, i - s), base);
		} else if (!plainText && (c == '"' || c == '\'')) {
			i++;
			while (i < n && line[i] != (char)c) {
				if (line[i] == '\\' && i + 1 < n) i++;
				i++;
			}
			if (i < n) i++;
			t.kind = T_STRING;
			t.key = line.substr(s, i - s);
		} else if (std::isdigit(c)) {
			while (i < n && (std::isalnum((unsigned char)line[i]) || line[i] == '.' || line[i] == '_')) i++;
			t.kind = T_NUMBER;
			t.key = numberKey(line.substr(s, i - s), base);
		} else if (isIdentStart(c)) {
			// a string prefix: L"...", u"..."
			while (i < n && isIdentChar((unsigned char)line[i])) i++;
			if (!plainText && i < n && (line[i] == '"' || line[i] == '\'') && i - s <= 2) {
				char q = line[i++];
				while (i < n && line[i] != q) {
					if (line[i] == '\\' && i + 1 < n) i++;
					i++;
				}
				if (i < n) i++;
				t.kind = T_STRING;
				t.key = line.substr(s, i - s);
			} else {
				t.kind = T_IDENT;
				t.key = identKey(line.substr(s, i - s));
			}
		} else {
			i++;
			t.kind = T_PUNCT;
			t.key = line.substr(s, 1);
		}
		t.start = (int)s;
		t.end = (int)i;
		out.push_back(std::move(t));
	}
	if (plainText) return out;

	// WIL diagnostics: the number right before the source file name,
	// Return_Hr(retaddr, 0x339, "...\\file.cxx", hr)
	for (size_t k = 0; k < out.size(); k++) {
		if (out[k].kind != T_NUMBER) continue;
		size_t j = k + 1;
		while (j < out.size() && out[j].kind == T_SPACE) j++;
		if (j >= out.size() || out[j].key != ",") continue;
		j++;
		while (j < out.size() && out[j].kind == T_SPACE) j++;
		if (j >= out.size() || out[j].kind != T_STRING) continue;
		std::string f = out[j].key;
		std::transform(f.begin(), f.end(), f.begin(), [](unsigned char ch) { return (char)std::tolower(ch); });
		static const char* exts[] = { ".c\"", ".cc\"", ".cpp\"", ".cxx\"", ".h\"", ".hpp\"", ".hxx\"", ".inl\"" };
		for (const char* e : exts) {
			size_t el = strlen(e);
			if (f.size() >= el && f.compare(f.size() - el, el, e) == 0) {
				out[k].key = "#";
				break;
			}
		}
	}
	return out;
}

static std::string keyOf(const std::vector<Token>& toks)
{
	std::string key;
	for (const Token& t : toks) {
		if (t.kind == T_SPACE) continue;
		if (!key.empty()) key += ' ';
		key += t.key;
	}
	return key;
}

std::string normalizeLine(const std::string& line, uint64_t imageBase)
{
	return keyOf(tokenize(line, imageBase));
}

std::vector<std::string> splitLines(const std::string& text)
{
	std::vector<std::string> out;
	std::string cur;
	for (char c : text) {
		if (c == '\r') continue;
		if (c == '\n') { out.push_back(cur); cur.clear(); }
		else cur += c;
	}
	out.push_back(cur);
	while (!out.empty() && out.back().find_first_not_of(" \t") == std::string::npos)
		out.pop_back();
	return out;
}

//------------------------------------------------------------------------------
// calls and constants of a line
//------------------------------------------------------------------------------
static bool isKeyword(const std::string& s)
{
	// void: the type of a function pointer, void (*)(int)
	static const std::set<std::string> kw = { "if", "while", "for", "switch", "return", "sizeof", "do", "else", "case",
		"goto", "void", "CONCAT11", "CONCAT12", "CONCAT14", "CONCAT22", "CONCAT24", "CONCAT31", "CONCAT44", "CONCAT88",
		"SUB41", "SUB42", "SUB81", "SUB82", "SUB84", "ZEXT", "SEXT" };
	return kw.count(s) != 0 || s.compare(0, 6, "CONCAT") == 0 || s.compare(0, 4, "ZEXT") == 0
		|| s.compare(0, 4, "SEXT") == 0 || (s.compare(0, 3, "SUB") == 0 && s.size() <= 6 && allDigits(s, 3, s.size()));
}

// key -> shown text
typedef std::map<std::string, std::string> Named;

static void lineFacts(const std::string& line, const std::vector<Token>& toks, Named* calls,
	std::map<std::string, int>* callCount, Named* consts)
{
	for (size_t k = 0; k < toks.size(); k++) {
		const Token& t = toks[k];
		std::string raw = line.substr(t.start, t.end - t.start);
		if (t.kind == T_IDENT) {
			size_t j = k + 1;
			while (j < toks.size() && toks[j].kind == T_SPACE) j++;
			if (j < toks.size() && toks[j].key == "(" && !isKeyword(raw)) {
				if (calls != nullptr) calls->emplace(t.key, raw);
				if (callCount != nullptr) (*callCount)[t.key]++;
			}
		} else if (t.kind == T_NUMBER && consts != nullptr) {
			uint64_t v = 0;
			if (t.key == "ADDR#" || t.key == "#" || (numberValue(raw, &v) && v < 10)) continue;
			consts->emplace(t.key, raw);
		} else if (t.kind == T_STRING && consts != nullptr) {
			consts->emplace(t.key, raw);
		}
	}
}

static void setDiff(const Named& a, const Named& b, std::vector<std::string>* onlyA)
{
	for (const auto& kv : a)
		if (b.find(kv.first) == b.end()) onlyA->push_back(kv.second);
}

//------------------------------------------------------------------------------
// line alignment: patience diff, LCS inside the gaps without anchors
//------------------------------------------------------------------------------
typedef std::vector<std::pair<int, int>> Matches;

static const size_t MAX_DP_CELLS = 4000000;

static void lcsDp(const std::vector<int>& A, const std::vector<int>& B, int a0, int a1, int b0, int b1, Matches& out)
{
	int n = a1 - a0, m = b1 - b0;
	if (n <= 0 || m <= 0 || (size_t)n * (size_t)m > MAX_DP_CELLS) return;
	// L[i][j]: LCS of A[a0+i..a1) and B[b0+j..b1); min(n, m) <= 2000 fits uint16
	std::vector<uint16_t> L((size_t)(n + 1) * (m + 1), 0);
	auto at = [&](int i, int j) -> uint16_t& { return L[(size_t)i * (m + 1) + j]; };
	for (int i = n - 1; i >= 0; i--)
		for (int j = m - 1; j >= 0; j--)
			at(i, j) = A[a0 + i] == B[b0 + j] ? (uint16_t)(at(i + 1, j + 1) + 1) : std::max(at(i + 1, j), at(i, j + 1));
	int i = 0, j = 0;
	while (i < n && j < m) {
		if (A[a0 + i] == B[b0 + j]) { out.push_back({ a0 + i, b0 + j }); i++; j++; }
		else if (at(i + 1, j) >= at(i, j + 1)) i++;
		else j++;
	}
}

static void patience(const std::vector<int>& A, const std::vector<int>& B, int a0, int a1, int b0, int b1, Matches& out)
{
	while (a0 < a1 && b0 < b1 && A[a0] == B[b0]) out.push_back({ a0++, b0++ });
	Matches tail;
	while (a0 < a1 && b0 < b1 && A[a1 - 1] == B[b1 - 1]) tail.push_back({ --a1, --b1 });
	if (a0 < a1 && b0 < b1) {
		struct Occ { int ca = 0, pa = 0, cb = 0, pb = 0; };
		std::unordered_map<int, Occ> occ;
		for (int i = a0; i < a1; i++) { Occ& o = occ[A[i]]; o.ca++; o.pa = i; }
		for (int j = b0; j < b1; j++) {
			auto p = occ.find(B[j]);
			if (p != occ.end()) { p->second.cb++; p->second.pb = j; }
		}
		std::vector<std::pair<int, int>> uniq;     // (pos in A, pos in B), sorted by A
		for (int i = a0; i < a1; i++) {
			const Occ& o = occ[A[i]];
			if (o.ca == 1 && o.cb == 1) uniq.push_back({ i, o.pb });
		}
		// longest increasing subsequence of the positions in B
		std::vector<int> tailIdx, prev(uniq.size(), -1);
		for (int k = 0; k < (int)uniq.size(); k++) {
			int lo = 0, hi = (int)tailIdx.size();
			while (lo < hi) {
				int mid = (lo + hi) / 2;
				if (uniq[tailIdx[mid]].second < uniq[k].second) lo = mid + 1; else hi = mid;
			}
			if (lo > 0) prev[k] = tailIdx[lo - 1];
			if (lo == (int)tailIdx.size()) tailIdx.push_back(k); else tailIdx[lo] = k;
		}
		Matches anchors;
		for (int k = tailIdx.empty() ? -1 : tailIdx.back(); k >= 0; k = prev[k]) anchors.push_back(uniq[k]);
		std::reverse(anchors.begin(), anchors.end());
		if (anchors.empty()) {
			lcsDp(A, B, a0, a1, b0, b1, out);
		} else {
			int pa = a0, pb = b0;
			for (const auto& an : anchors) {
				patience(A, B, pa, an.first, pb, an.second, out);
				out.push_back(an);
				pa = an.first + 1;
				pb = an.second + 1;
			}
			patience(A, B, pa, a1, pb, b1, out);
		}
	}
	out.insert(out.end(), tail.rbegin(), tail.rend());
}

//------------------------------------------------------------------------------
// the lines of a replaced block: pairs of similar lines, changed spans
//------------------------------------------------------------------------------
struct LineInfo
{
	std::vector<Token> toks;
	std::vector<int> words;     // ids of the keys of the non-space tokens
	std::vector<int> wordTok;   // their index in toks
	std::string key;
};

static double similarity(const LineInfo& a, const LineInfo& b)
{
	size_t n = a.words.size(), m = b.words.size();
	if (n == 0 && m == 0) return 1.0;
	if (n == 0 || m == 0) return 0.0;
	if (n * m > 90000) return a.key == b.key ? 1.0 : 0.0;
	std::vector<int> row(m + 1, 0), next(m + 1, 0);
	for (size_t i = n; i-- > 0; ) {
		for (size_t j = m; j-- > 0; )
			row[j] = a.words[i] == b.words[j] ? next[j + 1] + 1 : std::max(next[j], row[j + 1]);
		std::swap(row, next);
	}
	return 2.0 * next[0] / double(n + m);
}

static const double PAIR_MIN = 0.5;
static const size_t MAX_PAIR_CELLS = 40000;

// monotonic pairing of the old and new lines of a block, maximizing the
// similarity of the pairs
static Matches pairLines(const std::vector<LineInfo>& L, const std::vector<LineInfo>& R,
	int a0, int a1, int b0, int b1)
{
	Matches out;
	int n = a1 - a0, m = b1 - b0;
	if (n <= 0 || m <= 0 || (size_t)n * (size_t)m > MAX_PAIR_CELLS) return out;
	std::vector<double> sim((size_t)n * m), S((size_t)(n + 1) * (m + 1), 0.0);
	auto s = [&](int i, int j) -> double& { return S[(size_t)i * (m + 1) + j]; };
	for (int i = 0; i < n; i++)
		for (int j = 0; j < m; j++)
			sim[(size_t)i * m + j] = similarity(L[a0 + i], R[b0 + j]);
	for (int i = n - 1; i >= 0; i--)
		for (int j = m - 1; j >= 0; j--) {
			double best = std::max(s(i + 1, j), s(i, j + 1));
			double v = sim[(size_t)i * m + j];
			if (v >= PAIR_MIN) best = std::max(best, v + s(i + 1, j + 1));
			s(i, j) = best;
		}
	int i = 0, j = 0;
	while (i < n && j < m) {
		double v = sim[(size_t)i * m + j];
		if (v >= PAIR_MIN && s(i, j) == v + s(i + 1, j + 1)) { out.push_back({ a0 + i, b0 + j }); i++; j++; }
		else if (s(i, j) == s(i + 1, j)) i++;
		else j++;
	}
	return out;
}

static int firstNonSpace(const std::string& s)
{
	size_t p = s.find_first_not_of(" \t");
	return p == std::string::npos ? (int)s.size() : (int)p;
}

static void wholeSpan(const std::string& text, char kind, std::vector<Span>* spans)
{
	int s = firstNonSpace(text);
	if (s < (int)text.size()) spans->push_back({ s, (int)text.size(), kind });
}

// the equal words of two paired lines (indexes in words)
static Matches wordMatches(const LineInfo& a, const LineInfo& b)
{
	size_t n = a.words.size(), m = b.words.size();
	Matches tm;
	if (n * m <= 90000) {
		std::vector<int> L((n + 1) * (m + 1), 0);
		auto at = [&](size_t i, size_t j) -> int& { return L[i * (m + 1) + j]; };
		for (size_t i = n; i-- > 0; )
			for (size_t j = m; j-- > 0; )
				at(i, j) = a.words[i] == b.words[j] ? at(i + 1, j + 1) + 1 : std::max(at(i + 1, j), at(i, j + 1));
		size_t i = 0, j = 0;
		while (i < n && j < m) {
			if (a.words[i] == b.words[j]) { tm.push_back({ (int)i, (int)j }); i++; j++; }
			else if (at(i + 1, j) >= at(i, j + 1)) i++;
			else j++;
		}
	}
	return tm;
}

// the changed tokens of two paired lines
static void tokenSpans(const LineInfo& a, const LineInfo& b, const std::string& ta, const std::string& tb, Row* row)
{
	size_t n = a.words.size(), m = b.words.size();
	Matches tm = wordMatches(a, b);
	tm.push_back({ (int)n, (int)m });   // sentinel
	int pi = 0, pj = 0;
	for (const auto& mt : tm) {
		bool left = mt.first > pi, right = mt.second > pj;
		if (left) {
			int s = a.toks[a.wordTok[pi]].start, e = a.toks[a.wordTok[mt.first - 1]].end;
			row->lspans.push_back({ s, e, right ? '^' : '-' });
		}
		if (right) {
			int s = b.toks[b.wordTok[pj]].start, e = b.toks[b.wordTok[mt.second - 1]].end;
			row->rspans.push_back({ s, e, left ? '^' : '+' });
		}
		pi = mt.first + 1;
		pj = mt.second + 1;
	}
	if (row->lspans.empty() && row->rspans.empty()) {
		// equal once normalized but not aligned (a moved line)
		wholeSpan(ta, '^', &row->lspans);
		wholeSpan(tb, '^', &row->rspans);
	}
}

static std::string joinList(const std::vector<std::string>& v, size_t max = 8)
{
	std::string out;
	for (size_t i = 0; i < v.size() && i < max; i++) out += (i == 0 ? "" : ", ") + v[i];
	if (v.size() > max) out += " (+" + std::to_string(v.size() - max) + ")";
	return out;
}

//------------------------------------------------------------------------------
// the locals: renamed after OLD
//------------------------------------------------------------------------------
static const char LOCAL_KEY[] = "\x02local";

// the token k is a member: x.name, p->name
static bool isMember(const std::vector<Token>& toks, size_t k)
{
	size_t j = k;
	while (j > 0 && toks[j - 1].kind == T_SPACE) j--;
	if (j == 0) return false;
	if (toks[j - 1].key == ".") return true;
	return toks[j - 1].key == ">" && j >= 2 && toks[j - 2].key == "-";
}

// words that start a statement ending in ";" with a name: return v1;
static bool isStatementWord(const std::string& s)
{
	static const std::set<std::string> kw = { "return", "goto", "break", "continue", "do", "else", "case",
		"default", "if", "while", "for", "switch", "sizeof", "delete", "throw" };
	return kw.count(s) != 0;
}

// the name declared by a line ("  uint v1 [2];", "  void (*v1)(int);"), or ""
// if it is a statement: a type and a name (two words at least) made of names,
// '*', '&', '::' and template arguments only. With no locals the first line of
// the body is a statement: "return *(int *)(p + 0x10);", "FUN_1(a);", "x = 0;"
static std::string declaredName(const std::string& line)
{
	std::vector<Token> toks = tokenize(line, 0);
	while (!toks.empty() && (toks.back().kind == T_SPACE || toks.back().kind == T_COMMENT)) toks.pop_back();
	if (toks.empty() || toks.back().key != ";")
		return "";
	std::string name;
	int words = 0;
	bool fnPtr = false, first = true;
	for (size_t k = 0; k < toks.size(); k++) {
		const Token& t = toks[k];
		if (t.kind == T_SPACE || t.kind == T_COMMENT) continue;
		if (first && (t.kind != T_IDENT || isStatementWord(t.key))) return "";
		first = false;
		if (t.key == "[" || t.key == ";" || t.key == "=" || (t.key == ")" && fnPtr)) break;
		if (t.key == "(") {
			size_t j = k + 1;
			while (j < toks.size() && toks[j].kind == T_SPACE) j++;
			if (fnPtr || j >= toks.size() || toks[j].key != "*") return "";
			fnPtr = true;   // void (*v1)(int)
			continue;
		}
		if (t.kind == T_IDENT) {
			name = line.substr(t.start, t.end - t.start);
			words++;
		} else if (t.kind != T_NUMBER && t.key != "*" && t.key != "&" && t.key != ":" && t.key != "<"
			&& t.key != ">" && t.key != ",") {
			return "";
		}
	}
	return words >= 2 ? name : "";
}

// the names declared at the top of the body: the lines after the first one
// that ends in "{" (any brace style) up to the first one that is not a
// declaration
// *first: the index of the first declaration; names: the name of each one
static void declarations(const std::vector<std::string>& lines, size_t* first, std::vector<std::string>* names)
{
	size_t i = 0;
	for (; i < lines.size(); i++) {
		std::string key = normalizeLine(lines[i], 0);
		if (!key.empty() && key.back() == '{') break;
	}
	*first = i + 1;
	for (i++; i < lines.size(); i++) {
		std::string name = declaredName(lines[i]);
		if (name.empty())
			break;
		names->push_back(name);
	}
}

static std::set<std::string> declaredLocals(const std::vector<std::string>& lines)
{
	size_t first;
	std::vector<std::string> names;
	declarations(lines, &first, &names);
	return std::set<std::string>(names.begin(), names.end());
}

// the declarations of NEW (renamed) in the order of those of OLD, the others
// after them: Ghidra sorts them by name, and the order changes nothing
static void sortDeclarations(const std::vector<std::string>& oldLines, std::vector<std::string>* newLines)
{
	size_t oldFirst, newFirst;
	std::vector<std::string> oldNames, newNames;
	declarations(oldLines, &oldFirst, &oldNames);
	declarations(*newLines, &newFirst, &newNames);
	std::map<std::string, size_t> rank;
	for (size_t i = 0; i < oldNames.size(); i++) rank.emplace(oldNames[i], i);
	std::vector<std::pair<size_t, std::string>> decls;
	for (size_t i = 0; i < newNames.size(); i++) {
		auto r = rank.find(newNames[i]);
		decls.push_back({ r != rank.end() ? r->second : oldNames.size(), (*newLines)[newFirst + i] });
	}
	std::stable_sort(decls.begin(), decls.end(),
		[](const std::pair<size_t, std::string>& a, const std::pair<size_t, std::string>& b) { return a.first < b.first; });
	for (size_t i = 0; i < decls.size(); i++) (*newLines)[newFirst + i] = decls[i].second;
}

struct Builder
{
	std::unordered_map<std::string, int> ids;
	int idOf(const std::string& k)
	{
		auto p = ids.emplace(k, (int)ids.size());
		return p.first->second;
	}
	// locals: names that compare equal to each other
	void info(const std::vector<std::string>& lines, uint64_t base, const std::set<std::string>* locals,
		std::vector<LineInfo>* out, std::vector<int>* keys)
	{
		for (const auto& l : lines) {
			LineInfo li;
			li.toks = tokenize(l, base);
			if (locals != nullptr)
				for (size_t k = 0; k < li.toks.size(); k++) {
					Token& t = li.toks[k];
					if (t.kind == T_IDENT && locals->count(l.substr(t.start, t.end - t.start)) != 0 && !isMember(li.toks, k))
						t.key = LOCAL_KEY;
				}
			for (size_t k = 0; k < li.toks.size(); k++)
				if (li.toks[k].kind != T_SPACE) {
					li.words.push_back(idOf("\x01" + li.toks[k].key));
					li.wordTok.push_back((int)k);
				}
			li.key = keyOf(li.toks);
			keys->push_back(idOf(li.key));
			out->push_back(std::move(li));
		}
	}
};

// the lines that line up: the anchors of the patience diff and the similar
// lines paired inside the gaps
static Matches alignedLines(const std::vector<LineInfo>& L, const std::vector<LineInfo>& R,
	const std::vector<int>& A, const std::vector<int>& B)
{
	Matches matches, out;
	patience(A, B, 0, (int)A.size(), 0, (int)B.size(), matches);
	matches.push_back({ (int)A.size(), (int)B.size() });
	int pa = 0, pb = 0;
	for (const auto& mt : matches) {
		if (mt.first > pa || mt.second > pb) {
			Matches pairs = pairLines(L, R, pa, mt.first, pb, mt.second);
			out.insert(out.end(), pairs.begin(), pairs.end());
		}
		if (mt.first < (int)A.size()) out.push_back(mt);
		pa = mt.first + 1;
		pb = mt.second + 1;
	}
	return out;
}

// NEW name -> OLD name: a pair of locals gets a vote for every place where
// both are used in two lines that line up (with the locals masked); the pairs
// with the most votes win
static std::map<std::string, std::string> matchLocals(const std::vector<std::string>& oldLines,
	const std::vector<std::string>& newLines, uint64_t oldBase, uint64_t newBase,
	const std::set<std::string>& oldLocals, const std::set<std::string>& newLocals)
{
	Builder bld;
	std::vector<LineInfo> L, R;
	std::vector<int> A, B;
	bld.info(oldLines, oldBase, &oldLocals, &L, &A);
	bld.info(newLines, newBase, &newLocals, &R, &B);

	std::map<std::pair<std::string, std::string>, int> votes;     // (old, new)
	for (const auto& ln : alignedLines(L, R, A, B)) {
		const LineInfo& a = L[ln.first];
		const LineInfo& b = R[ln.second];
		for (const auto& w : wordMatches(a, b)) {
			const Token& ta = a.toks[a.wordTok[w.first]];
			const Token& tb = b.toks[b.wordTok[w.second]];
			if (ta.key != LOCAL_KEY || tb.key != LOCAL_KEY) continue;
			votes[{ oldLines[ln.first].substr(ta.start, ta.end - ta.start),
				newLines[ln.second].substr(tb.start, tb.end - tb.start) }]++;
		}
	}
	typedef std::pair<int, std::pair<std::string, std::string>> Vote;
	std::vector<Vote> ranked;
	for (const auto& v : votes) ranked.push_back({ v.second, v.first });
	// the most votes first; on a tie the same name, then the order of the names
	std::stable_sort(ranked.begin(), ranked.end(), [](const Vote& x, const Vote& y) {
		if (x.first != y.first) return x.first > y.first;
		return (x.second.first == x.second.second) > (y.second.first == y.second.second);
	});
	std::map<std::string, std::string> out;
	std::set<std::string> taken;
	for (const Vote& r : ranked)
		if (out.count(r.second.second) == 0 && taken.count(r.second.first) == 0) {
			out[r.second.second] = r.second.first;
			taken.insert(r.second.first);
		}
	return out;
}

// NEW with its locals renamed; those without a match whose name OLD uses get
// a new one (v1, v2... used by neither side)
static std::vector<std::string> renameLocals(const std::vector<std::string>& oldLines,
	const std::vector<std::string>& newLines, const std::set<std::string>& oldLocals,
	const std::set<std::string>& newLocals, std::map<std::string, std::string>* names)
{
	std::set<std::string> used;
	for (const std::vector<std::string>* lines : { &oldLines, &newLines })
		for (const auto& l : *lines)
			for (const Token& t : tokenize(l, 0))
				if (t.kind == T_IDENT) used.insert(l.substr(t.start, t.end - t.start));
	std::set<std::string> targets;
	for (const auto& kv : *names) targets.insert(kv.second);
	int next = 1;
	for (const std::string& n : newLocals) {
		if (names->count(n) != 0 || (oldLocals.count(n) == 0 && targets.count(n) == 0)) continue;
		std::string nn;
		do nn = "v" + std::to_string(next++); while (used.count(nn) != 0 || targets.count(nn) != 0);
		(*names)[n] = nn;
		targets.insert(nn);
	}
	if (names->empty())
		return newLines;

	std::vector<std::string> out;
	for (const auto& l : newLines) {
		std::vector<Token> toks = tokenize(l, 0);
		std::string r;
		for (size_t k = 0; k < toks.size(); k++) {
			std::string raw = l.substr(toks[k].start, toks[k].end - toks[k].start);
			auto p = toks[k].kind == T_IDENT && !isMember(toks, k) ? names->find(raw) : names->end();
			r += p != names->end() ? p->second : raw;
		}
		out.push_back(r);
	}
	return out;
}

//------------------------------------------------------------------------------
static Result diffAligned(const std::vector<std::string>& oldLines, const std::vector<std::string>& newLines,
	uint64_t oldBase, uint64_t newBase)
{
	Result res;
	Builder bld;
	std::vector<LineInfo> L, R;
	std::vector<int> A, B;
	bld.info(oldLines, oldBase, nullptr, &L, &A);
	bld.info(newLines, newBase, nullptr, &R, &B);

	Matches matches;
	patience(A, B, 0, (int)A.size(), 0, (int)B.size(), matches);
	matches.push_back({ (int)A.size(), (int)B.size() });    // sentinel

	auto fullRow = [&](int i, int j) {
		Row r;
		r.lno = i >= 0 ? i + 1 : 0;
		r.rno = j >= 0 ? j + 1 : 0;
		r.changed = true;
		if (i >= 0) wholeSpan(oldLines[i], '-', &r.lspans);
		if (j >= 0) wholeSpan(newLines[j], '+', &r.rspans);
		res.rows.push_back(std::move(r));
	};
	// unpaired lines of a gap, side by side
	auto unpaired = [&](int i0, int i1, int j0, int j1) {
		int k = std::max(i1 - i0, j1 - j0);
		for (int x = 0; x < k; x++)
			fullRow(i0 + x < i1 ? i0 + x : -1, j0 + x < j1 ? j0 + x : -1);
	};

	int pa = 0, pb = 0;
	for (const auto& mt : matches) {
		if (mt.first > pa || mt.second > pb) {
			Matches pairs = pairLines(L, R, pa, mt.first, pb, mt.second);
			int ca = pa, cb = pb;
			for (const auto& p : pairs) {
				unpaired(ca, p.first, cb, p.second);
				Row r;
				r.lno = p.first + 1;
				r.rno = p.second + 1;
				r.changed = true;
				tokenSpans(L[p.first], R[p.second], oldLines[p.first], newLines[p.second], &r);
				res.rows.push_back(std::move(r));
				ca = p.first + 1;
				cb = p.second + 1;
			}
			unpaired(ca, mt.first, cb, mt.second);
		}
		if (mt.first < (int)A.size()) {
			Row r;
			r.lno = mt.first + 1;
			r.rno = mt.second + 1;
			r.normalized = oldLines[mt.first] != newLines[mt.second];
			if (r.normalized) res.normalizedRows++;
			res.rows.push_back(std::move(r));
		}
		pa = mt.first + 1;
		pb = mt.second + 1;
	}

	// the changes: runs of changed rows
	for (size_t k = 0; k < res.rows.size(); ) {
		if (!res.rows[k].changed) { k++; continue; }
		Change c;
		Named oc, nc, ok, nk;
		int oldN = 0, newN = 0;
		for (; k < res.rows.size() && res.rows[k].changed; k++) {
			const Row& r = res.rows[k];
			if (r.lno != 0) {
				if (c.oldFirst == 0) c.oldFirst = r.lno;
				c.oldLast = r.lno;
				oldN++;
				lineFacts(oldLines[r.lno - 1], L[r.lno - 1].toks, &oc, nullptr, &ok);
			}
			if (r.rno != 0) {
				if (c.newFirst == 0) c.newFirst = r.rno;
				c.newLast = r.rno;
				newN++;
				lineFacts(newLines[r.rno - 1], R[r.rno - 1].toks, &nc, nullptr, &nk);
			}
		}
		c.kind = oldN == 0 ? "added" : newN == 0 ? "removed" : "modified";
		setDiff(nc, oc, &c.callsAdded);
		setDiff(oc, nc, &c.callsRemoved);
		setDiff(nk, ok, &c.constantsAdded);
		setDiff(ok, nk, &c.constantsRemoved);
		if (c.kind == "added") c.description = std::to_string(newN) + (newN == 1 ? " line added" : " lines added");
		else if (c.kind == "removed") c.description = std::to_string(oldN) + (oldN == 1 ? " line removed" : " lines removed");
		else c.description = std::to_string(oldN) + " -> " + std::to_string(newN) + " lines";
		if (!c.callsAdded.empty()) c.description += "; calls added: " + joinList(c.callsAdded);
		if (!c.callsRemoved.empty()) c.description += "; calls removed: " + joinList(c.callsRemoved);
		if (!c.constantsAdded.empty()) c.description += "; constants added: " + joinList(c.constantsAdded);
		if (!c.constantsRemoved.empty()) c.description += "; constants removed: " + joinList(c.constantsRemoved);
		res.changes.push_back(std::move(c));
	}
	res.identical = res.changes.empty();

	// the whole function
	Named ocalls, ncalls, oconst, nconst;
	std::map<std::string, int> ocount, ncount;
	for (size_t i = 0; i < oldLines.size(); i++) lineFacts(oldLines[i], L[i].toks, &ocalls, &ocount, &oconst);
	for (size_t i = 0; i < newLines.size(); i++) lineFacts(newLines[i], R[i].toks, &ncalls, &ncount, &nconst);
	std::set<std::string> keys;
	for (const auto& kv : ocount) keys.insert(kv.first);
	for (const auto& kv : ncount) keys.insert(kv.first);
	for (const auto& k : keys) {
		int o = ocount.count(k) ? ocount[k] : 0, nn = ncount.count(k) ? ncount[k] : 0;
		if (o == nn) continue;
		std::string name = nn > 0 ? ncalls[k] : ocalls[k];
		if (o == 0) res.callsAdded.push_back(name);
		else if (nn == 0) res.callsRemoved.push_back(name);
		else (nn > o ? res.callsAdded : res.callsRemoved).push_back(name + " (" + std::to_string(o) + " -> " + std::to_string(nn) + ")");
	}
	setDiff(nconst, oconst, &res.constantsAdded);
	setDiff(oconst, nconst, &res.constantsRemoved);
	return res;
}

Result diffCode(const std::vector<std::string>& oldLines, const std::vector<std::string>& newLines,
	uint64_t oldBase, uint64_t newBase, bool rename)
{
	if (!rename) {
		Result res = diffAligned(oldLines, newLines, oldBase, newBase);
		res.newLines = newLines;
		return res;
	}
	std::set<std::string> oldLocals = declaredLocals(oldLines), newLocals = declaredLocals(newLines);
	std::map<std::string, std::string> names;
	if (!oldLocals.empty() && !newLocals.empty())
		names = matchLocals(oldLines, newLines, oldBase, newBase, oldLocals, newLocals);
	std::vector<std::string> renamed = renameLocals(oldLines, newLines, oldLocals, newLocals, &names);
	if (!names.empty())
		sortDeclarations(oldLines, &renamed);
	Result res = diffAligned(oldLines, renamed, oldBase, newBase);
	res.newLines = std::move(renamed);
	for (const auto& kv : names)
		if (kv.first != kv.second) res.renamedLocals.push_back(kv);
	return res;
}

} // namespace ghidradec_diff
