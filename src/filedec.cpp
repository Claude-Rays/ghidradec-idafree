/**
 * @file filedec.cpp
 * @brief Decompile a function of a binary on disk (PE or ELF).
 *
 * The other version of a Diaphora-ng diff is not open in IDA, and its SQLite
 * export has no bytes: GhidraDec maps the sections of its file itself and
 * answers the queries of a second decompile.exe from them (FileCallback),
 * instead of the IDA database (IdaCallback). The processor, the compiler spec
 * and the options are those of the open database: both versions are the same
 * program.
 *
 * What the file cannot give, the caller and the open database do: the names
 * and the prototypes of the functions come from Diaphora's export of the other
 * database, and the prototypes of the imports from the import of the same name
 * in the open database. The addresses are those of the other database: the
 * file is mapped at its image base (a rebased IDB).
 */

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <functional>
#include <mutex>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <io.h>
#include <memory>
#include <sys/stat.h>

#include "defs.h"
#include "decompiler.h"
#include "filedec.h"
#include "sleighinterface.h"

namespace idaplugin {

	// decompiler.cpp
	void makeUnknownFunctionPrototype(FuncProtoInfo& func);
	bool isKnownNoReturnFunctionName(std::string name);

//------------------------------------------------------------------------------
// the queries of the decompiler (FileCallback) that need IDA's API, main
// thread only: run there by the main thread that waits for the reply
// (mainThreadPost)
static void onMain(const std::function<void()>& fn)
{
	if (is_main_thread()) {
		fn();
		return;
	}
	if (!mainThreadPost(fn))
		throw DecompError("the main thread is not waiting for the decompiler.");
}

//------------------------------------------------------------------------------
// the binary
//------------------------------------------------------------------------------
struct FileRegion
{
	uint64_t start = 0;		// preferred address
	uint64_t size = 0;
	uint64_t fileOff = 0;
	uint64_t fileSize = 0;	// the rest of the region is zeros
	bool write = false;
	bool exec = false;
};

class FileImage
{
public:
	std::string path;
	long long mtime = 0;
	std::vector<uint8_t> file;
	std::string format;			// "PE" or "ELF"
	bool is64 = false;
	bool bigEndian = false;
	unsigned machine = 0;
	uint64_t base = 0;			// preferred image base
	std::vector<FileRegion> regions;
	std::map<uint64_t, std::pair<std::string, std::string>> imports;	// slot -> name, module
	std::map<uint64_t, std::string> symbols;	// exported or symbol table functions
	// x64 PE: the functions of the exception directory (.pdata), the chained
	// entries (cold parts, funclets of the same frame) under their function
	struct Chunk { uint64_t end; uint64_t root; };
	std::map<uint64_t, Chunk> chunks;	// start -> end (exclusive), function
	std::map<uint64_t, std::vector<std::pair<uint64_t, uint64_t>>> funcChunks;	// function -> [start, end)

	// the function whose chunk has va
	bool owner(uint64_t va, uint64_t* root) const;
	// the first function start after va (~0: none)
	uint64_t nextStart(uint64_t va) const;

	bool load(const std::string& p, std::string* err);
	const FileRegion* find(uint64_t va) const;
	// the mapped bytes from va, 0 from the first unmapped one
	int read(uint64_t va, uint8_t* out, int size) const;

private:
	uint64_t at(uint64_t off, int n) const;		// file offset, endian aware
	uint64_t atVa(uint64_t va, int n) const;
	std::string strAt(uint64_t off) const;
	std::string strAtVa(uint64_t va) const;
	bool loadPe(std::string* err);
	bool loadElf(std::string* err);
};

static long long fileMtime(const std::string& p)
{
	struct _stat64 st;
	return _stat64(p.c_str(), &st) == 0 ? (long long)st.st_mtime : -1;
}

uint64_t FileImage::at(uint64_t off, int n) const
{
	if (off + n > file.size() || off + n < off)
		return 0;
	uint64_t v = 0;
	for (int i = 0; i < n; i++)
		v |= (uint64_t)file[(size_t)off + (bigEndian ? n - 1 - i : i)] << (8 * i);
	return v;
}

uint64_t FileImage::atVa(uint64_t va, int n) const
{
	uint8_t b[8] = { 0 };
	if (read(va, b, n) != n)
		return 0;
	uint64_t v = 0;
	for (int i = 0; i < n; i++)
		v |= (uint64_t)b[bigEndian ? n - 1 - i : i] << (8 * i);
	return v;
}

std::string FileImage::strAt(uint64_t off) const
{
	std::string s;
	while (off < file.size() && file[(size_t)off] != 0 && s.size() < 4096)
		s += (char)file[(size_t)off++];
	return s;
}

std::string FileImage::strAtVa(uint64_t va) const
{
	std::string s;
	uint8_t c;
	while (s.size() < 4096 && read(va++, &c, 1) == 1 && c != 0)
		s += (char)c;
	return s;
}

bool FileImage::owner(uint64_t va, uint64_t* root) const
{
	auto it = chunks.upper_bound(va);
	if (it == chunks.begin())
		return false;
	--it;
	if (va >= it->second.end)
		return false;
	*root = it->second.root;
	return true;
}

uint64_t FileImage::nextStart(uint64_t va) const
{
	uint64_t next = ~0ull;
	auto f = funcChunks.upper_bound(va);
	if (f != funcChunks.end())
		next = f->first;
	auto y = symbols.upper_bound(va);
	if (y != symbols.end())
		next = std::min(next, y->first);
	return next;
}

const FileRegion* FileImage::find(uint64_t va) const
{
	for (const FileRegion& r : regions)
		if (va >= r.start && va - r.start < r.size)
			return &r;
	return nullptr;
}

int FileImage::read(uint64_t va, uint8_t* out, int size) const
{
	int i = 0;
	while (i < size) {
		const FileRegion* r = find(va + i);
		if (r == nullptr)
			break;
		uint64_t o = va + i - r->start;
		for (; i < size && o < r->size; i++, o++) {
			uint64_t fo = r->fileOff + o;
			out[i] = o < r->fileSize && fo < file.size() ? file[(size_t)fo] : 0;
		}
	}
	return i;
}

bool FileImage::load(const std::string& p, std::string* err)
{
	path = p;
	mtime = fileMtime(p);
	std::ifstream in(p, std::ios::binary);
	if (!in) {
		*err = "cannot open " + p + ".";
		return false;
	}
	file.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
	if (file.size() >= 0x40 && file[0] == 'M' && file[1] == 'Z')
		return loadPe(err);
	if (file.size() >= 0x34 && file[0] == 0x7f && file[1] == 'E' && file[2] == 'L' && file[3] == 'F')
		return loadElf(err);
	*err = p + " is not a PE or an ELF file.";
	return false;
}

bool FileImage::loadPe(std::string* err)
{
	format = "PE";
	bigEndian = false;
	uint64_t pe = at(0x3c, 4);
	if (at(pe, 4) != 0x4550) {
		*err = path + " is an MZ file without a PE header.";
		return false;
	}
	machine = (unsigned)at(pe + 4, 2);
	unsigned nsec = (unsigned)at(pe + 6, 2);
	unsigned optSize = (unsigned)at(pe + 20, 2);
	uint64_t opt = pe + 24;
	unsigned magic = (unsigned)at(opt, 2);
	if (magic != 0x10b && magic != 0x20b) {
		*err = path + " has an unknown PE optional header.";
		return false;
	}
	is64 = magic == 0x20b;
	base = is64 ? at(opt + 24, 8) : at(opt + 28, 4);
	uint64_t hdrSize = at(opt + 60, 4);
	unsigned ndd = (unsigned)at(opt + (is64 ? 108 : 92), 4);
	uint64_t dd = opt + (is64 ? 112 : 96);

	FileRegion h;
	h.start = base;
	h.size = hdrSize;
	h.fileSize = hdrSize;
	regions.push_back(h);
	uint64_t sec = opt + optSize;
	for (unsigned i = 0; i < nsec; i++) {
		uint64_t s = sec + 40ull * i;
		uint64_t vsize = at(s + 8, 4), va = at(s + 12, 4), rawSize = at(s + 16, 4), rawPtr = at(s + 20, 4);
		uint32_t ch = (uint32_t)at(s + 36, 4);
		FileRegion r;
		r.start = base + va;
		r.size = vsize != 0 ? vsize : rawSize;
		r.fileOff = rawPtr;
		r.fileSize = std::min(rawSize, r.size);
		r.write = (ch & 0x80000000u) != 0;
		r.exec = (ch & 0x20000000u) != 0;
		if (r.size != 0)
			regions.push_back(r);
	}

	int ps = is64 ? 8 : 4;
	uint64_t ordFlag = is64 ? 0x8000000000000000ull : 0x80000000ull;
	auto module = [](std::string dll) {
		size_t dot = dll.rfind('.');
		if (dot != std::string::npos)
			dll.erase(dot);
		std::transform(dll.begin(), dll.end(), dll.begin(), [](unsigned char c) { return (char)toupper(c); });
		return dll;
	};
	auto thunks = [&](const std::string& mod, uint64_t names, uint64_t iat) {
		for (uint64_t k = 0; k < 100000; k++) {
			uint64_t t = atVa(base + names + k * ps, ps);
			if (t == 0)
				break;
			std::string nm = (t & ordFlag) != 0 ? mod + "_" + std::to_string((unsigned)(t & 0xffff))
				: strAtVa(base + (t & 0x7fffffff) + 2);
			if (!nm.empty())
				imports[base + iat + k * ps] = std::make_pair(nm, mod);
		}
	};
	// imports
	if (ndd > 1 && at(dd + 8, 4) != 0) {
		uint64_t desc = base + at(dd + 8, 4);
		for (int i = 0; i < 10000; i++, desc += 20) {
			uint64_t oft = atVa(desc, 4), name = atVa(desc + 12, 4), ft = atVa(desc + 16, 4);
			if (ft == 0)
				break;
			thunks(module(strAtVa(base + name)), oft != 0 ? oft : ft, ft);
		}
	}
	// delay-load imports (RVA based)
	if (ndd > 13 && at(dd + 13 * 8, 4) != 0) {
		uint64_t desc = base + at(dd + 13 * 8, 4);
		for (int i = 0; i < 10000; i++, desc += 32) {
			uint64_t attr = atVa(desc, 4), name = atVa(desc + 4, 4), iat = atVa(desc + 12, 4), nt = atVa(desc + 16, 4);
			if (name == 0)
				break;
			if ((attr & 1) != 0 && iat != 0 && nt != 0)
				thunks(module(strAtVa(base + name)), nt, iat);
		}
	}
	// exports
	if (ndd > 0 && at(dd, 4) != 0) {
		uint64_t erva = at(dd, 4), esize = at(dd + 4, 4);
		uint64_t ed = base + erva;
		uint64_t nnames = atVa(ed + 24, 4), aof = atVa(ed + 28, 4), aon = atVa(ed + 32, 4), aoo = atVa(ed + 36, 4);
		for (uint64_t i = 0; i < nnames && i < 1000000; i++) {
			uint64_t ord = atVa(base + aoo + 2 * i, 2);
			uint64_t frva = atVa(base + aof + 4 * ord, 4);
			if (frva == 0 || (frva >= erva && frva < erva + esize))
				continue;	// a forwarder
			std::string nm = strAtVa(base + atVa(base + aon + 4 * i, 4));
			if (!nm.empty())
				symbols[base + frva] = nm;
		}
	}
	// the exception directory of x64: RUNTIME_FUNCTION {start, end, unwind}
	if (machine == 0x8664 && ndd > 3 && at(dd + 24, 4) != 0) {
		uint64_t erva = at(dd + 24, 4), esize = at(dd + 28, 4);
		for (uint64_t i = 0; i + 12 <= esize && i < 12ull * 2000000; i += 12) {
			uint64_t b = atVa(base + erva + i, 4), e = atVa(base + erva + i + 4, 4), u = atVa(base + erva + i + 8, 4);
			if (b == 0 || e <= b)
				continue;
			// UNW_FLAG_CHAININFO: the RUNTIME_FUNCTION of the parent follows
			// the unwind codes
			uint64_t root = b;
			for (int depth = 0; depth < 32 && u != 0; depth++) {
				if (((atVa(base + (u & ~1ull), 1) >> 3) & 4) == 0)
					break;
				unsigned count = (unsigned)atVa(base + u + 2, 1);
				uint64_t parent = base + u + 4 + ((count + 1ull) & ~1ull) * 2;
				uint64_t pb = atVa(parent, 4);
				if (pb == 0)
					break;
				root = pb;
				u = atVa(parent + 8, 4);
			}
			chunks[base + b] = Chunk{ base + e, base + root };
			funcChunks[base + root].push_back(std::make_pair(base + b, base + e));
		}
		for (auto& f : funcChunks)
			std::sort(f.second.begin(), f.second.end());
	}
	return true;
}

// the relocations of an import slot (GOT entry), per ELF machine
static bool isElfImportReloc(unsigned machine, uint64_t type, bool* jumpSlot)
{
	struct { unsigned machine; uint64_t globDat, jumpSlot; } table[] = {
		{ 3, 6, 7 },		// i386
		{ 62, 6, 7 },		// x86-64
		{ 40, 21, 22 },		// ARM
		{ 183, 1025, 1026 },	// AArch64
		{ 8, ~0ull, 127 },	// MIPS
		{ 20, 20, 21 },		// PPC
		{ 21, 20, 21 },		// PPC64
		{ 243, ~0ull, 5 },	// RISC-V
	};
	for (const auto& t : table)
		if (t.machine == machine && (type == t.globDat || type == t.jumpSlot)) {
			*jumpSlot = type == t.jumpSlot;
			return true;
		}
	return false;
}

bool FileImage::loadElf(std::string* err)
{
	format = "ELF";
	is64 = file[4] == 2;
	bigEndian = file[5] == 2;
	machine = (unsigned)at(18, 2);
	uint64_t phoff = is64 ? at(32, 8) : at(28, 4);
	uint64_t shoff = is64 ? at(40, 8) : at(32, 4);
	unsigned phentsize = (unsigned)at(is64 ? 54 : 42, 2), phnum = (unsigned)at(is64 ? 56 : 44, 2);
	unsigned shentsize = (unsigned)at(is64 ? 58 : 46, 2), shnum = (unsigned)at(is64 ? 60 : 48, 2);

	uint64_t minVa = ~0ull;
	for (unsigned i = 0; i < phnum; i++) {
		uint64_t p = phoff + (uint64_t)i * phentsize;
		if (at(p, 4) != 1)	// PT_LOAD
			continue;
		uint64_t flags, off, va, filesz, memsz;
		if (is64) {
			flags = at(p + 4, 4); off = at(p + 8, 8); va = at(p + 16, 8); filesz = at(p + 32, 8); memsz = at(p + 40, 8);
		} else {
			off = at(p + 4, 4); va = at(p + 8, 4); filesz = at(p + 16, 4); memsz = at(p + 20, 4); flags = at(p + 24, 4);
		}
		FileRegion r;
		r.start = va;
		r.size = memsz;
		r.fileOff = off;
		r.fileSize = std::min(filesz, memsz);
		r.write = (flags & 2) != 0;
		r.exec = (flags & 1) != 0;
		if (r.size != 0) {
			regions.push_back(r);
			minVa = std::min(minVa, va);
		}
	}
	if (regions.empty()) {
		*err = path + " has no loadable segment (an object file?).";
		return false;
	}
	base = minVa & ~0xfffull;

	struct Sec { uint64_t type, offset, size, link, entsize; };
	std::vector<Sec> secs;
	for (unsigned i = 0; i < shnum && shoff != 0; i++) {
		uint64_t s = shoff + (uint64_t)i * shentsize;
		Sec x;
		if (is64) {
			x.type = at(s + 4, 4); x.offset = at(s + 24, 8); x.size = at(s + 32, 8); x.link = at(s + 40, 4); x.entsize = at(s + 56, 8);
		} else {
			x.type = at(s + 4, 4); x.offset = at(s + 16, 4); x.size = at(s + 20, 4); x.link = at(s + 24, 4); x.entsize = at(s + 36, 4);
		}
		secs.push_back(x);
	}
	struct Sym { std::string name; uint64_t value; unsigned type; unsigned shndx; };
	auto symAt = [&](const Sec& symtab, uint64_t idx) {
		Sym y{ "", 0, 0, 0 };
		uint64_t e = symtab.offset + idx * (symtab.entsize != 0 ? symtab.entsize : (is64 ? 24 : 16));
		uint64_t nameOff;
		if (is64) {
			nameOff = at(e, 4); y.type = (unsigned)at(e + 4, 1) & 0xf; y.shndx = (unsigned)at(e + 6, 2); y.value = at(e + 8, 8);
		} else {
			nameOff = at(e, 4); y.value = at(e + 4, 4); y.type = (unsigned)at(e + 12, 1) & 0xf; y.shndx = (unsigned)at(e + 14, 2);
		}
		if (symtab.link < secs.size())
			y.name = strAt(secs[(size_t)symtab.link].offset + nameOff);
		return y;
	};
	// functions: the symbol table first, then the dynamic one
	for (uint64_t want : { 2ull, 11ull }) {
		for (const Sec& s : secs) {
			if (s.type != want || s.entsize == 0)
				continue;
			for (uint64_t i = 1; i < s.size / s.entsize && i < 10000000; i++) {
				Sym y = symAt(s, i);
				if (y.type != 2 || y.shndx == 0 || y.value == 0 || y.name.empty())
					continue;
				uint64_t va = machine == 40 ? y.value & ~1ull : y.value;	// Thumb
				symbols.insert(std::make_pair(va, y.name));
			}
		}
	}
	// imports: the GOT slots of the undefined symbols
	for (const Sec& s : secs) {
		if ((s.type != 4 && s.type != 9) || s.link >= secs.size())
			continue;
		const Sec& symtab = secs[(size_t)s.link];
		uint64_t entsize = s.entsize != 0 ? s.entsize : (is64 ? (s.type == 4 ? 24 : 16) : (s.type == 4 ? 12 : 8));
		for (uint64_t i = 0; i < s.size / entsize && i < 10000000; i++) {
			uint64_t e = s.offset + i * entsize;
			uint64_t off = is64 ? at(e, 8) : at(e, 4);
			uint64_t info = is64 ? at(e + 8, 8) : at(e + 4, 4);
			uint64_t symIdx = is64 ? info >> 32 : info >> 8;
			uint64_t type = is64 ? info & 0xffffffffull : info & 0xff;
			bool jumpSlot = false;
			if (symIdx == 0 || !isElfImportReloc(machine, type, &jumpSlot))
				continue;
			Sym y = symAt(symtab, symIdx);
			if (y.shndx != 0 || y.name.empty() || (!jumpSlot && y.type != 2))
				continue;
			size_t at_ = y.name.find('@');	// symbol versions
			imports[off] = std::make_pair(at_ != std::string::npos ? y.name.substr(0, at_) : y.name, std::string());
		}
	}
	return true;
}

//------------------------------------------------------------------------------
// the session: the loaded binary and its decompiler process
//------------------------------------------------------------------------------
class FileCallback;

struct FileSession
{
	FileImage img;
	int64_t bias = 0;		// address in the other database = preferred address + bias
	std::map<uint64_t, FileFunc> funcs;
	std::map<uint64_t, FuncProtoInfo> protoCache;
	uint64_t current = 0;	// the function being decompiled (other database)
	std::unique_ptr<FileCallback> cb;
	std::unique_ptr<DecompInterface> dec;
	~FileSession();
};

static std::unique_ptr<FileSession> g_file;

static std::string hexName(const char* prefix, uint64_t v)
{
	char buf[64];
	qsnprintf(buf, sizeof(buf), "%s%llX", prefix, (unsigned long long)v);
	return buf;
}

// a name that Diaphora's export already demangled ("public: virtual long
// C::Save(unsigned short const *,int)"): without the arguments, the access,
// the return type and the qualifiers ("C::Save")
static std::string undecoratedShortName(const std::string& raw)
{
	std::string out = raw;
	int depth = 0;
	for (size_t i = 0; i < out.size(); ++i) {
		if (out.compare(i, 8, "operator") == 0) {
			i += 8;
			if (out.compare(i, 2, "()") == 0)
				i += 2;
			while (i < out.size() && strchr("<>=!+-*/%^&|~[], ", out[i]) != nullptr && out[i] != '(')
				++i;
			--i;
		} else if (out[i] == '<')
			++depth;
		else if (out[i] == '>' && depth > 0)
			--depth;
		else if (out[i] == '(' && depth == 0) {
			out.resize(i);
			break;
		}
	}
	depth = 0;
	size_t start = 0;
	for (size_t i = 0; i < out.size(); ++i) {
		if (out[i] == '<')
			++depth;
		else if (out[i] == '>' && depth > 0)
			--depth;
		else if (out[i] == ' ' && depth == 0 && out.compare(i + 1, 8, "operator") != 0
			&& !(i >= 8 && out.compare(i - 8, 8, "operator") == 0))
			start = i + 1;
	}
	out = out.substr(start);
	return out.empty() ? raw : out;
}

// as functionDisplayName(): demangled, without the arguments
static std::string displayName(const std::string& raw)
{
	static std::mutex m;
	static std::map<std::string, std::string> cache;
	{
		std::lock_guard<std::mutex> lock(m);
		auto c = cache.find(raw);
		if (c != cache.end())
			return c->second;
	}
	std::string name;
	onMain([&]() { name = demangledShortName(raw); });
	if (name.empty())
		name = undecoratedShortName(raw);
	while (!name.empty() && name[0] == '.')
		name.erase(name.begin());
	std::replace(name.begin(), name.end(), '.', '_');
	std::replace(name.begin(), name.end(), '@', '_');
	std::lock_guard<std::mutex> lock(m);
	cache[raw] = name;
	return name;
}

// IDA's C declaration of a function, with or without its name
static bool parsePrototype(const std::string& decl, tinfo_t* ti)
{
	if (decl.empty())
		return false;
	int flags = PT_SIL | PT_RELAXED;
	qstring nm;
	if (parse_decl(ti, &nm, nullptr, (decl + ";").c_str(), flags) && ti->is_func())
		return true;
	size_t p = decl.find('(');
	if (p == std::string::npos)
		return false;
	std::string named = decl.substr(0, p) + " ghidradec_f" + decl.substr(p) + ";";
	return parse_decl(ti, &nm, nullptr, named.c_str(), flags) && ti->is_func();
}

// the protocol of the last decompilation of a file, for the diagnosis:
// %TEMP%\ghidradec-filedec.log, only with GHIDRADEC_FILE_TRACE=1 (it is
// large and slow)
static std::mutex g_traceMutex;
static FILE* g_trace = nullptr;

static void traceOpen()
{
	std::lock_guard<std::mutex> lock(g_traceMutex);
	if (g_trace != nullptr) {
		qfclose(g_trace);
		g_trace = nullptr;
	}
	qstring on;
	if (!qgetenv("GHIDRADEC_FILE_TRACE", &on) || on != "1")
		return;
	qstring tmp;
	if (!qgetenv("TEMP", &tmp))
		tmp = ".";
	std::string p = std::string(tmp.c_str()) + "\\ghidradec-filedec.log";
	g_trace = qfopen(p.c_str(), "w");
}

static void trace(const std::string& line)
{
	std::lock_guard<std::mutex> lock(g_traceMutex);
	if (g_trace != nullptr) {
		qfputs((line + "\n").c_str(), g_trace);
		qflush(g_trace);
	}
}

static std::string traceSym(const SymInfo& si)
{
	std::string t;
	for (const TypeInfo& ti : si.pi.ti)
		t += (t.empty() ? "" : " > ") + ti.typeName + "/" + ti.metaType + "/" + std::to_string(ti.size);
	char off[32];
	qsnprintf(off, sizeof(off), "0x%llx", (unsigned long long)si.addr.addr.offset);
	return si.pi.name + " @" + si.addr.addr.space + ":" + off + ":" + std::to_string(si.addr.size)
		+ " joins=" + std::to_string(si.addr.addr.joins.size()) + " [" + t + "]";
}

// the prototype sent to the decompiler, in the trace
static void traceProto(const std::string& what, const FuncProtoInfo& func)
{
	if (g_trace == nullptr)
		return;
	trace("proto " + what + " model=" + func.model + " extrapop=" + std::to_string((long long)func.extraPop)
		+ " noreturn=" + std::to_string(func.isNoReturn) + " ret=" + traceSym(func.retType));
	for (const SymInfo& si : func.syminfo)
		trace("proto   arg" + std::to_string(si.argIndex) + " " + traceSym(si));
}

// as IdaCallback::getFuncInfo: IDA's prototype gives the bytes purged by the
// callee and the stack arguments past the return address, Ghidra wants both
// with the return address (on x64, extrapop 8). Without it every CALL leaves
// its return address on the stack: "*(undefined8 *)(rsp + -8) = 0x180074daa"
// and a lost stack pointer
static void addReturnAddress(FuncProtoInfo& func)
{
	unsigned long long retSize = inf_is_64bit() ? 8 : inf_is_32bit() ? 4 : 2;
	for (SymInfo& si : func.syminfo)
		if (si.addr.addr.space == "stack")
			si.addr.addr.offset += retSize;
	if (func.extraPop != -1)
		func.extraPop += retSize;
	else if (inf_is_64bit())
		func.extraPop = retSize;    // the callee never purges arguments on x64
}

class FileCallback : public DecompileCallback
{
	RdGlobalInfo* di;
	FileSession* s;
public:
	intptr_t pid = 0;
	void* hdl = nullptr;
	int rd = -1, wr = -1;
	bool canonical = true;	// of the current request

	FileCallback(RdGlobalInfo* d, FileSession* fs) : di(d), s(fs) {}

	void stop(bool deregister)
	{
		if (pid != 0) {
			try {
				if (deregister && s->dec)
					s->dec->deregisterProgram();
			} catch (DecompError&) {
			}
			int rc = 0;
			if (check_process_exit(hdl, &rc, 0) != 0)
				term_process(hdl);
			pid = 0;
		}
		if (rd != -1) { _close(rd); rd = -1; }
		if (wr != -1) { _close(wr); wr = -1; }
	}

	void launchDecompiler() override
	{
		runCommand(di->decCmd, "", &pid, &hdl, &rd, &wr, true);
	}
	size_t readDec(void* Buf, size_t MaxCharCount) override
	{
		int val = _read(rd, Buf, (unsigned int)MaxCharCount);
		return val > 0 ? (size_t)val : 0;
	}
	size_t writeDec(void const* Buf, size_t MaxCharCount) override
	{
		int val = _write(wr, Buf, (unsigned int)MaxCharCount);
		return val > 0 ? (size_t)val : 0;
	}
	void terminate() override
	{
		stop(false);
	}
	bool callerIsMainThread() override
	{
		return is_main_thread();
	}
	void protocolRecorder(std::string data, bool bWrite) override
	{
		if (g_trace != nullptr)
			trace((bWrite ? "Sent: " : "Received: ") + data.substr(0, 2000));
	}
	void getInits(std::vector<InitStateItem>&) override {}
	std::string getPcodeInject(int, std::string, AddrInfo, std::string, unsigned long long) override { return ""; }
	void getCPoolRef(const std::vector<unsigned long long>&, CPoolRecord&) override {}
	std::string emit(std::string, std::string, std::string str) override { return str; }
	// only used by the diff (api.cpp)
	bool canonicalLocalNames() override { return canonical; }
	void getComments(AddrInfo, std::vector<CommentInfo>&) override {}

	int getBytes(unsigned char* ptr, int size, AddrInfo addr) override
	{
		int n = addr.space == "ram" ? s->img.read(addr.offset - s->bias, ptr, size) : 0;
		if (n < size)
			memset(ptr + n, 0, size - n);
		if (g_trace == nullptr)
			return n;
		char head[64];
		std::string hex;
		for (int i = 0; i < size && i < 16; i++) {
			qsnprintf(head, sizeof(head), "%02x", ptr[i]);
			hex += head;
		}
		qsnprintf(head, sizeof(head), "0x%llx", (unsigned long long)addr.offset);
		trace("getBytes " + addr.space + ":" + head + " size=" + std::to_string(size) + " read=" + std::to_string(n) + " " + hex);
		return n;
	}

	// a C string (at least 4 printable characters) in read-only data
	size_t cString(uint64_t ea) const
	{
		const FileRegion* r = s->img.find(ea - s->bias);
		if (r == nullptr || r->write || r->exec)
			return 0;
		uint8_t buf[1024];
		int n = s->img.read(ea - s->bias, buf, sizeof(buf));
		for (int i = 0; i < n; i++) {
			if (buf[i] == 0)
				return i >= 4 ? (size_t)i + 1 : 0;
			if (buf[i] < 0x20 && buf[i] != '\t' && buf[i] != '\n' && buf[i] != '\r')
				return 0;
		}
		return 0;
	}

	void functionProto(uint64_t ea, const std::string& name, FuncProtoInfo& func)
	{
		auto c = s->protoCache.find(ea);
		if (c != s->protoCache.end()) {
			func = c->second;
			return;
		}
		auto f = s->funcs.find(ea);
		std::string decl = f != s->funcs.end() ? f->second.prototype : std::string();
		onMain([&]() {
			tinfo_t ti;
			if (parsePrototype(decl, &ti) && di->idacb != nullptr)
				di->idacb->getFuncTypeInfo(ti, false, func);
			else
				makeUnknownFunctionPrototype(func);
			addReturnAddress(func);
		});
		if (isKnownNoReturnFunctionName(name))
			func.isNoReturn = true;
		traceProto("function " + name + (decl.empty() ? " (no prototype)" : " " + decl), func);
		s->protoCache[ea] = func;
	}

	bool functionName(uint64_t ea, std::string* name) const
	{
		auto f = s->funcs.find(ea);
		if (f != s->funcs.end() && !f->second.name.empty()) {
			*name = displayName(f->second.name);
			return true;
		}
		auto y = s->img.symbols.find(ea - s->bias);
		if (y != s->img.symbols.end()) {
			*name = displayName(y->second);
			return true;
		}
		if (f != s->funcs.end()) {
			*name = hexName("sub_", ea);
			return true;
		}
		return false;
	}

	// the function that has ea (addresses of the other database) and its
	// ranges: from the exception directory, else a function known by name
	// that starts at ea, or the one being decompiled up to the next start
	bool functionOwner(uint64_t ea, uint64_t* entry, std::vector<RangeInfo>* ranges) const
	{
		uint64_t va = ea - s->bias, root;
		if (s->img.owner(va, &root)) {
			*entry = root + s->bias;
			auto f = s->img.funcChunks.find(root);
			if (f != s->img.funcChunks.end())
				for (const auto& c : f->second)
					ranges->push_back(RangeInfo{ "ram", c.first + s->bias, c.second + s->bias - 1 });
			return true;
		}
		// without unwind information (a leaf function, not x64)
		std::string name;
		uint64_t start;
		if (functionName(ea, &name))
			start = ea;
		else if (s->current != 0 && ea > s->current)
			start = s->current;
		else
			return false;
		uint64_t sva = start - s->bias;
		const FileRegion* r = s->img.find(sva);
		if (r == nullptr || !r->exec)
			return start == ea;
		uint64_t end = std::min(s->img.nextStart(sva), r->start + r->size);
		for (auto f = s->funcs.upper_bound(start); f != s->funcs.end(); ++f)
			if (f->first - s->bias > sva) {
				end = std::min(end, f->first - s->bias);
				break;
			}
		if (va >= end)
			return false;
		*entry = start;
		ranges->push_back(RangeInfo{ "ram", start, end + s->bias - 1 });
		return true;
	}

	void getMappedSymbol(AddrInfo addr, MappedSymbolInfo& msi) override
	{
		msi.kind = KIND_HOLE;
		msi.ranges.clear();
		msi.readonly = false;
		msi.volatil = addr.space != "register";
		msi.size = 1;
		if (addr.space != "ram")
			return;
		uint64_t ea = addr.offset;
		auto imp = s->img.imports.find(ea - s->bias);
		if (imp != s->img.imports.end()) {
			msi.kind = KIND_EXTERNALREFERENCE;
			msi.name = displayName(imp->second.first);
			msi.readonly = true;
			msi.volatil = false;
			return;
		}
		std::string name;
		std::vector<RangeInfo> ranges;
		uint64_t entry = 0;
		if (functionOwner(ea, &entry, &ranges)) {
			if (!functionName(entry, &name))
				name = hexName("sub_", entry);
			msi.kind = KIND_FUNCTION;
			msi.entryPoint = entry;
			msi.ranges = ranges;
			msi.size = 1;
			for (const RangeInfo& r : ranges)
				if (r.beginoffset == entry)
					msi.size = r.endoffset - r.beginoffset + 1;
			msi.readonly = true;
			msi.volatil = false;
			msi.name = name;
			if (ea == entry)
				functionProto(ea, name, msi.func);
			return;
		}
		const FileRegion* r = s->img.find(ea - s->bias);
		msi.volatil = r == nullptr;
		msi.readonly = r != nullptr && !r->write;
		msi.size = r != nullptr ? 1 : 0;
		size_t len = cString(ea);
		if (len != 0) {
			msi.kind = KIND_DATA;
			msi.name = hexName("str_", ea);
			msi.size = len;
			msi.typeChain.clear();
			msi.typeChain.push_back(TypeInfo{ "", len, "array", false, false, false, len });
			msi.typeChain.push_back(TypeInfo{ "char", 1, "int", false, false, true });
			msi.typeChain.front().isReadOnly = true;
		}
	}

	void getExternInfo(AddrInfo addr, std::string& callName, std::string& modName, FuncProtoInfo& func) override
	{
		makeUnknownFunctionPrototype(func);
		if (addr.space != "ram") {
			addReturnAddress(func);
			return;
		}
		auto imp = s->img.imports.find(addr.offset - s->bias);
		if (imp == s->img.imports.end()) {
			callName = hexName("sub_", addr.offset);
			addReturnAddress(func);
			return;
		}
		callName = displayName(imp->second.first);
		modName = imp->second.second;
		// the prototype of the same import in the open database
		const std::string& impName = imp->second.first;
		onMain([&]() {
			ea_t ea = get_name_ea(BADADDR, impName.c_str());
			if (ea == BADADDR)
				ea = get_name_ea(BADADDR, ("__imp_" + impName).c_str());
			tinfo_t ti;
			bool found = ea != BADADDR && get_tinfo(&ti, ea);
			// an import that only the other version has: the type libraries
			// of the open database (PSCreateMemoryPropertyStore in mssdk64)
			if (!found)
				found = ti.get_named_type(nullptr, impName.c_str());
			if (found) {
				if (ti.is_ptr())
					ti = ti.get_pointed_object();
				// a new prototype: getFuncTypeInfo appends the return type to
				// the "void" of the unknown one ([void > HRESULT] is a void)
				if (ti.is_func() && di->idacb != nullptr) {
					func = FuncProtoInfo{};
					di->idacb->getFuncTypeInfo(ti, false, func);
				}
			}
			addReturnAddress(func);
		});
		if (isKnownNoReturnFunctionName(callName))
			func.isNoReturn = true;
		traceProto("import " + callName, func);
	}

	void getMetaType(std::string typeName, std::vector<TypeInfo>& typeChain) override
	{
		// the types of the prototypes come from the open database
		if (di->idacb != nullptr)
			onMain([&]() { di->idacb->getMetaType(typeName, typeChain); });
		else
			typeChain.push_back(TypeInfo{ "void", 0, "void" });
	}

	std::string getSymbol(AddrInfo addr) override
	{
		if (addr.space != "ram")
			return "";
		std::string name;
		if (functionName(addr.offset, &name))
			return name;
		return hexName("loc_", addr.offset);
	}

	std::vector<uchar> getStringData(AddrInfo addr) override
	{
		std::vector<uchar> res;
		if (addr.space != "ram")
			return res;
		uint8_t buf[4096];
		int n = s->img.read(addr.offset - s->bias, buf, sizeof(buf));
		// UTF-16 when the second byte is 0
		bool wide = n >= 4 && buf[0] != 0 && buf[1] == 0;
		for (int i = 0; wide ? i + 1 < n : i < n; i += wide ? 2 : 1) {
			if (buf[i] == 0 && (!wide || buf[i + 1] == 0))
				break;
			res.push_back(buf[i]);
			if (wide)
				res.push_back(buf[i + 1]);
		}
		return res;
	}
};

FileSession::~FileSession()
{
	if (cb)
		cb->stop(dec != nullptr);
	dec.reset();
	cb.reset();
}

void fileSessionEnd()
{
	g_file.reset();
}

static std::string hexStr(uint64_t v)
{
	char buf[32];
	qsnprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
	return buf;
}

// the binary is for the processor of the open database
static bool sameProcessor(const FileImage& img, std::string* err)
{
	bool is64 = inf_is_64bit();
	if (img.is64 != is64 || img.bigEndian != inf_is_be()) {
		*err = img.path + " is a " + std::string(img.is64 ? "64" : "32") + "-bit " + (img.bigEndian ? "big" : "little")
			+ "-endian " + img.format + ", the open database is " + (is64 ? "64" : "32") + "-bit "
			+ (inf_is_be() ? "big" : "little") + "-endian: it is not the other version of this binary.";
		return false;
	}
	std::string proc = inf_procname;
	std::transform(proc.begin(), proc.end(), proc.begin(), [](unsigned char c) { return (char)tolower(c); });
	std::string family;
	unsigned m = img.machine;
	if (img.format == "PE")
		family = m == 0x14c || m == 0x8664 ? "metapc" : m == 0x1c0 || m == 0x1c2 || m == 0x1c4 || m == 0xaa64 ? "arm" : "";
	else
		family = m == 3 || m == 62 ? "metapc" : m == 40 || m == 183 ? "arm" : m == 8 ? "mips" : m == 20 || m == 21 ? "ppc" : "";
	if (!family.empty() && proc.compare(0, family.size(), family) != 0) {
		*err = img.path + " is not for the processor of the open database (" + proc + ").";
		return false;
	}
	return true;
}

bool fileDecompile(RdGlobalInfo* di, const FileDecompRequest& req, std::string* code, std::string* proto,
	std::string* name, std::vector<std::string>* warnings, std::string* err)
{
	IdaCallback* idacb = di->idacb;
	if (idacb == nullptr || idacb->sleighfilename.empty()) {
		*err = "the decompiler of the open database is not set up.";
		return false;
	}
	// a new binary, or a new version of the file
	if (g_file && (g_file->img.path != req.path || g_file->img.mtime != fileMtime(req.path)))
		g_file.reset();
	if (!g_file) {
		std::unique_ptr<FileSession> fs(new FileSession());
		if (!fs->img.load(req.path, err) || !sameProcessor(fs->img, err))
			return false;
		g_file = std::move(fs);
	}
	FileSession* s = g_file.get();

	// where the other database has the binary: at its image base, or as in
	// the file
	int64_t bias = req.imageBase != 0 ? (int64_t)(req.imageBase - s->img.base) : 0;
	auto inCode = [s](uint64_t va) {
		const FileRegion* r = s->img.find(va);
		return r != nullptr && r->exec;
	};
	if (!inCode(req.address - bias)) {
		if (bias != 0 && inCode(req.address))
			bias = 0;
		else {
			*err = hexStr(req.address) + " is not in the code of " + req.path + " (image base " + hexStr(req.imageBase)
				+ "): is it the binary of the other database?";
			return false;
		}
	}
	if (bias != s->bias && s->dec) {
		// the decompiler has the other addresses: start again
		g_file.reset();
		return fileDecompile(di, req, code, proto, name, warnings, err);
	}
	s->bias = bias;
	s->current = req.address;
	for (const auto& f : req.functions) {
		auto old = s->funcs.find(f.first);
		if (old == s->funcs.end() || old->second.name != f.second.name || old->second.prototype != f.second.prototype) {
			s->funcs[f.first] = f.second;
			s->protoCache.erase(f.first);
		}
	}

	if (!s->cb)
		s->cb.reset(new FileCallback(di, s));
	FileCallback* cb = s->cb.get();
	cb->canonical = req.canonicalNames;
	traceOpen();
	trace("file " + req.path + " address " + hexStr(req.address) + " image base " + hexStr(req.imageBase)
		+ " file base " + hexStr(s->img.base) + " bias " + std::to_string(s->bias));
	for (const FileRegion& r : s->img.regions)
		trace("region " + hexStr(r.start) + " size " + hexStr(r.size) + " file " + hexStr(r.fileOff) + "/" + hexStr(r.fileSize)
			+ (r.exec ? " x" : "") + (r.write ? " w" : ""));
	if (!cb->functionName(req.address, name))
		*name = hexName("sub_", req.address);
	try {
		if (!s->dec) {
			s->dec.reset(new DecompInterface());
			std::vector<CoreType> cts(&defaultCoreTypes[0], &defaultCoreTypes[numDefCoreTypes]);
			s->dec->setup(cb, idacb->sleighfilename, idacb->pspec, idacb->cspec, cts, idacb->getOpts(),
				(int)di->timeout, (int)di->maxPayload);
		}
		if (cb->pid == 0)
			s->dec->registerProgram();
		std::string display, funcColorProto;
		FuncProtoInfo symInf;
		*code = s->dec->doDecompile(defaultDecMode, AddrInfo{ "ram", req.address }, display, *proto, funcColorProto,
			symInf);
	} catch (DecompError& e) {
		trace("DecompError: " + e.explain);
		cb->stop(false);
		*err = "Ghidra's decompiler failed on " + req.path + ": " + e.explain;
		return false;
	}
	if (proto->empty()) {
		std::string e = code->size() > 3 ? code->substr(3) : "no result.";
		while (!e.empty() && (e.back() == '\n' || e.back() == '\r'))
			e.pop_back();
		*err = e;
		return false;
	}
	if (s->img.symbols.empty() && s->funcs.size() <= 1)
		warnings->push_back(req.path + " has no symbols: the names of the other version are the default ones.");
	return true;
}

} // namespace idaplugin
