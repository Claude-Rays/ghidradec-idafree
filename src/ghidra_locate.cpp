/**
 * @file ghidra_locate.cpp
 * @brief Finding the Ghidra installation (see ghidra_locate.h).
 */

#include "ghidra_locate.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace idaplugin {

namespace {

std::wstring wide(const std::string& s)
{
	if (s.empty())
		return std::wstring();
	int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
	std::wstring w(n, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
	return w;
}

std::string narrow(const std::wstring& w)
{
	if (w.empty())
		return std::string();
	int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
	std::string s(n, '\0');
	WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
	return s;
}

bool isSlash(char c)
{
	return c == '\\' || c == '/';
}

std::string join(const std::string& dir, const std::string& name)
{
	if (dir.empty() || isSlash(dir.back()))
		return dir + name;
	return dir + "\\" + name;
}

// without the trailing slashes (but "C:\" stays)
std::string trimSlashes(std::string dir)
{
	while (dir.size() > 3 && isSlash(dir.back()))
		dir.pop_back();
	return dir;
}

std::string parentOf(const std::string& dir)
{
	size_t p = dir.find_last_of("\\/");
	if (p == std::string::npos || p < 2)
		return std::string();
	return dir.substr(0, p == 2 ? 3 : p);
}

bool isFile(const std::string& path)
{
	DWORD a = GetFileAttributesW(wide(path).c_str());
	return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// the subfolders of 'dir' whose name matches 'pattern'
std::vector<std::string> subfolders(const std::string& dir, const char* pattern)
{
	std::vector<std::string> out;
	if (dir.empty())
		return out;
	WIN32_FIND_DATAW fd;
	HANDLE h = FindFirstFileExW(wide(join(dir, pattern)).c_str(), FindExInfoBasic, &fd, FindExSearchLimitToDirectories,
		nullptr, 0);
	if (h == INVALID_HANDLE_VALUE)
		return out;
	do {
		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
			|| wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
			continue;
		out.push_back(join(dir, narrow(fd.cFileName)));
	} while (FindNextFileW(h, &fd));
	FindClose(h);
	return out;
}

std::string env(const wchar_t* name)
{
	wchar_t buf[2048];
	DWORD n = GetEnvironmentVariableW(name, buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
	if (n == 0 || n >= sizeof(buf) / sizeof(buf[0]))
		return std::string();
	return narrow(buf);
}

// -1, 0, 1 comparing "12.1.4" with "11.4.2" part by part (numbers first)
int compareVersions(const std::string& a, const std::string& b)
{
	size_t i = 0, j = 0;
	while (i < a.size() || j < b.size()) {
		long x = i < a.size() ? strtol(a.c_str() + i, nullptr, 10) : 0;
		long y = j < b.size() ? strtol(b.c_str() + j, nullptr, 10) : 0;
		if (x != y)
			return x < y ? -1 : 1;
		i = a.find('.', i);
		j = b.find('.', j);
		i = i == std::string::npos ? a.size() : i + 1;
		j = j == std::string::npos ? b.size() : j + 1;
	}
	return 0;
}

std::string key(std::string path)
{
	path = trimSlashes(path);
	for (char& c : path)
		c = c == '/' ? '\\' : (char)tolower((unsigned char)c);
	return path;
}

void addUnique(std::vector<std::string>* list, const std::string& dir)
{
	if (dir.empty())
		return;
	for (const std::string& d : *list)
		if (key(d) == key(dir))
			return;
	list->push_back(dir);
}

// the best of several installations: version 'prefer', else the newest
void sortBest(std::vector<std::string>* dirs, const std::string& prefer)
{
	std::vector<std::pair<std::string, std::string>> v;
	for (const std::string& d : *dirs)
		v.push_back({ ghidraFolderVersion(d), d });
	std::stable_sort(v.begin(), v.end(), [&](const auto& x, const auto& y) {
		bool px = !prefer.empty() && x.first == prefer;
		bool py = !prefer.empty() && y.first == prefer;
		if (px != py)
			return px;
		return compareVersions(x.first, y.first) > 0;
	});
	dirs->clear();
	for (const auto& p : v)
		dirs->push_back(p.second);
}

} // anonymous namespace

bool isGhidraFolder(const std::string& dir)
{
	if (dir.empty())
		return false;
	return isFile(join(dir, "Ghidra\\Features\\Decompiler\\os\\win_x86_64\\decompile.exe"))
		|| isFile(join(dir, "Ghidra\\Features\\Decompiler\\os\\win64\\decompile.exe"));
}

std::string normalizeGhidraFolder(const std::string& dir)
{
	std::string d = trimSlashes(dir);
	if (d.empty())
		return std::string();
	if (isGhidraFolder(d))
		return d;
	std::string parent = parentOf(d);
	if (isGhidraFolder(parent))
		return parent;
	std::vector<std::string> found;
	for (const std::string& sub : subfolders(d, "ghidra*"))
		if (isGhidraFolder(sub))
			found.push_back(sub);
	sortBest(&found, std::string());
	return found.empty() ? std::string() : found.front();
}

std::string ghidraFolderVersion(const std::string& dir)
{
	FILE* fp = nullptr;
	if (_wfopen_s(&fp, wide(join(dir, "Ghidra\\application.properties")).c_str(), L"rb") != 0 || fp == nullptr)
		return std::string();
	std::string version;
	char line[1024];
	static const char KEY[] = "application.version=";
	while (fgets(line, sizeof(line), fp) != nullptr) {
		if (strncmp(line, KEY, sizeof(KEY) - 1) == 0) {
			version = line + sizeof(KEY) - 1;
			while (!version.empty() && (version.back() == '\n' || version.back() == '\r' || version.back() == ' '))
				version.pop_back();
			break;
		}
	}
	fclose(fp);
	return version;
}

std::vector<std::string> findGhidraFolders(const std::string& builtIn, const std::string& preferVersion)
{
	std::vector<std::string> out;
	addUnique(&out, normalizeGhidraFolder(env(L"GHIDRADEC_GHIDRA_DIR")));
	addUnique(&out, normalizeGhidraFolder(env(L"GHIDRA_INSTALL_DIR")));
	addUnique(&out, normalizeGhidraFolder(builtIn));

	// where a Ghidra zip is usually unpacked (or installed by scoop/chocolatey)
	std::string drive = env(L"SystemDrive");
	if (drive.empty())
		drive = "C:";
	std::string user = env(L"USERPROFILE");
	std::string publicDir = env(L"PUBLIC");
	std::string programData = env(L"ProgramData");
	std::string localAppData = env(L"LOCALAPPDATA");
	std::vector<std::string> roots = {
		drive + "\\", drive + "\\Tools", drive + "\\Program Files", env(L"ProgramFiles"),
		publicDir, publicDir.empty() ? std::string() : publicDir + "\\Tools",
		user, user.empty() ? std::string() : user + "\\Tools",
		user.empty() ? std::string() : user + "\\Downloads",
		user.empty() ? std::string() : user + "\\Desktop",
		user.empty() ? std::string() : user + "\\Documents",
		localAppData.empty() ? std::string() : localAppData + "\\Programs",
		programData.empty() ? std::string() : programData + "\\chocolatey\\lib\\ghidra\\tools",
	};
	std::vector<std::string> found;
	if (!user.empty())
		addUnique(&found, normalizeGhidraFolder(user + "\\scoop\\apps\\ghidra\\current"));
	for (const std::string& root : roots)
		for (const std::string& sub : subfolders(root, "ghidra*"))
			addUnique(&found, normalizeGhidraFolder(sub));
	sortBest(&found, preferVersion);
	for (const std::string& d : found)
		addUnique(&out, d);
	return out;
}

} // namespace idaplugin
