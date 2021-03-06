#pragma once


#include <string>
#include <vector>
#include <chrono>
#include <set>
#include <functional>
#include <iostream>
#include <distorm.h>

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <tchar.h>
#include <inttypes.h>
#include <sddl.h>

#include "buffer.h"

#define POINTER_ADD(t, p, v)	((t)(((PBYTE)p) + (v)))

namespace utils
{

	namespace convert
	{
		std::shared_ptr<Buffer<PBYTE>> from_hex(std::string s);

		std::string to_hex(PVOID buffer, unsigned long size);
	}

	namespace strings
	{
		std::string upper(std::string& s);

		std::string lower(std::string& s);

		void ltrim(std::string& s);

		void rtrim(std::string& s);

		void trim(std::string& s);

		DWORD utf8_string_size(const std::string& str);

		std::wstring from_string(std::string s);

		std::u16string str_to_utf16(const std::string& s, DWORD encoding = CP_ACP);

		std::string str_to_utf8(std::string s, DWORD encoding = CP_ACP);

		std::string to_utf8(std::wstring s, DWORD encoding = CP_UTF8);

		std::string reverse(std::string input);

		void replace(std::string& str, const std::string& from, const std::string& to);

		std::vector<std::string> split(const std::string& text, TCHAR delimiter);

		std::string join(std::vector<std::string> items, std::string separator);
	}

	namespace format
	{
		std::string size(DWORD64 size);

		std::string hex(BYTE value, bool suffix = false, bool swap = false);

		std::string hex(USHORT value, bool suffix = false, bool swap = false);

		std::string hex(ULONG32 value, bool suffix = false, bool swap = false);

		std::string hex(DWORD value, bool suffix = false, bool swap = false);

		std::string hex6(ULONG64 value, bool suffix = false, bool swap = false);

		std::string hex(ULONG64 value, bool suffix = false, bool swap = false);

		std::string hex(LONG64 value, bool suffix = false, bool swap = false);

		std::string hex(std::u16string value, bool suffix = false, bool swap = false);

		std::string hex(std::string value, bool suffix = false, bool swap = false);

		std::string hex(PBYTE value, size_t byte_size, bool suffix = false, bool swap = false);
	}

	namespace processes {

		BOOL elevated(HANDLE p);
	}

	namespace files
	{
		std::string basename(const std::string& str);

		std::pair<std::string, std::string> split_file_and_stream(std::string& str);
	}

	namespace times
	{
		std::string display_systemtime(SYSTEMTIME st);

		BOOL filetime_to_systemtime(FILETIME ft, PSYSTEMTIME pST);

		BOOL ull_to_systemtime(ULONGLONG ull, PSYSTEMTIME pST);

		BOOL filetime_to_local_systemtime(FILETIME ft, PSYSTEMTIME pST);

		BOOL ull_to_local_systemtime(ULONGLONG ull, PSYSTEMTIME pST);
	}

	namespace dirs
	{
		std::string temp();
	}

	namespace id
	{
		std::string guid_to_string(GUID id);

		std::string sid_to_string(PSID id);
	}

	namespace os
	{
		std::string short_version();
	}

	namespace ui
	{
		std::string line(unsigned int length, char type = '-');

		void title(std::string s, std::ostream& out = std::cout);

		bool ask_question(std::string question);
	}

	namespace disass
	{
		std::vector<std::string> buffer(PVOID code, ULONG32 size, _DecodeType type, _OffsetType offset);
	}

	namespace crypto
	{
		void xor_buffer(PVOID data, DWORD datalen, PVOID key, DWORD keylen);
	}

}