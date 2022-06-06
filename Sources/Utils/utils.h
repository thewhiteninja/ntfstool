#pragma once


#include <string>
#include <sstream>
#include <vector>
#include <chrono>
#include <set>
#include <functional>
#include <iostream>
#include <distorm.h>


#include <ws2tcpip.h>
#include <Windows.h>
#include <tchar.h>
#include <inttypes.h>
#include <sddl.h>

#include "buffer.h"
#include "Compression/ntdll_defs.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/sha.h>


#define POINTER_ADD(t, p, v)	(reinterpret_cast<t>(reinterpret_cast<uint64_t>(p) + v))

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

		template <class T>
		std::string join_vec(std::vector<T> items, const std::string separator)
		{
			std::ostringstream out;
			if (items.size() > 0) out << std::string(items[0]);
			for (unsigned int i = 1; i < items.size(); i++) {
				out << separator << std::string(items[i]);
			}
			return out.str();
		}

		template <class T>
		std::string join_set(std::set<T> items, const std::string separator)
		{
			std::ostringstream out;
			bool first = true;
			for (auto& item : items)
			{
				if (!first)
				{
					out << separator;
				}
				else
				{
					first = false;
				}
				out << std::string(item);
			}
			return out.str();
		}
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
		std::string ensure_file_ext(const std::string& str, std::string ext);

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

		std::string username_from_sid(std::string sid);
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

		namespace hash
		{
			void sha256_file(std::string filename, BYTE output[SHA256_DIGEST_LENGTH]);

			void sha256_buffer(PBYTE input, size_t input_len, BYTE output[SHA256_DIGEST_LENGTH]);

			void sha1_buffer(PBYTE input, size_t input_len, BYTE output[SHA_DIGEST_LENGTH]);

			void md4_buffer(PBYTE input, size_t input_len, BYTE output[MD4_DIGEST_LENGTH]);
		}

		namespace cryptoapi
		{
			const EVP_MD* hash_to_evp(DWORD hash_alg);

			const EVP_CIPHER* encryption_to_evp(DWORD enc_alg);
		}
	}

	namespace dll
	{
		namespace ntdll
		{
			int load_compression_functions(_RtlDecompressBuffer* RtlDecompressBuffer, _RtlDecompressBufferEx* RtlDecompressBufferEx, _RtlGetCompressionWorkSpaceSize* RtlGetCompressionWorkSpaceSize);
		}
	}

}