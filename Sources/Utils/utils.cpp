#include "Utils.h"

#include <map>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <codecvt>
#include <bitset>
#include <vector>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <distorm.h>

#include <Mstcpip.h>
#include <Taskschd.h>
#include <comdef.h>
#include <tchar.h>
#include <string.h>
#include <psapi.h>
#include <strsafe.h>
#include <Userenv.h>
#include <Shlobj.h>
#include <Softpub.h>
#include <mscat.h>
#include <Rpc.h>

#include <openssl/bn.h>

#include <filesystem>
#include <regex>

#include "Buffer.h"

#pragma comment(lib, "ntdll")
#pragma comment(lib, "wintrust")
#pragma comment(lib, "advapi32")
#pragma comment(lib, "rpcrt4")
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "shell32")


namespace utils
{
	namespace dirs
	{
		std::string temp()
		{
			TCHAR  infoBuf[MAX_PATH + 1];
			DWORD  bufCharCount = MAX_PATH + 1;

			GetTempPath(bufCharCount, infoBuf);
			return std::string(infoBuf);
		}
	}

	namespace convert
	{
		std::string to_base64(const char* in, size_t in_len)
		{
			std::string ret;
			int i = 0;
			unsigned char char_array_3[3];
			unsigned char char_array_4[4];
			const std::string base64_chars =
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz"
				"0123456789+/";

			while (in_len--)
			{
				char_array_3[i++] = *(in++);
				if (i == 3)
				{
					char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
					char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
					char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
					char_array_4[3] = char_array_3[2] & 0x3f;

					for (i = 0; (i < 4); i++)
						ret += base64_chars[char_array_4[i]];
					i = 0;
				}
			}

			if (i)
			{
				for (int j = i; j < 3; j++)
					char_array_3[j] = '\0';

				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for (int j = 0; (j < i + 1); j++)
					ret += base64_chars[char_array_4[j]];

				while ((i++ < 3))
					ret += '=';
			}

			return ret;
		}

		std::string to_base64(std::string s)
		{
			return to_base64(s.c_str(), s.length());
		}

		std::shared_ptr<Buffer<PBYTE>> from_hex(std::string s)
		{
			BIGNUM* input = BN_new();
			int input_length = BN_hex2bn(&input, s.c_str());
			std::shared_ptr<Buffer<PBYTE>> ret = std::make_shared<Buffer<PBYTE>>((input_length + 1) / 2);
			BN_bn2bin(input, ret->data());
			return ret;
		}

		std::string to_hex(PVOID buffer, unsigned long size)
		{
			std::ostringstream ret;
			PBYTE buf = reinterpret_cast<PBYTE>(buffer);
			if (buffer != nullptr)
			{
				for (unsigned int i = 0; i < size; i++)
				{
					ret << "0123456789ABCDEF"[buf[i] >> 4] << "0123456789ABCDEF"[buf[i] & 0x0F];
				}
			}
			return ret.str();
		}
	}

	namespace strings
	{
		template<typename _Iterator1, typename _Iterator2>
		size_t _inc_utf8_string_iterator(_Iterator1& it, const _Iterator2& last) {
			if (it == last) return 0;
			unsigned char c;
			size_t res = 1;
			for (++it; last != it; ++it, ++res) {
				c = *it;
				if (!(c & 0x80) || ((c & 0xC0) == 0xC0)) break;
			}

			return res;
		}

		DWORD utf8_string_size(const std::string& str) {
			int q = 0;
			size_t i = 0, ix = 0;
			for (q = 0, i = 0, ix = str.length(); i < ix; i++, q++)
			{
				int c = (unsigned char)str[i];
				if (c >= 0 && c <= 127) i += 0; //-V560
				else if ((c & 0xE0) == 0xC0) i += 1;
				else if ((c & 0xF0) == 0xE0) i += 2;
				else if ((c & 0xF8) == 0xF0) i += 3;
				else return 0;
			}
			return q;
		}

		std::string lower(std::string& s)
		{
			transform(s.begin(), s.end(), s.begin(), ::tolower);
			return s;
		}

		std::string upper(std::string& s)
		{
			transform(s.begin(), s.end(), s.begin(), ::toupper);
			return s;
		}

		void ltrim(std::string& s)
		{
			s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
				return !std::isspace(ch & 0xff) && ((ch & 0xff) != 0);
				}));
		}

		void rtrim(std::string& s)
		{
			s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned int ch) {
				return !std::isspace(ch & 0xff) && ((ch & 0xff) != 0);
				}).base(), s.end());
		}

		void trim(std::string& s)
		{
			ltrim(s);
			rtrim(s);
		}

		std::string reverse(std::string input)
		{
			std::reverse(input.begin(), input.end());
			return input;
		}

		void replace(std::string& str, const std::string& from, const std::string& to)
		{
			if (from.empty())
				return;
			size_t start_pos = 0;
			while ((start_pos = str.find(from, start_pos)) != std::string::npos)
			{
				str.replace(start_pos, from.length(), to);
				start_pos += to.length();
			}
		}

		std::vector<std::string> split(const std::string& text, TCHAR delimiter)
		{
			std::vector<std::string> result;

			std::string::size_type start = 0;
			std::string::size_type end = text.find(delimiter, start);

			while (end != std::string::npos)
			{
				std::string token = text.substr(start, end - start);

				result.push_back(token);

				start = end + 1;
				end = text.find(delimiter, start);
			}

			result.push_back(text.substr(start));

			return result;
		}

		std::wstring from_string(std::string s)
		{
			std::wstring ws;
			ws.assign(s.begin(), s.end());
			return ws;
		}

		std::u16string str_to_utf16(const std::string& s, DWORD encoding)
		{
			std::string utf8 = str_to_utf8(s, encoding);

			std::wstring_convert<std::codecvt_utf8_utf16<char16_t, 0x10ffff,
				std::codecvt_mode::little_endian>, char16_t> cnv;
			return cnv.from_bytes(utf8);
		}

		std::string str_to_utf8(std::string s, DWORD encoding)
		{
			Buffer<PWCHAR> bufw;
			int need_size = MultiByteToWideChar(encoding, 0, s.c_str(), -1, NULL, 0);
			bufw.resize((DWORD64)need_size * sizeof(WCHAR));
			MultiByteToWideChar(encoding, 0, s.c_str(), -1, bufw.data(), need_size);

			Buffer<PCHAR> bufu;
			int utf8len = WideCharToMultiByte(CP_UTF8, 0, bufw.data(), -1, NULL, 0, NULL, NULL);
			bufu.resize(utf8len);
			WideCharToMultiByte(CP_UTF8, 0, bufw.data(), -1, bufu.data(), utf8len, NULL, NULL);

			return bufu.data();
		}

		std::string to_utf8(std::wstring ws, DWORD encoding)
		{
			if (ws.empty()) return "";

			int utf16len = 0;
			if (!FAILED(SizeTToInt(ws.length(), &utf16len)))
			{
				int utf8len = WideCharToMultiByte(encoding, 0, ws.c_str(), utf16len, NULL, 0, NULL, NULL);

				std::string ret(utf8len, 0);
				WideCharToMultiByte(encoding, 0, ws.c_str(), utf16len, &ret[0], utf8len, 0, 0);
				return ret;
			}

			return "";
		}
	}

	namespace format
	{
		std::string size(DWORD64 size)
		{
			double s = static_cast<double>(size);
			std::stringstream stream;
			stream << std::fixed << std::setprecision(2);
			if (s < 1024)
			{
				stream << s << TEXT(" byte") << (s < 2 ? TEXT("") : TEXT("s"));
				return stream.str();
			}
			s /= 1024;
			if (s < 1024)
			{
				stream << s << TEXT(" KiB") << (s < 2 ? TEXT("") : TEXT("s"));
				return stream.str();
			}
			s /= 1024;
			if (s < 1024)
			{
				stream << s << TEXT(" MiB") << (s < 2 ? TEXT("") : TEXT("s"));
				return stream.str();
			}
			s /= 1024;
			if (s < 1024)
			{
				stream << s << TEXT(" GiB") << (s < 2 ? TEXT("") : TEXT("s"));
				return stream.str();
			}
			s /= 1024;
			if (s < 1024)
			{
				stream << s << TEXT(" TiB") << (s < 2 ? TEXT("") : TEXT("s"));
				return stream.str();
			}
			s /= 1024;
			stream << s << TEXT(" PiB") << (s < 2 ? TEXT("") : TEXT("s"));
			return stream.str();
		}

		std::string hex(BYTE value, bool suffix, bool swap)
		{
			std::ostringstream os;
			os << std::hex << std::setw(2) << std::setfill('0') << (ULONG32)value << std::dec;
			if (suffix)
			{
				os << "h";
			}
			return os.str();
		}

		std::string hex(USHORT value, bool suffix, bool swap)
		{
			if (swap)
			{
				value = _byteswap_ushort(value);
			}
			std::ostringstream os;
			os << std::hex << std::setw(4) << std::setfill('0') << value << std::dec;
			if (suffix)
			{
				os << "h";
			}
			return os.str();
		}

		std::string hex(ULONG32 value, bool suffix, bool swap)
		{
			if (swap)
			{
				value = _byteswap_ulong(value);
			}
			std::ostringstream os;
			os << std::hex << std::setw(8) << std::setfill('0') << value << std::dec;
			if (suffix)
			{
				os << "h";
			}
			return os.str();
		}

		std::string hex(DWORD value, bool suffix, bool swap)
		{
			return  hex((ULONG32)value, suffix, swap);
		}

		std::string hex6(ULONG64 value, bool suffix, bool swap)
		{
			if (swap)
			{
				value = _byteswap_uint64(value);
			}
			std::ostringstream os;
			os << std::hex << std::setw(12) << std::setfill('0') << value << std::dec;
			if (suffix)
			{
				os << "h";
			}
			return os.str();
		}

		std::string hex(ULONG64 value, bool suffix, bool swap)
		{
			if (swap)
			{
				value = _byteswap_uint64(value);
			}
			std::ostringstream os;
			os << std::hex << std::setw(16) << std::setfill('0') << value << std::dec;
			if (suffix)
			{
				os << "h";
			}
			return os.str();
		}

		std::string hex(LONG64 value, bool suffix, bool swap)
		{
			return hex((ULONG64)value, suffix, swap);
		}

		std::string hex(std::u16string value, bool suffix, bool swap)
		{
			return hex(((PBYTE)value.c_str()), value.size() * sizeof(char16_t), suffix, swap);
		}

		std::string hex(std::string value, bool suffix, bool swap)
		{
			return hex(((PBYTE)value.c_str()), value.size(), suffix, swap);
		}

		std::string hex(PBYTE value, size_t byte_size, bool suffix, bool swap)
		{
			std::ostringstream os;
			if (swap)
			{
				for (size_t i = 0; i < byte_size; i++)
				{
					os << std::setfill('0') << std::setw(2) << std::hex << (ULONG)value[byte_size - i - 1];
				}
			}
			else
			{
				for (size_t i = 0; i < byte_size; i++)
				{
					os << std::setfill('0') << std::setw(2) << std::hex << (ULONG)value[i];
				}
			}

			os << std::dec;
			if (suffix)
			{
				os << "h";
			}
			return os.str();
		}
	}

	namespace times {


		std::string display_systemtime(SYSTEMTIME st)
		{
			TCHAR buf[64] = { 0 };
			_stprintf_s(buf, TEXT("%04u-%02u-%02u %02u:%02u:%02u"), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
			return std::string(buf);
		}

		BOOL filetime_to_systemtime(FILETIME ft, PSYSTEMTIME pST)
		{
			return FileTimeToSystemTime(&ft, pST);
		}

		BOOL ull_to_systemtime(ULONGLONG ull, PSYSTEMTIME pST)
		{
			FILETIME ft;
			ft.dwLowDateTime = (DWORD)(ull & 0xFFFFFFFF);
			ft.dwHighDateTime = (DWORD)(ull >> 32);
			return filetime_to_systemtime(ft, pST);
		}

		BOOL filetime_to_local_systemtime(FILETIME ft, PSYSTEMTIME pST)
		{
			FILETIME local;
			if (FileTimeToLocalFileTime(&ft, &local))
			{
				if (FileTimeToSystemTime(&local, pST))
				{
					return TRUE;
				}
			}
			return FALSE;
		}

		BOOL ull_to_local_systemtime(ULONGLONG ull, PSYSTEMTIME pST)
		{
			FILETIME ft;
			ft.dwLowDateTime = (DWORD)(ull & 0xFFFFFFFF);
			ft.dwHighDateTime = (DWORD)(ull >> 32);
			return filetime_to_local_systemtime(ft, pST);
		}
	}

	namespace processes {

		BOOL elevated(HANDLE p)
		{
			DWORD dwSize = 0;
			HANDLE hToken = NULL;
			TOKEN_ELEVATION tokenInformation;

			BOOL elevated = FALSE;

			if (OpenProcessToken(p, TOKEN_QUERY, &hToken))
			{
				if (GetTokenInformation(hToken, TokenElevation, &tokenInformation, sizeof(TOKEN_ELEVATION), &dwSize))
					elevated = tokenInformation.TokenIsElevated;
				CloseHandle(hToken);
			}

			return elevated;
		}
	}

	namespace files {

		std::string ensure_file_ext(const std::string& str, std::string ext)
		{
			std::filesystem::path p(str);
			return p.replace_extension(ext).string();
		}

		std::string basename(const std::string& str)
		{
			size_t found = str.find_last_of("/\\");
			if (found == std::string::npos)
			{
				return str;
			}
			else
			{
				return str.substr(found + 1);
			}
		}

		std::pair<std::string, std::string> split_file_and_stream(std::string& str)
		{
			std::filesystem::path p(str);
			std::string fname = str;

			size_t ads_sep = p.filename().string().find(':');
			std::string stream_name = "";
			if (ads_sep != std::string::npos)
			{
				stream_name = p.filename().string().substr(ads_sep + 1);
				size_t last_sep = fname.find_last_of(':');
				fname = fname.substr(0, last_sep);
			}

			return std::make_pair(fname, stream_name);
		}
	}

	namespace id
	{
		std::string guid_to_string(GUID guid)
		{
			char guid_cstr[64];
			snprintf(guid_cstr, sizeof(guid_cstr),
				"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
				guid.Data1, guid.Data2, guid.Data3,
				guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
				guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

			return std::string(guid_cstr);
		}
		std::string sid_to_string(PSID pid)
		{
			std::string ret;
			LPSTR psSid = NULL;
			if (ConvertSidToStringSidA(pid, &psSid))
			{
				ret = std::string(psSid);
				LocalFree(psSid);
				return ret;
			}
			else
			{
				return "Converting SID failed";
			}
		}

		std::string username_from_sid(std::string sid)
		{
			char oname[512] = { 0 };
			char doname[512] = { 0 };
			DWORD namelen = 512;
			DWORD domainnamelen = 512;

			SID_NAME_USE peUse;

			PSID psid = nullptr;
			std::string username = "";
			if (ConvertStringSidToSidA(sid.c_str(), &psid))
			{
				if (LookupAccountSidA(NULL, psid, oname, &namelen, doname, &domainnamelen, &peUse))
				{
					if (strnlen_s(oname, 512) > 0 && strnlen_s(doname, 512) > 0)
					{
						username = std::string(doname, domainnamelen) + "/" + std::string(oname, namelen);
					}
				}
				FreeSid(psid);
			}
			return username;
		}
	}

	namespace ui
	{
		std::string line(unsigned int length, char type)
		{
			std::string s;
			for (unsigned int i = 0; i < length; i++) s += type;
			return s;
		}

		void title(std::string s, std::ostream& out)
		{
			std::cout << std::setfill('0');
			out << s << std::endl;
			out << line(utils::strings::utf8_string_size(s));
			out << std::endl;
			out << std::endl;
		}

		bool ask_question(std::string question)
		{
			std::string type = "n";

			do
			{
				std::cout << question << " [y/N] ? ";
				std::getline(std::cin, type);
				type = utils::strings::lower(type);
				if (type.empty())
				{
					type = "n";
				}
			} while (!std::cin.fail() && type != "y" && type != "n");

			return type == "y";
		}
	}

}

std::string utils::os::short_version()
{
	OSVERSIONINFOEX osvi;
	SYSTEM_INFO si;
	DWORD dwType = 0;

	std::string osname;

	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

#pragma warning(disable: 28159)
#pragma warning(disable: 4996)
	GetVersionEx((OSVERSIONINFO*)&osvi);

	GetNativeSystemInfo(&si);
	GetProductInfo(osvi.dwMajorVersion, osvi.dwMinorVersion, 0, 0, &dwType);

	if (VER_PLATFORM_WIN32_NT == osvi.dwPlatformId && osvi.dwMajorVersion > 4)
	{
		if (osvi.dwMajorVersion == 10) osname = "10";

		if (osvi.dwMajorVersion == 6)
		{
			if (osvi.dwMinorVersion == 0) osname = "Vista";
			if (osvi.dwMinorVersion == 1)  osname = "7";
			if (osvi.dwMinorVersion == 2) osname = "8";
		}

		if (osvi.dwMajorVersion == 5)
		{
			osname = "XP";
		}
	}
	else
	{
		osname = "Unsupported";
	}
	return osname;
}

std::vector<std::string> utils::disass::buffer(PVOID code, ULONG32 size, _DecodeType type, _OffsetType offset)
{
	std::vector<std::string> ret;

	_DecodeResult res;
	std::shared_ptr<Buffer<_DecodedInst*>> decodedInstructions = std::make_shared<Buffer<_DecodedInst*>>(1000 * sizeof(_DecodedInst));
	unsigned int decodedInstructionsCount = 0;

	res = distorm_decode(offset, (const unsigned char*)code, size, type, decodedInstructions->data(), 1000, &decodedInstructionsCount);
	if (res != DECRES_INPUTERR)
	{
		for (unsigned int i = 0; i < decodedInstructionsCount; i++)
		{
			std::ostringstream os;
			os << utils::format::hex((WORD)(decodedInstructions->data()[i].offset)) << " : ";
			os.width(14);
			os << std::left << decodedInstructions->data()[i].instructionHex.p << " : ";
			os << utils::strings::lower(std::string((char*)decodedInstructions->data()[i].mnemonic.p)) << " ";
			if (decodedInstructions->data()[i].operands.length != 0)
			{
				os << utils::strings::lower(std::string((char*)decodedInstructions->data()[i].operands.p));
			}
			ret.push_back(os.str());
		}
	}

	return ret;
}

void utils::crypto::xor_buffer(PVOID data, DWORD datalen, PVOID key, DWORD keylen)
{
	for (DWORD i = 0; i < datalen; i++)
	{
		PBYTE(data)[i] ^= PBYTE(key)[i % keylen];
	}
}

void utils::crypto::hash::sha256_file(std::string filename, BYTE output[SHA256_DIGEST_LENGTH])
{
	Buffer<PCHAR> buffer(4096 * 16);
	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx)
	{
		EVP_DigestInit(ctx, EVP_sha256());
		std::ifstream is(filename.c_str(), std::ifstream::binary);
		if (is.is_open() && buffer.is_valid())
		{
			while (!is.eof())
			{
				is.read(buffer.data(), buffer.size());
				EVP_DigestUpdate(ctx, buffer.data(), static_cast<size_t>(is.gcount()));
			}
			unsigned int rsize = 0;
			EVP_DigestFinal(ctx, output, &rsize);
			is.close();
		}
		EVP_MD_CTX_destroy(ctx);
	}
}

void utils::crypto::hash::sha256_buffer(PBYTE input, size_t input_len, BYTE output[SHA256_DIGEST_LENGTH])
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx)
	{
		EVP_DigestInit(ctx, EVP_sha256());
		EVP_DigestUpdate(ctx, input, input_len);
		unsigned int rsize = 0;
		EVP_DigestFinal(ctx, output, &rsize);
		EVP_MD_CTX_destroy(ctx);
	}
}

void utils::crypto::hash::sha1_buffer(PBYTE input, size_t input_len, BYTE output[SHA_DIGEST_LENGTH])
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx)
	{
		EVP_DigestInit(ctx, EVP_sha1());
		EVP_DigestUpdate(ctx, input, input_len);
		unsigned int rsize = 0;
		EVP_DigestFinal(ctx, output, &rsize);
		EVP_MD_CTX_destroy(ctx);
	}
}

void utils::crypto::hash::md4_buffer(PBYTE input, size_t input_len, BYTE output[MD4_DIGEST_LENGTH])
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx)
	{
		EVP_DigestInit(ctx, EVP_md4());
		EVP_DigestUpdate(ctx, input, input_len);
		unsigned int rsize = 0;
		EVP_DigestFinal(ctx, output, &rsize);
		EVP_MD_CTX_destroy(ctx);
	}
}

const EVP_MD* utils::crypto::cryptoapi::hash_to_evp(DWORD hash_alg)
{
	const EVP_MD* hash = nullptr;
	switch (hash_alg)
	{
	case CALG_MD4: return EVP_md4();
	case CALG_MD5: return EVP_md5();
	case CALG_SHA1: return EVP_sha1();
	case CALG_SHA_256: return EVP_sha256();
	case CALG_SHA_384: return EVP_sha384();
	case CALG_SHA_512: return EVP_sha512();
	default:
		return nullptr;
	}
}

const EVP_CIPHER* utils::crypto::cryptoapi::encryption_to_evp(DWORD enc_alg)
{
	const EVP_CIPHER* enc = nullptr;
	switch (enc_alg)
	{
	case CALG_3DES: return EVP_des_ede3_cbc();
	case CALG_AES_128: return EVP_aes_128_cbc();
	case CALG_AES_192: return EVP_aes_192_cbc();
	case CALG_AES_256: return EVP_aes_256_cbc();
	case CALG_DES: return EVP_des_cbc();
	case CALG_DESX: return EVP_desx_cbc();
	default:
		return nullptr;
	}
}

int utils::dll::ntdll::load_compression_functions(_RtlDecompressBuffer* RtlDecompressBuffer, _RtlDecompressBufferEx* RtlDecompressBufferEx, _RtlGetCompressionWorkSpaceSize* RtlGetCompressionWorkSpaceSize)
{
	auto ntdll = GetModuleHandle("ntdll.dll");
	if (ntdll != nullptr)
	{
		if (RtlDecompressBuffer)
		{
			*RtlDecompressBuffer = (_RtlDecompressBuffer)GetProcAddress(ntdll, "RtlDecompressBuffer");
			if (*RtlDecompressBuffer == nullptr)
			{
				return 4;
			}
		}

		if (RtlGetCompressionWorkSpaceSize)
		{
			*RtlGetCompressionWorkSpaceSize = (_RtlGetCompressionWorkSpaceSize)GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize");
			if (*RtlGetCompressionWorkSpaceSize == nullptr)
			{
				return 3;
			}
		}

		if (RtlDecompressBufferEx)
		{
			*RtlDecompressBufferEx = (_RtlDecompressBufferEx)GetProcAddress(ntdll, "RtlDecompressBufferEx");
			if (*RtlDecompressBufferEx == nullptr)
			{
				return 2;
			}
		}
	}
	else
	{
		return 1;
	}
	return 0;
}
