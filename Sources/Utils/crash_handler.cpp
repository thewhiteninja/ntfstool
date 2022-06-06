
#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "dbghelp")

#pragma pack( push, before_imagehlp, 8 )
#include <imagehlp.h>
#pragma pack( pop, before_imagehlp )

#include <stdexcept>
#include <iterator>
#include <vector>
#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <sstream>
#include <filesystem>

#include "Utils\utils.h"
#include <Utils\table.h>

class Crash
{
private:
	PEXCEPTION_POINTERS _ex;

public:
	explicit Crash(PEXCEPTION_POINTERS pEx)
	{
		_ex = pEx;
	}

	bool dump(std::wstring filename = L"")
	{
		std::wstring dump_filename = filename;
		if (dump_filename.empty())
		{
			wchar_t szExeFileName[MAX_PATH];
			GetModuleFileNameW(NULL, szExeFileName, MAX_PATH);
			std::filesystem::path p(szExeFileName);
			dump_filename = p.replace_extension(".dmp");
		}

		HANDLE hFile = CreateFileW(dump_filename.c_str(), GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			MINIDUMP_EXCEPTION_INFORMATION mdei;

			mdei.ThreadId = GetCurrentThreadId();
			mdei.ExceptionPointers = _ex;
			mdei.ClientPointers = FALSE;

			if (MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, (MINIDUMP_TYPE)(MiniDumpNormal), &mdei, nullptr, nullptr))
			{
				CloseHandle(hFile);
				return true;
			}
			CloseHandle(hFile);
		}
		return false;
	}
};

LONG WINAPI Filter(PEXCEPTION_POINTERS ep)
{
	std::shared_ptr<Crash> ex = std::make_shared<Crash>(ep);
	std::wcout << std::endl << "[!] Sorry, the application has crashed!" << std::endl;

	ex->dump();

	return EXCEPTION_EXECUTE_HANDLER;
}

void install_crash_handler()
{
	SetUnhandledExceptionFilter(&Filter);
}

void uninstall_crash_handler()
{
	SetUnhandledExceptionFilter(nullptr);
}