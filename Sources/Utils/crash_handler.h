#pragma once


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

#include "Utils/utils.h"

void install_crash_handler();

void uninstall_crash_handler();

class Crash
{
private:
	PEXCEPTION_POINTERS _ex;
	EXCEPTION_RECORD _exception;
	CONTEXT _context;

	HANDLE _hProcess = INVALID_HANDLE_VALUE;
	HANDLE _hThread = INVALID_HANDLE_VALUE;

public:
	explicit Crash(PEXCEPTION_POINTERS pEx);

	bool dump(std::wstring filename = L"");

	PEXCEPTION_RECORD exception() { return &_exception; }

	PCONTEXT context() { return &_context; }
};

LONG WINAPI Filter(PEXCEPTION_POINTERS ep);
