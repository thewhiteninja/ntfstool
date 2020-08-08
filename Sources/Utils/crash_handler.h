#pragma once

#include <WinSock2.h>
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

typedef struct {
	std::wstring image_name;
	std::wstring module_name;
	void* base_address;
	DWORD load_size;
} CRASH_MODULE_DATA;

static bool g_Dump = false;

typedef struct
{
	DWORD64 address;
	std::wstring function;
	std::wstring filename;
	DWORD line;
} CRASH_STACK_TRACE;


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
	std::vector<CRASH_MODULE_DATA> _modules;

	std::vector<CRASH_STACK_TRACE> _traces;

	STACKFRAME64 _build_stack_frame(CONTEXT c);

	void _load_modules_symbols();

	std::wstring _get_symbol_at(DWORD64 address);

	void _build_stack_trace();

public:
	Crash(PEXCEPTION_POINTERS pEx);

	bool dump(std::wstring filename = L"");

	std::wstring name();

	PEXCEPTION_RECORD exception() { return &_exception; }

	PCONTEXT context() { return &_context; }

	std::vector<CRASH_STACK_TRACE> traces() { return _traces; }
};

LONG WINAPI Filter(PEXCEPTION_POINTERS ep);
