#pragma once

#include <Windows.h>

class ExportFlags
{
private:
	DWORD _flags = 0;
public:
	ExportFlags(PBYTE data, DWORD size)
	{
		if (data && size >= 4)
		{
			_flags = reinterpret_cast<DWORD*>(data)[0];
		}
	}

	DWORD flags() { return _flags; }
};