
#include "reader.h"

Reader::Reader(std::wstring& volume_name)
{
	std::wstring valid_name = volume_name;
	if (valid_name.back() == '\\') valid_name.pop_back();
	_handle_disk = CreateFileW(valid_name.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_handle_disk == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed");
	}
	else
	{
		DWORD read = 0;
		seek(0);
		if (!ReadFile(_handle_disk, &_boot_record, 0x200, &read, NULL))
		{
			printf("ReadFile on bootsector failed (%08x)", static_cast<unsigned int>(GetLastError()));
		}
	}
}

Reader::~Reader()
{
	if (_handle_disk != INVALID_HANDLE_VALUE)
	{
		CloseHandle(_handle_disk);
	}
}

bool Reader::seek(ULONG64 position)
{
	LARGE_INTEGER pos;
	pos.QuadPart = (LONGLONG)position;
	LARGE_INTEGER result;

	if (_handle_disk != INVALID_HANDLE_VALUE)
	{
		return SetFilePointerEx(_handle_disk, pos, &result, SEEK_SET) || pos.QuadPart != result.QuadPart;
	}

	return false;
}

bool Reader::read(LPVOID lpBuffer, ULONG32 nNumberOfBytesToRead)
{
	DWORD readBytes = 0;

	if (_handle_disk != INVALID_HANDLE_VALUE)
	{
		return ReadFile(_handle_disk, lpBuffer, nNumberOfBytesToRead, &readBytes, NULL);
	}

	return false;
}