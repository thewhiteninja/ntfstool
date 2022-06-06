#pragma once


#include <Windows.h>

#include <memory>
#include <string>

class Reader {
protected:
	HANDLE _handle_disk = INVALID_HANDLE_VALUE;

	BYTE _boot_record[512] = { 0 };

	DWORD64 _current_position = 0;
	DWORD64 _image_volume_offset = 0;

public:
	explicit Reader(std::wstring volume_name, DWORD64 volume_offset = 0);

	~Reader();

	Reader(const Reader& reader2);

	Reader& operator= (const Reader& e);

	HANDLE handle() const { return _handle_disk; }

	bool seek(ULONG64 position);

	DWORD64 get_volume_offset() { return _image_volume_offset; }

	bool read(LPVOID lpBuffer, ULONG32 nNumberOfBytesToRead);
};