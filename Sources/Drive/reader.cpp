#include "reader.h"

Reader::Reader(std::wstring volume_name, DWORD64 volume_offset)
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
		_image_volume_offset = volume_offset;

		LARGE_INTEGER result;
		LARGE_INTEGER pos;
		pos.QuadPart = volume_offset;
		SetFilePointerEx(_handle_disk, pos, &result, SEEK_SET);

		DWORD read = 0;
		seek(0);
		if (!ReadFile(_handle_disk, &_boot_record, 0x200, &read, NULL))
		{
			printf("ReadFile on bootsector failed (%08x)\n", static_cast<unsigned int>(GetLastError()));
		}
	}
}

Reader::Reader(const Reader& reader_copy)
{
	_handle_disk = INVALID_HANDLE_VALUE;

	DuplicateHandle(GetCurrentProcess(), reader_copy.handle(), GetCurrentProcess(), &_handle_disk, DUPLICATE_SAME_ACCESS, TRUE, DUPLICATE_SAME_ACCESS);

	memcpy(_boot_record, reader_copy._boot_record, 512);

	_current_position = reader_copy._current_position;
}

Reader& Reader::operator=(const Reader& e)
{
	_handle_disk = e._handle_disk;

	memcpy(_boot_record, e._boot_record, 512);

	_current_position = e._current_position;

	return *this;
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
	if (_current_position != position)
	{
		_current_position = position;

		if (_handle_disk != INVALID_HANDLE_VALUE)
		{
			LARGE_INTEGER pos;
			pos.QuadPart = (LONGLONG)position + _image_volume_offset;
			LARGE_INTEGER result;

			return SetFilePointerEx(_handle_disk, pos, &result, SEEK_SET) || pos.QuadPart != result.QuadPart;
		}
		else
		{
			return false;
		}
	}
	return true;
}

bool Reader::read(LPVOID lpBuffer, ULONG32 nNumberOfBytesToRead)
{
	bool ret = false;
	DWORD readBytes = 0;

	if (_handle_disk != INVALID_HANDLE_VALUE)
	{
		ret = ReadFile(_handle_disk, lpBuffer, nNumberOfBytesToRead, &readBytes, NULL);
		_current_position += readBytes;
		return ret;
	}

	return ret;
}