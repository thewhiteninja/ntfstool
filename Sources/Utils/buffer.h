#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <Intsafe.h>

#include <memory>
#include <string>

#include <cppcoro/generator.hpp>

template< typename T>
class Buffer
{
private:
	T _mem = NULL;
	DWORD _size = 0;

public:
	explicit Buffer() : _mem(NULL), _size(0)
	{
	}

	template< typename V>
	V read_at(DWORD offset)
	{
		return *((V*)(((PBYTE)_mem) + offset));
	}

	explicit Buffer(std::string s)
	{
		_size = s.length();
		_mem = static_cast<T>(malloc(s.length() + 1));
		if (_mem != NULL)
		{
			memcpy_s(_mem, s.length(), s.c_str(), s.length());
		}
		else
		{
			_size = 0;
		}
	}

	explicit Buffer(DWORD64 size)
	{
		_mem = static_cast<T>(malloc(size & 0xffffffff));
		if (_mem != NULL)
		{
			ZeroMemory((void*)_mem, size & 0xffffffff);
			_size = size & 0xffffffff;
		}
		else
		{
			_size = 0;
		}
	}

	explicit Buffer(PBYTE data, DWORD size)
	{
		_mem = static_cast<T>(malloc(size));
		if (_mem != NULL)
		{
			_size = size;
			memcpy_s(_mem, size, data, size);
		}
		else
		{
			_size = 0;
		}
	}

	~Buffer()
	{
		if (_mem != NULL)
		{
			ZeroMemory((void*)_mem, _size);
			free((void*)_mem);

			_mem = NULL;
		}
	}

	DWORD size() const
	{
		return _size;
	}

	T data() const
	{
		return _mem;
	}

	PBYTE address() const
	{
		return (PBYTE)_mem;
	}

	bool is_valid() const
	{
		return _mem != NULL;
	}

	void shrink(DWORD size)
	{
		if (_mem != NULL)
		{
			_size = size;
		}
	}

	cppcoro::generator<std::pair<PBYTE, DWORD>> process_data(DWORD block_size)
	{
		for (DWORD64 offset = 0; offset < _size; offset += block_size)
		{
			co_yield std::pair<PBYTE, DWORD>(reinterpret_cast<PBYTE>(_mem) + offset, static_cast<DWORD>(min(_size - offset, block_size)));
		}
	}

	bool to_file(std::wstring filename)
	{
		HANDLE hFile = INVALID_HANDLE_VALUE;
		DWORD dwWritten = 0;
		BOOL ret = FALSE;

		if ((hFile = CreateFileW(filename.c_str(), (GENERIC_WRITE), FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL)) != INVALID_HANDLE_VALUE)
		{
			if (WriteFile(hFile, _mem, _size, &dwWritten, NULL))
			{
				if (dwWritten == _size) ret = TRUE;
			}
			CloseHandle(hFile);
		}

		return ret;
	}

	static std::shared_ptr<Buffer<T>> from_file(std::wstring filename)
	{
		HANDLE hFile = INVALID_HANDLE_VALUE;
		DWORD dwWritten = 0;
		std::shared_ptr<Buffer<T>> ret = NULL;

		if ((hFile = CreateFileW(filename.c_str(), (GENERIC_READ), FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE)
		{
			DWORD dwSizeOfFile = GetFileSize(hFile, NULL);
			if (dwSizeOfFile != INVALID_FILE_SIZE)
			{
				ret = std::make_shared<Buffer<T>>(dwSizeOfFile);
				if (ReadFile(hFile, reinterpret_cast<LPVOID>(ret->data()), ret->size(), &dwWritten, NULL))
				{
					if (dwWritten != ret->size()) ret = NULL;
				}
			}
			CloseHandle(hFile);
		}

		return ret;
	}

	static std::shared_ptr<Buffer<T>> from_hex(std::string hexstring)
	{
		return utils::convert::from_hex(hexstring);
	}

	std::shared_ptr<Buffer<PBYTE>> concat(PBYTE toAddr, size_t toSize)
	{
		std::shared_ptr<Buffer<PBYTE>> conc = std::make_shared<Buffer<PBYTE>>(_size + toSize);
		memcpy_s(conc->data(), conc->size(), _mem, _size);
		memcpy_s(conc->data() + _size, conc->size() - _size, toAddr, toSize);
		return conc;
	}

	void clear()
	{
		if (_mem != NULL)
		{
			ZeroMemory(_mem, _size);
		}
	}

	void resize(DWORD64 size)
	{
		T tmp;
		if (_mem != NULL)
		{
			tmp = static_cast<T>(realloc(_mem, size & 0xffffffff));
			if (tmp != NULL)
			{
				_mem = tmp;
				this->_size = size & 0xffffffff;
			}
			else
			{
				this->_size = 0;
			}
		}
		else
		{
			_mem = static_cast<T>(malloc(size & 0xffffffff));
			if (_mem != NULL)
			{
				ZeroMemory(_mem, size & 0xffffffff);
				this->_size = size & 0xffffffff;
			}
			else
			{
				_size = 0;
			}
		}
	}

	std::wstring to_hex() const
	{
		constexpr wchar_t hexmap[] = { L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9', L'a', L'b', L'c', L'd', L'e', L'f' };
		std::wstring s(_size * 2, L' ');
		for (DWORD i = 0; i < _size; ++i)
		{
			s[2 * i] = hexmap[((((PBYTE)_mem)[i]) & 0xF0) >> 4];
			s[2 * i + 1] = hexmap[((PBYTE)_mem)[i] & 0x0F];
		}
		return s;
	}

	void reverse_bytes()
	{
		BYTE* istart = _mem, * iend = istart + _size;
		std::reverse(istart, iend);
	}

	std::string to_base64() const
	{
		return utils::convert::to_base64((const char*)_mem, _size);
	}

	std::string to_string() const
	{
		return std::string(reinterpret_cast<char*>(_mem), _size);
	}

	std::string dump_to_string(std::string title = "", unsigned int block_size = 16, unsigned int limit = 0xffffffff)
	{
		std::ostringstream os;

		os << title << ":" << std::endl;
		for (unsigned int i = 0; i < _size; i += block_size)
		{
			os << utils::convert::to_hex(_mem + i, min(_size - i, block_size)) << std::endl;
		}

		return os.str();
	}
};
