#include "EFS/key_file.h"

void KeyFile::_load_keyfile()
{
	DWORD offset = 0;

	if (_buf->data()->NameLen)
	{
		_name = std::string((char*)_buf->data()->Data + offset, _buf->data()->NameLen);
		utils::strings::rtrim(_name);
		offset += _buf->data()->NameLen;
	}

	if (_buf->data()->HmacLen)
	{
		_hmac = std::make_shared<Buffer<PBYTE>>(_buf->data()->Data + offset, _buf->data()->HmacLen);
		offset += _buf->data()->HmacLen;
	}

	if (_buf->data()->SignPublicKeyLen)
	{
		_sign_public_key = std::make_shared<Buffer<PBYTE>>(_buf->data()->Data + offset, _buf->data()->SignPublicKeyLen);
		offset += _buf->data()->SignPublicKeyLen;
	}
	if (_buf->data()->SignPrivateKeyLen)
	{
		_sign_private_key = std::make_shared<Buffer<PBYTE>>(_buf->data()->Data + offset, _buf->data()->SignPrivateKeyLen);
		offset += _buf->data()->SignPrivateKeyLen;
	}
	if (_buf->data()->ExPublicKeyLen)
	{
		_public_key = std::make_shared<PublicKey>(_buf->data()->Data + offset, _buf->data()->ExPublicKeyLen);
		offset += _buf->data()->ExPublicKeyLen;
	}

	if (_buf->data()->ExPrivateKeyLen)
	{
		_private_key = std::make_shared<PrivateKeyEnc>(_buf->data()->Data + offset, _buf->data()->ExPrivateKeyLen);
		offset += _buf->data()->ExPrivateKeyLen;
	}

	if (_buf->data()->SignExportFlagLen)
	{
		_sign_export_flag = std::make_shared<Buffer<PBYTE>>(_buf->data()->Data + offset, _buf->data()->SignExportFlagLen);
		offset += _buf->data()->SignExportFlagLen;
	}
	if (_buf->data()->ExExportFlagLen)
	{
		_export_flag = std::make_shared<ExportFlagsEnc>(_buf->data()->Data + offset, _buf->data()->ExExportFlagLen);
		offset += _buf->data()->ExExportFlagLen;
	}
}

bool KeyFile::_check_file()
{
	if (_buf == nullptr) return false;
	if (_buf->data()->Version > 2) return false;
	if (_buf->data()->Flags != 0LL) return false;
	return true;
}


KeyFile::KeyFile(std::wstring filename)
{
	_buf = Buffer<PKEYFILE_BLOB>::from_file(filename);

	if (_check_file())
	{
		_load_keyfile();
		_loaded = true;
		_buf = nullptr;
	}
}

KeyFile::KeyFile(PBYTE data, DWORD size)
{
	_buf = std::make_shared<Buffer<PKEYFILE_BLOB>>(data, size);

	if (_check_file())
	{
		_load_keyfile();
		_loaded = true;
		_buf = nullptr;
	}
}