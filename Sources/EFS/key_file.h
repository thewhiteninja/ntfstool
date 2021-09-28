#pragma once
#include <string>
#include <WinSock2.h>
#include <Windows.h>

#include <memory>

#include "Utils/utils.h"

#pragma pack(push, 1)

typedef struct {
	DWORD	Version;
	DWORD	Flags;
	DWORD	NameLen;
	DWORD	SignPublicKeyLen;
	DWORD	SignPrivateKeyLen;
	DWORD	ExPublicKeyLen;
	DWORD	ExPrivateKeyLen;
	DWORD	HmacLen;
	DWORD	SignExportFlagLen;
	DWORD	ExExportFlagLen;
	BYTE	Data[1];
} KEYFILE_BLOB, * PKEYFILE_BLOB;

typedef struct {
	DWORD	Magic;
	DWORD	ModulusLen;
	DWORD	Bitsize;
	DWORD	Permissions;
	DWORD	Exponent;
	BYTE	Modulus[1];
} PUBLICKEY_BLOB, * PPUBLICKEY_BLOB;

typedef struct {
	DWORD	Version;
	GUID	ProviderGuid;
	DWORD	MasterKeyVersion;
	GUID	MasterKeyGuid;
	DWORD	Flags;
	DWORD	DescriptionLen;
	DWORD	EncryptionAlgorithm;
	DWORD	EncryptionAlgorithmLen;
	DWORD	SaltLen;
	DWORD	HMACLen;
	DWORD	HashAlgorithm;
	DWORD	HashAlgorithmLen;
	DWORD	HMAC2Len;
	DWORD	DataLen;
	DWORD	SignatureLen;
} PRIVATEKEY_ENC_BLOB, * PPRIVATEKEY_ENC_BLOB;


#pragma pack(pop)

class PublicKey
{
private:
	PUBLICKEY_BLOB _header;
	std::shared_ptr<Buffer<PBYTE>> _modulus = nullptr;
public:
	PublicKey(PBYTE data, DWORD size)
	{
		memcpy_s(&_header, 20, data, 20);
		_modulus = std::make_shared<Buffer<PBYTE>>(data + 20, _header.ModulusLen);
		_modulus->shrink(_header.Bitsize / 8);
		_modulus->reverse_bytes();
	}

	PPUBLICKEY_BLOB header()
	{
		return &_header;
	}

	std::shared_ptr<Buffer<PBYTE>> modulus()
	{
		return _modulus;
	}
};

class PrivateKey
{
private:
	PRIVATEKEY_ENC_BLOB _header;

	std::string _description;
	std::shared_ptr<Buffer<PBYTE>> _salt = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _hmac = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _hmac2 = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _data = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _signature = nullptr;
public:
	PrivateKey(PBYTE data, DWORD size)
	{
		memcpy_s(&_header, 48, data, 48);
		DWORD offset = 44;

		_header.DescriptionLen = *(PDWORD(data + offset));
		offset += 4;
		_description = utils::strings::to_utf8(std::wstring((wchar_t*)(data + offset), _header.DescriptionLen / sizeof(wchar_t)));
		utils::strings::rtrim(_description);
		offset += _header.DescriptionLen;

		_header.EncryptionAlgorithm = *(PDWORD(data + offset));
		offset += 4;

		_header.EncryptionAlgorithmLen = *(PDWORD(data + offset));
		offset += 4;

		_header.SaltLen = *(PDWORD(data + offset));
		offset += 4;

		_salt = std::make_shared<Buffer<PBYTE>>(data + offset, _header.SaltLen);
		offset += _header.SaltLen;

		_header.HMACLen = *(PDWORD(data + offset));
		offset += 4;

		_hmac = std::make_shared<Buffer<PBYTE>>(data + offset, _header.HMACLen);
		offset += _header.HMACLen;

		_header.HashAlgorithm = *(PDWORD(data + offset));
		offset += 4;

		_header.HashAlgorithmLen = *(PDWORD(data + offset));
		offset += 4;

		_header.HMAC2Len = *(PDWORD(data + offset));
		offset += 4;

		_hmac2 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.HMAC2Len);
		offset += _header.HMAC2Len;

		_header.DataLen = *(PDWORD(data + offset));
		offset += 4;
		_data = std::make_shared<Buffer<PBYTE>>(data + offset, _header.DataLen);
		offset += _header.DataLen;

		_header.SignatureLen = *(PDWORD(data + offset));
		offset += 4;
		_signature = std::make_shared<Buffer<PBYTE>>(data + offset, _header.SignatureLen);
	}

	PPRIVATEKEY_ENC_BLOB header()
	{
		return &_header;
	}

	std::string description()
	{
		return _description;
	}

	std::shared_ptr<Buffer<PBYTE>> salt()
	{
		return _salt;
	}

	std::shared_ptr<Buffer<PBYTE>> hmac()
	{
		return _hmac;
	}

	std::shared_ptr<Buffer<PBYTE>> hmac2()
	{
		return _hmac2;
	}

	std::shared_ptr<Buffer<PBYTE>> data()
	{
		return _data;
	}

	std::shared_ptr<Buffer<PBYTE>> signature()
	{
		return _signature;
	}
};

class ExportFlag : public PrivateKey
{
private:
public:
	ExportFlag(PBYTE data, DWORD size) : PrivateKey(data, size)
	{
	}
};

class KeyFile
{
private:
	bool _loaded = false;
	DWORD _version = 0;
	DWORD _flags = 0;
	std::string _name;

	std::shared_ptr<Buffer<PKEYFILE_BLOB>> _buf = nullptr;

	std::shared_ptr<Buffer<PBYTE>> _sign_public_key = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _sign_private_key = nullptr;
	std::shared_ptr<PublicKey> _public_key = nullptr;
	std::shared_ptr<PrivateKey> _private_key = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _hmac = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _sign_export_flag = nullptr;
	std::shared_ptr<ExportFlag> _export_flag = nullptr;

	void _load_keyfile()
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
			_private_key = std::make_shared<PrivateKey>(_buf->data()->Data + offset, _buf->data()->ExPrivateKeyLen);
			offset += _buf->data()->ExPrivateKeyLen;
		}

		if (_buf->data()->SignExportFlagLen)
		{
			_sign_export_flag = std::make_shared<Buffer<PBYTE>>(_buf->data()->Data + offset, _buf->data()->SignExportFlagLen);
			offset += _buf->data()->SignExportFlagLen;
		}
		if (_buf->data()->ExExportFlagLen)
		{
			_export_flag = std::make_shared<ExportFlag>(_buf->data()->Data + offset, _buf->data()->ExExportFlagLen);
			offset += _buf->data()->ExExportFlagLen;
		}
	}

	bool _check_file()
	{
		if (_buf == nullptr) return false;
		if (_buf->data()->Version > 2) return false;
		if (_buf->data()->Flags != 0LL) return false;
		return true;
	}

public:
	KeyFile(std::wstring filename)
	{
		_buf = Buffer<PKEYFILE_BLOB>::from_file(filename);

		if (_check_file())
		{
			_load_keyfile();
			_loaded = true;
			_buf = nullptr;
		}
	}

	KeyFile(PBYTE data, DWORD size)
	{
		_buf = std::make_shared<Buffer<PKEYFILE_BLOB>>(data, size);

		if (_check_file())
		{
			_load_keyfile();
			_loaded = true;
			_buf = nullptr;
		}
	}

	bool is_loaded() { return _loaded; }

	DWORD version() { return _version; }

	DWORD flags() { return _flags; }

	std::string name() { return _name; }

	std::shared_ptr<Buffer<PBYTE>> sign_public_key() { return _sign_public_key; }

	std::shared_ptr<Buffer<PBYTE>> sign_private_key() { return _sign_private_key; }

	std::shared_ptr<PublicKey> public_key() { return _public_key; }

	std::shared_ptr<PrivateKey> private_key() { return _private_key; }

	std::shared_ptr<Buffer<PBYTE>> hash() { return _hmac; }

	std::shared_ptr<Buffer<PBYTE>> sign_export_flag() { return _sign_export_flag; }

	std::shared_ptr<ExportFlag> export_flag() { return _export_flag; }
};