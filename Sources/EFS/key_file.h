#pragma once
#include <string>

#include <Windows.h>

#include <memory>

#include "Utils/utils.h"
#include <EFS/private_key_enc.h>
#include <EFS/export_flags_enc.h>
#include <EFS/public_key.h>

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

#pragma pack(pop)

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
	std::shared_ptr<PrivateKeyEnc> _private_key = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _hmac = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _sign_export_flag = nullptr;
	std::shared_ptr<ExportFlagsEnc> _export_flag = nullptr;

	void _load_keyfile();

	bool _check_file();

public:
	KeyFile(std::wstring filename);

	KeyFile(PBYTE data, DWORD size);

	bool is_loaded() { return _loaded; }

	DWORD version() { return _version; }

	DWORD flags() { return _flags; }

	std::string name() { return _name; }

	std::shared_ptr<Buffer<PBYTE>> sign_public_key() { return _sign_public_key; }

	std::shared_ptr<Buffer<PBYTE>> sign_private_key() { return _sign_private_key; }

	std::shared_ptr<PublicKey> public_key() { return _public_key; }

	std::shared_ptr<PrivateKeyEnc> private_key() { return _private_key; }

	std::shared_ptr<Buffer<PBYTE>> hash() { return _hmac; }

	std::shared_ptr<Buffer<PBYTE>> sign_export_flag() { return _sign_export_flag; }

	std::shared_ptr<ExportFlagsEnc> export_flags() { return _export_flag; }
};