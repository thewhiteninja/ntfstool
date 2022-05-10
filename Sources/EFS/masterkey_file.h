#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <string>
#include <memory>

#include "EFS/masterkey_file.h"
#include "Utils/buffer.h"
#include "Utils/utils.h"

#include <openssl/hmac.h>

#define POLICY_HASH (4)

#pragma pack(push, 1)

typedef struct {
	DWORD	Version;
	BYTE	Salt[16];
	DWORD	Rounds;
	ALG_ID	Hash_algorithm;
	ALG_ID	Enc_algorithm;
	BYTE	Key[1];
} EFS_MASTERKEY, * PEFS_MASTERKEY;

typedef struct EFS_CREDHIST {
	DWORD	Version;
	GUID	Guid;
} EFS_CREDHIST, * PEFS_CREDHIST;

typedef struct {
	DWORD	Version;
	DWORD	SecretLen;
	DWORD	AccessCheckLen;
	GUID	Guid;
	BYTE	Data[1];
} EFS_DOMAINKEY, * PEFS_DOMAINKEY;

typedef struct {
	GUID Guid;
	FILETIME timestamp;
} EFS_PREFERRED_FILE, * PEFS_PREFERRED_FILE;

typedef struct {
	DWORD	Version;
	DWORD64	Zero0;
	WCHAR	Guid[36];
	DWORD64	Zero1;
	DWORD	Policy;
	DWORD64	MasterKeyLen;
	DWORD64 BackupKeyLen;
	DWORD64 CredHistoryLen;
	DWORD64	DomainKeyLen;
	BYTE	Data[1];
} EFS_MASTERKEY_FILE, * PEFS_MASTERKEY_FILE;

#pragma pack(pop)

class MasterKey
{
protected:
	DWORD _policy = 0;
	EFS_MASTERKEY _header;
	std::shared_ptr<Buffer<PBYTE>> _encrypted_masterkey = nullptr;

	void hash_password(std::u16string& password, std::shared_ptr<Buffer<PBYTE>> output, int policy);

	void derive_intermediate_key_with_sid(std::shared_ptr<Buffer<PBYTE>> password_hash, std::u16string sid, std::shared_ptr<Buffer<PBYTE>> output);

	void derive_masterkey_key(const EVP_MD* hash, std::shared_ptr<Buffer<PBYTE>> derived_key, std::shared_ptr<Buffer<PBYTE>> output);

	void decrypt_masterkey(const EVP_CIPHER* dec, std::shared_ptr<Buffer<PBYTE>> encrypted_masterkey, std::shared_ptr<Buffer<PBYTE>> masterkey_key, std::shared_ptr<Buffer<PBYTE>> clear_masterkey);

	bool check_mac(const EVP_MD* hash, std::shared_ptr<Buffer<PBYTE>> derived_key, std::shared_ptr<Buffer<PBYTE>> masterkey);

	std::shared_ptr<Buffer<PBYTE>> extract_masterkey(std::shared_ptr<Buffer<PBYTE>> masterkey_clear);

public:
	MasterKey(PBYTE data, DWORD64 size, DWORD flags);

	PEFS_MASTERKEY header() { return &_header; }

	std::shared_ptr<Buffer<PBYTE>> key() { return _encrypted_masterkey; }

	std::shared_ptr<Buffer<PBYTE>> decrypt_with_password(std::string sid, std::string password);
};

class BackupKey : public MasterKey
{
public:
	BackupKey(PBYTE data, DWORD64 size, DWORD flags) : MasterKey(data, size, flags)
	{
	}
};

class DomainKey
{
protected:
	EFS_DOMAINKEY _header;
	std::shared_ptr<Buffer<PBYTE>> _secret = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _access_check = nullptr;

public:
	DomainKey(PBYTE data, DWORD64 size, DWORD flags)
	{
		memcpy_s(&_header, sizeof(EFS_DOMAINKEY), data, sizeof(EFS_DOMAINKEY));
		_secret = std::make_shared<Buffer<PBYTE>>(data + 28, _header.SecretLen);
		_access_check = std::make_shared<Buffer<PBYTE>>(data + 28 + _header.SecretLen, _header.AccessCheckLen);
	}

	PEFS_DOMAINKEY header() { return &_header; }

	std::shared_ptr<Buffer<PBYTE>> secret() { return _secret; }

	std::shared_ptr<Buffer<PBYTE>> access_check() { return _access_check; }
};

class CredHistory
{
protected:
	EFS_CREDHIST _header;
public:
	CredHistory(PBYTE data, DWORD64 size)
	{
		memcpy_s(&_header, sizeof(EFS_CREDHIST), data, sizeof(EFS_CREDHIST));
	}

	PEFS_CREDHIST header() { return &_header; }
};


class MasterKeyFile
{
private:
	bool _loaded = false;
	DWORD _version = 0;
	DWORD _policy = 0;
	std::string _guid;

	std::shared_ptr<Buffer<PEFS_MASTERKEY_FILE>> _buf = nullptr;
	std::shared_ptr<MasterKey> _masterkey = nullptr;
	std::shared_ptr<BackupKey> _backupkey = nullptr;
	std::shared_ptr<DomainKey> _domainkey = nullptr;
	std::shared_ptr<CredHistory> _credhistory = nullptr;

	void _load_keyfile();

	bool _check_file();

public:
	MasterKeyFile(std::wstring filename)
	{
		_buf = Buffer<PEFS_MASTERKEY_FILE>::from_file(filename);

		if (_check_file())
		{
			_load_keyfile();
			_loaded = true;
			_buf = nullptr;
		}
	}

	MasterKeyFile(PBYTE data, DWORD size)
	{
		_buf = std::make_shared<Buffer<PEFS_MASTERKEY_FILE>>(data, size);

		if (_check_file())
		{
			_load_keyfile();
			_loaded = true;
			_buf = nullptr;
		}
	}

	bool is_loaded() { return _loaded; }

	std::string guid() { return _guid; }

	DWORD version() { return _version; }

	DWORD policy() { return _policy; }

	std::shared_ptr<MasterKey> master_key() { return _masterkey; }

	std::shared_ptr<BackupKey> backup_key() { return _backupkey; }

	std::shared_ptr<DomainKey> domain_key() { return _domainkey; }

	std::shared_ptr<CredHistory> credential_history() { return _credhistory; }
};