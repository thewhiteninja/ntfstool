#pragma once

#include <Windows.h>

#include <memory>
#include <string>

#include "Utils/utils.h"
#include "EFS/private_key.h"

#pragma pack(push, 1)

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

class PrivateKeyEnc
{
protected:
	PRIVATEKEY_ENC_BLOB _header;

	std::string _description;
	std::shared_ptr<Buffer<PBYTE>> _salt = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _hmac = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _hmac2 = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _data = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _signature = nullptr;

	void hash_masterkey(std::shared_ptr<Buffer<PBYTE>> masterkey, std::shared_ptr<Buffer<PBYTE>> masterkey_hash);

	void derive_intermediate_key(DWORD hashAlg, std::shared_ptr<Buffer<PBYTE>> masterkey_hash, std::shared_ptr<Buffer<PBYTE>> salt, std::shared_ptr<Buffer<PBYTE>> derive_intermediate_key);

	void decrypt_key(DWORD decAlg, std::shared_ptr<Buffer<PBYTE>> encrypted, std::shared_ptr<Buffer<PBYTE>> salt, std::shared_ptr<Buffer<PBYTE>> key, std::shared_ptr<Buffer<PBYTE>> clear);

	bool check(std::shared_ptr<Buffer<PBYTE>> key);

public:
	PrivateKeyEnc(PBYTE data, DWORD size);

	std::shared_ptr<PrivateKey> decrypt_with_masterkey(std::shared_ptr<Buffer<PBYTE>> masterkey);

	PPRIVATEKEY_ENC_BLOB header() { return &_header; }

	std::string description() { return _description; }

	std::shared_ptr<Buffer<PBYTE>> salt() { return _salt; }

	std::shared_ptr<Buffer<PBYTE>> hmac() { return _hmac; }

	std::shared_ptr<Buffer<PBYTE>> hmac2() { return _hmac2; }

	std::shared_ptr<Buffer<PBYTE>> data() { return _data; }

	std::shared_ptr<Buffer<PBYTE>> signature() { return _signature; }
};