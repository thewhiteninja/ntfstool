#include "EFS/private_key_enc.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <EFS/private_key.h>

PrivateKeyEnc::PrivateKeyEnc(PBYTE data, DWORD size)
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

void PrivateKeyEnc::hash_masterkey(std::shared_ptr<Buffer<PBYTE>> masterkey, std::shared_ptr<Buffer<PBYTE>> masterkey_hash)
{
	utils::crypto::hash::sha1_buffer(masterkey->data(), masterkey->size(), masterkey_hash->data());
}

void PrivateKeyEnc::derive_intermediate_key(DWORD hashAlg, std::shared_ptr<Buffer<PBYTE>> masterkey_hash, std::shared_ptr<Buffer<PBYTE>> salt, std::shared_ptr<Buffer<PBYTE>> derive_intermediate_key)
{
	unsigned int output_size = derive_intermediate_key->size();
	auto hash = utils::crypto::cryptoapi::hash_to_evp(hashAlg);
	HMAC(hash, masterkey_hash->data(), masterkey_hash->size(), salt->data(), salt->size(), derive_intermediate_key->data(), &output_size);
	derive_intermediate_key->shrink(output_size);
}

void PrivateKeyEnc::decrypt_key(DWORD decAlg, std::shared_ptr<Buffer<PBYTE>> encrypted, std::shared_ptr<Buffer<PBYTE>> salt, std::shared_ptr<Buffer<PBYTE>> key, std::shared_ptr<Buffer<PBYTE>> clear)
{
	EVP_CIPHER_CTX* pctx = EVP_CIPHER_CTX_new();
	auto dec = utils::crypto::cryptoapi::encryption_to_evp(decAlg);
	int clear_key_size = 0;
	int tmp_size = 0;

	EVP_DecryptInit(pctx, dec, key->data(), 0);
	EVP_DecryptUpdate(pctx, clear->data(), &tmp_size, encrypted->data(), encrypted->size());
	clear_key_size += tmp_size;
	EVP_DecryptFinal(pctx, clear->data() + tmp_size, &tmp_size);
	clear_key_size += tmp_size;
	clear->shrink(clear_key_size);

	EVP_CIPHER_CTX_cleanup(pctx);
}

bool PrivateKeyEnc::check(std::shared_ptr<Buffer<PBYTE>> key)
{
	if (((PDWORD)key->data())[0] != 0x32415352UL) return false;
	if (((PDWORD)key->data())[4] != 65537) return false;
	return true;
}

std::shared_ptr<PrivateKey> PrivateKeyEnc::decrypt_with_masterkey(std::shared_ptr<Buffer<PBYTE>> masterkey)
{
	auto masterkey_hash = std::make_shared<Buffer<PBYTE>>(SHA_DIGEST_LENGTH);
	hash_masterkey(masterkey, masterkey_hash);

	auto derived_intermediate_key = std::make_shared<Buffer<PBYTE>>(_header.HashAlgorithmLen / 8);
	derive_intermediate_key(_header.HashAlgorithm, masterkey_hash, _salt, derived_intermediate_key);

	auto privatekey_key = std::make_shared<Buffer<PBYTE>>(derived_intermediate_key->data(), _header.EncryptionAlgorithmLen / 8);
	auto clear_key = std::make_shared<Buffer<PBYTE>>(_data->size());
	decrypt_key(_header.EncryptionAlgorithm, _data, _salt, privatekey_key, clear_key);

	if (check(clear_key))
	{
		return std::make_shared<PrivateKey>(clear_key->data(), clear_key->size());
	}

	return nullptr;
}