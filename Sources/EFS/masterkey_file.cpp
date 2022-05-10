#include "EFS/masterkey_file.h"

void MasterKey::hash_password(std::u16string& password, std::shared_ptr<Buffer<PBYTE>> output, int policy)
{
	if (policy & POLICY_HASH)
	{
		utils::crypto::hash::sha1_buffer((PBYTE)password.c_str(), password.size() * 2, output->data());
		output->shrink(SHA_DIGEST_LENGTH);
	}
	else
	{
		utils::crypto::hash::md4_buffer((PBYTE)password.c_str(), password.size() * 2, output->data());
		output->shrink(MD4_DIGEST_LENGTH);
	}
}

void MasterKey::derive_intermediate_key_with_sid(std::shared_ptr<Buffer<PBYTE>> password_hash, std::u16string sid, std::shared_ptr<Buffer<PBYTE>> output)
{
	unsigned int output_size = 0;
	HMAC(EVP_sha1(), password_hash->data(), password_hash->size(), (const unsigned char*)sid.c_str(), (sid.length() + 1) * sizeof(wchar_t), output->data(), &output_size);
	output->shrink(output_size);
}

void MasterKey::derive_masterkey_key(const EVP_MD* hash, std::shared_ptr<Buffer<PBYTE>> derived_key, std::shared_ptr<Buffer<PBYTE>> output)
{

	unsigned int hash_len = 0;
	unsigned int block = 1;
	unsigned int needed_bytes = output->size();

	unsigned char salt_and_block[20] = { 0 };

	std::shared_ptr<Buffer<PBYTE>> intermediate_key_a = std::make_shared<Buffer<PBYTE>>(EVP_MD_size(hash));
	std::shared_ptr<Buffer<PBYTE>> intermediate_key_b = std::make_shared<Buffer<PBYTE>>(EVP_MD_size(hash));

	while (needed_bytes)
	{
		memcpy_s(salt_and_block, sizeof(salt_and_block), _header.Salt, sizeof(_header.Salt));
		((PDWORD)salt_and_block)[4] = _byteswap_ulong(block);

		HMAC(hash, derived_key->data(), derived_key->size(), salt_and_block, sizeof(salt_and_block), intermediate_key_a->data(), &hash_len);
		for (DWORD round = 1; round < _header.Rounds; round++)
		{
			HMAC(hash, derived_key->data(), derived_key->size(), intermediate_key_a->data(), intermediate_key_a->size(), intermediate_key_b->data(), &hash_len);
			utils::crypto::xor_buffer(intermediate_key_a->data(), intermediate_key_a->size(), intermediate_key_b->data(), intermediate_key_b->size());
		}

		memcpy_s(output->data() + ((block - 1) * hash_len), min(hash_len, needed_bytes), intermediate_key_a->data(), min(intermediate_key_a->size(), needed_bytes));

		needed_bytes -= min(hash_len, needed_bytes);
		block++;
	}
}

void MasterKey::decrypt_masterkey(const EVP_CIPHER* dec, std::shared_ptr<Buffer<PBYTE>> encrypted_masterkey, std::shared_ptr<Buffer<PBYTE>> masterkey_key, std::shared_ptr<Buffer<PBYTE>> clear_masterkey)
{
	int clear_master_key_size = clear_masterkey->size();
	EVP_CIPHER_CTX* pctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(pctx, dec, masterkey_key->data(), masterkey_key->data() + EVP_CIPHER_key_length(dec));
	EVP_CIPHER_CTX_set_padding(pctx, 0);
	EVP_DecryptUpdate(pctx, clear_masterkey->data(), &clear_master_key_size, encrypted_masterkey->data(), encrypted_masterkey->size());
	EVP_DecryptFinal(pctx, clear_masterkey->data() + clear_master_key_size, &clear_master_key_size);
	EVP_CIPHER_CTX_cleanup(pctx);
}

bool MasterKey::check_mac(const EVP_MD* hash, std::shared_ptr<Buffer<PBYTE>> derived_key, std::shared_ptr<Buffer<PBYTE>> masterkey)
{
	std::shared_ptr<Buffer<PBYTE>> hmac_a = std::make_shared<Buffer<PBYTE>>(EVP_MD_size(hash));
	std::shared_ptr<Buffer<PBYTE>> hmac_b = std::make_shared<Buffer<PBYTE>>(EVP_MD_size(hash));

	unsigned int hmac_a_len = 0;
	HMAC(hash, derived_key->data(), derived_key->size(), masterkey->data(), 16, hmac_a->data(), &hmac_a_len);
	unsigned int hmac_b_len = 0;
	HMAC(hash, hmac_a->data(), hmac_a_len, masterkey->data() + masterkey->size() - hmac_a_len, hmac_a_len, hmac_b->data(), &hmac_b_len);

	return memcmp(hmac_b->data(), masterkey->data() + 16, hmac_b_len) == 0;
}

std::shared_ptr<Buffer<PBYTE>> MasterKey::extract_masterkey(std::shared_ptr<Buffer<PBYTE>> masterkey_clear)
{
	unsigned int keysize = (masterkey_clear->size() - 16) / 2;
	return std::make_shared<Buffer<PBYTE>>(masterkey_clear->data() + 16 + keysize, keysize);
}

MasterKey::MasterKey(PBYTE data, DWORD64 size, DWORD flags)
{
	memcpy_s(&_header, sizeof(EFS_MASTERKEY), data, sizeof(EFS_MASTERKEY));
	_policy = flags;
	_encrypted_masterkey = std::make_shared<Buffer<PBYTE>>(data + 0x20, static_cast<DWORD>(size & 0xffffffff) - 0x20);
}

std::shared_ptr<Buffer<PBYTE>> MasterKey::decrypt_with_password(std::string sid, std::string password)
{
	std::u16string password_utf16_le = utils::strings::str_to_utf16(password);
	std::u16string sid_utf16_le = utils::strings::str_to_utf16(sid);

	const EVP_MD* hash = utils::crypto::cryptoapi::hash_to_evp(_header.Hash_algorithm);
	const EVP_CIPHER* dec = utils::crypto::cryptoapi::encryption_to_evp(_header.Enc_algorithm);

	auto password_hash = std::make_shared<Buffer<PBYTE>>(SHA_DIGEST_LENGTH);
	auto derived_key = std::make_shared<Buffer<PBYTE>>(SHA_DIGEST_LENGTH);
	auto masterkey_key = std::make_shared<Buffer<PBYTE>>(EVP_CIPHER_key_length(dec) + EVP_CIPHER_iv_length(dec));
	auto clear_masterkey = std::make_shared<Buffer<PBYTE>>(_encrypted_masterkey->size());

	hash_password(password_utf16_le, password_hash, _policy);
	derive_intermediate_key_with_sid(password_hash, sid_utf16_le, derived_key);
	derive_masterkey_key(hash, derived_key, masterkey_key);

	decrypt_masterkey(dec, _encrypted_masterkey, masterkey_key, clear_masterkey);

	if (check_mac(hash, derived_key, clear_masterkey))
	{
		return extract_masterkey(clear_masterkey);
	}

	return nullptr;
}

void MasterKeyFile::_load_keyfile()
{
	if (_buf)
	{
		_version = _buf->data()->Version;
		_policy = _buf->data()->Policy;
		_guid = utils::strings::to_utf8(_buf->data()->Guid);
	}

	if (_buf->data()->MasterKeyLen)
	{
		_masterkey = std::make_shared<MasterKey>(_buf->data()->Data, _buf->data()->MasterKeyLen, _buf->data()->Policy);
	}

	if (_buf->data()->BackupKeyLen)
	{
		_backupkey = std::make_shared<BackupKey>(_buf->data()->Data + _buf->data()->MasterKeyLen, _buf->data()->BackupKeyLen, _buf->data()->Policy);
	}
	if (_buf->data()->CredHistoryLen)
	{
		_credhistory = std::make_shared<CredHistory>(_buf->data()->Data + _buf->data()->MasterKeyLen + _buf->data()->BackupKeyLen, _buf->data()->CredHistoryLen);
	}
	if (_buf->data()->DomainKeyLen)
	{
		_domainkey = std::make_shared<DomainKey>(_buf->data()->Data + _buf->data()->MasterKeyLen + _buf->data()->BackupKeyLen + _buf->data()->CredHistoryLen, _buf->data()->DomainKeyLen, _buf->data()->Policy);
	}
}

bool MasterKeyFile::_check_file()
{
	if (_buf == nullptr) return false;
	if (_buf->data()->Version > 2) return false;
	if (_buf->data()->Zero0 != 0LL) return false;
	if (_buf->data()->Zero1 != 0LL) return false;
	return true;
}
