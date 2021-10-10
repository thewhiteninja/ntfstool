#include "EFS/export_flags_enc.h"
#include <openssl/sha.h>

std::shared_ptr<ExportFlags> ExportFlagsEnc::decrypt_with_masterkey(std::shared_ptr<Buffer<PBYTE>> masterkey)
{
	auto masterkey_hash = std::make_shared<Buffer<PBYTE>>(SHA_DIGEST_LENGTH);
	hash_masterkey(masterkey, masterkey_hash);

	auto derived_intermediate_key = std::make_shared<Buffer<PBYTE>>(_header.HashAlgorithmLen / 8);
	auto salt_and_entropy = std::make_shared<Buffer<PBYTE>>(_salt->size() + sizeof(EXPORTFLAGS_ENTROPY));
	memcpy_s(salt_and_entropy->data(), salt_and_entropy->size(), _salt->data(), _salt->size());
	memcpy_s(salt_and_entropy->data() + _salt->size(), sizeof(EXPORTFLAGS_ENTROPY), EXPORTFLAGS_ENTROPY, sizeof(EXPORTFLAGS_ENTROPY));

	derive_intermediate_key(_header.HashAlgorithm, masterkey_hash, salt_and_entropy, derived_intermediate_key);

	auto export_flag_key = std::make_shared<Buffer<PBYTE>>(derived_intermediate_key->data(), _header.EncryptionAlgorithmLen / 8);
	auto clear_flag = std::make_shared<Buffer<PBYTE>>(_data->size());
	decrypt_key(_header.EncryptionAlgorithm, _data, _salt, export_flag_key, clear_flag);

	return std::make_shared<ExportFlags>(clear_flag->data(), clear_flag->size());

}