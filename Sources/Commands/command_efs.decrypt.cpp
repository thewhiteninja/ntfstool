#include "Commands/commands.h"
#include "Utils/table.h"
#include "Utils/constant_names.h"
#include <EFS/pkcs12_archive.h>
#include <EFS/fek.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

static unsigned char EFS_IV[16] = { 0x12, 0x13, 0x16, 0xe9, 0x7b, 0x65, 0x16, 0x58, 0x61, 0x89, 0x91, 0x44, 0xbe, 0xad, 0x89, 0x19 };

std::shared_ptr<Buffer<PEFS_FEK>> decrypt_fek(EVP_PKEY* private_key, std::shared_ptr<Buffer<PBYTE>> encrypted_fek)
{
	std::shared_ptr<Buffer<PEFS_FEK>> ret = nullptr;

	if (encrypted_fek && private_key)
	{
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, NULL);
		if (ctx)
		{
			EVP_PKEY_decrypt_init(ctx);
			std::shared_ptr<Buffer<PEFS_FEK>> decrypted_fek = std::make_shared<Buffer<PEFS_FEK>>(encrypted_fek->size());

			size_t outl = decrypted_fek->size();
			if (EVP_PKEY_decrypt(ctx, reinterpret_cast<PBYTE>(decrypted_fek->data()), &outl, encrypted_fek->data(), encrypted_fek->size()))
			{
				decrypted_fek->shrink(static_cast<DWORD>(outl));
				ret = decrypted_fek;
			}
			EVP_PKEY_CTX_free(ctx);
		}
	}
	return ret;
}

void decrypt_block(std::pair<PBYTE, DWORD> block, std::shared_ptr<Buffer<PEFS_FEK>> fek, DWORD64 index, ULONG32 cluster_size)
{
	EVP_CIPHER_CTX* pctx = EVP_CIPHER_CTX_new();
	unsigned char iv[16];

	memcpy_s(iv, 16, EFS_IV, 16);

	((DWORD64*)iv)[0] += (index * cluster_size);
	((DWORD64*)iv)[1] += (index * cluster_size);

	int outl = block.second;
	EVP_DecryptInit(pctx, utils::crypto::cryptoapi::encryption_to_evp(fek->data()->Algorithm), fek->data()->Key, iv);
	EVP_DecryptUpdate(pctx, block.first, &outl, block.first, block.second);
	block.second = outl;
	EVP_CIPHER_CTX_free(pctx);
}

int decrypt_file(std::shared_ptr<MFTRecord> record, std::shared_ptr<Buffer<PEFS_FEK>> fek, std::shared_ptr<Options> opts, ULONG32 cluster_size)
{
	int ret = 0;
	if (opts->output == "")
	{
		opts->output = utils::strings::to_utf8(record->filename() + L".decrypted");
	}

	BIO* output = BIO_new_file(opts->output.c_str(), "wb");
	if (output)
	{
		DWORD64 written_bytes = 0ULL;
		DWORD res_write = 0;
		DWORD index_block = 0;
		DWORD64 clear_size = record->datasize("", false);
		for (auto data_block : record->process_virtual_data("", cluster_size, true))
		{
			if (data_block.second == cluster_size)
			{
				decrypt_block(data_block, fek, index_block, cluster_size);

				int need_to_write = static_cast<int>(min(clear_size - written_bytes, data_block.second));
				if (need_to_write)
				{
					res_write = BIO_write(output, data_block.first, need_to_write);
					if (res_write == 0 || res_write == -1)
					{
						std::cout << "[!] Failed to write decrypted file" << std::endl;
						ret = 3;
					}
					else
					{
						written_bytes += res_write;
					}
				}
			}
			else
			{
				std::cerr << "[!] Wrong block size during decryption (" << data_block.second << ")" << std::endl;
				ret = 4;
				break;
			}
			index_block++;
		}
		BIO_free(output);
	}
	else
	{
		std::cout << "[!] Failed to create decrypted file" << std::endl;
		ret = 1;
	}

	return ret;
}

int load_key_and_decrypt_file(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	utils::ui::title("Decrypt EFS file for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	std::string keyid;

	std::cout << "[+] Loading PKCS12 input file" << std::endl;
	std::shared_ptr<PKCS12Archive> pkcs12 = std::make_shared<PKCS12Archive>(opts->pfx, opts->password);
	if (pkcs12->certificate() && pkcs12->key())
	{
		keyid = pkcs12->certificate_hash();
		std::cout << "[-] KeyID : " << keyid << std::endl;

	}
	else
	{
		std::cout << "[!] Failed to load PKCS12 file" << std::endl;
		return 2;
	}

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::shared_ptr<MFTRecord> record = commands::helpers::find_record(explorer, opts);

	PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION stdinfo = nullptr;
	PMFT_RECORD_ATTRIBUTE_HEADER stdinfo_att = record->attribute_header($STANDARD_INFORMATION);
	if (stdinfo_att)
	{
		stdinfo = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, stdinfo_att, stdinfo_att->Form.Resident.ValueOffset);
	}
	if (stdinfo)
	{
		if (stdinfo->u.Permission.encrypted == 0)
		{
			std::cout << "[!] File is not encrypted" << std::endl;
			return 1;
		}
	}

	std::cout << "[+] Parsing $EFS streams" << std::endl;
	PMFT_RECORD_ATTRIBUTE_HEADER pLogged_utility_attr_header = record->attribute_header($LOGGED_UTILITY_STREAM, "$EFS");
	if (pLogged_utility_attr_header)
	{
		auto efs_header = record->attribute_data<PMFT_RECORD_ATTRIBUTE_EFS_HEADER>(pLogged_utility_attr_header);
		if (efs_header)
		{
			PMFT_RECORD_ATTRIBUTE_EFS_ARRAY_HEADER efs_arr_header = nullptr;
			if (efs_header->data()->OffsetToDDF != 0)
			{
				efs_arr_header = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_EFS_ARRAY_HEADER, efs_header->data(), efs_header->data()->OffsetToDDF);
				std::cout << "[-] " << efs_arr_header->Count << " data decryption field(s) found" << std::endl;

				uint32_t i = 0;
				PMFT_RECORD_ATTRIBUTE_EFS_DATA_DECRYPTION_ENTRY_HEADER entry_header = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_EFS_DATA_DECRYPTION_ENTRY_HEADER, efs_arr_header, 4);
				while (i < efs_arr_header->Count)
				{
					auto fek_enc = std::make_shared<Buffer<PBYTE>>(POINTER_ADD(PBYTE, entry_header, entry_header->FEKOffset), entry_header->FEKSize);
					fek_enc->reverse_bytes();

					PMFT_RECORD_ATTRIBUTE_EFS_DATA_DECRYPTION_ENTRY entry = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_EFS_DATA_DECRYPTION_ENTRY, entry_header, entry_header->CredentialHeaderOffset);
					PMFT_RECORD_ATTRIBUTE_EFS_DF_CERTIFICATE_THUMBPRINT_HEADER thumprint_header = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_EFS_DF_CERTIFICATE_THUMBPRINT_HEADER, entry, entry->cert_thumbprint_header_offset);

					auto cert_fingerprint = std::make_shared<Buffer<PBYTE>>(POINTER_ADD(PBYTE, thumprint_header, thumprint_header->thumbprint_offset), thumprint_header->thumbprint_size);
					std::string ddf_id = utils::strings::to_utf8(cert_fingerprint->to_hex());

					if (ddf_id == keyid)
					{
						std::cout << "[+] Decrypting FEK" << std::endl;
						std::shared_ptr<Buffer<PEFS_FEK>> decrypted_fek = decrypt_fek(pkcs12->key(), fek_enc);
						if (decrypted_fek)
						{
							std::cout << "[-] FEK" << std::endl;
							std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
							table->set_margin_left(4);
							table->add_header_line("Property");
							table->add_header_line("Value");

							table->add_item_line("Entropy");
							table->add_item_line(std::to_string(decrypted_fek->data()->Entropy));
							table->new_line();

							table->add_item_line("Algorithm");
							table->add_item_line(constants::efs::enc_algorithm(decrypted_fek->data()->Algorithm));
							table->new_line();

							table->add_item_line("Key (" + std::to_string((decrypted_fek->size() - 16) * 8) + "bits)");
							table->add_item_line(utils::convert::to_hex(decrypted_fek->data()->Key, decrypted_fek->size() - 16));
							table->new_line();

							table->render(std::cout);
							table = nullptr;

							std::cout << "[+] Decrypting file" << std::endl;
							if (!decrypt_file(record, decrypted_fek, opts, explorer->reader()->sizes.cluster_size))
							{
								std::cout << "[-] Decrypted file written to " << opts->output << " (" << utils::format::size(record->datasize()) << ")" << std::endl;
							}
							else
							{
								std::cerr << "[!] Failed to decrypt the file using FEK" << std::endl;
								return 6;
							}
						}
						else
						{
							std::cerr << "[!] Failed to decrypt encrypted FEK" << std::endl;
							return 5;
						}
					}
					else
					{
						std::cout << "[-] Skipping field: " << i + 1 << " (cert/key not match)" << std::endl;
					}

					entry_header = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_EFS_DATA_DECRYPTION_ENTRY_HEADER, entry_header, entry_header->Length);
					i++;
				}
			}
			else
			{
				std::cout << "[!] Empty data decryption field" << std::endl;
				return 4;
			}
		}
	}
	else
	{
		std::cout << "[!] Unable to find $EFS stream in file" << std::endl;
		return 3;
	}
	return 0;
}


namespace commands
{
	namespace efs
	{
		namespace decrypt
		{
			int dispatch(std::shared_ptr<Options> opts)
			{
				std::ios_base::fmtflags flag_backup(std::cout.flags());

				std::shared_ptr<Disk> disk = get_disk(opts);
				if (disk != nullptr)
				{
					std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
					if (volume != nullptr)
					{
						if (opts->pfx == "") invalid_option(opts, "pfx", opts->pfx);
						if (opts->password == "") invalid_option(opts, "password", opts->password);

						load_key_and_decrypt_file(disk, volume, opts);
					}
					else
					{
						invalid_option(opts, "volume", opts->volume);
					}
				}
				else
				{
					invalid_option(opts, "disk", opts->disk);
				}

				std::cout.flags(flag_backup);
				return 0;
			}
		}
	}
}