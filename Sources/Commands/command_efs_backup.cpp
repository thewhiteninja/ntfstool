#include "Commands/commands.h"
#include "NTFS/ntfs_explorer.h"
#include <Utils/table.h>
#include <Utils/constant_names.h>
#include "EFS/certificate_file.h"
#include <EFS/private_key.h>
#include <EFS/masterkey_file.h>
#include <EFS/key_file.h>
#include <EFS/pkcs12_archive.h>


int backup_keys(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("Backup certificates and keys for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Listing user directories" << std::endl;
	auto user_dirs = explorer->mft()->list("C:\\Users", true, false);
	std::cout << "    " << user_dirs.size() << " directories found" << std::endl;

	std::vector<std::shared_ptr<CertificateFile>> user_certificates;
	std::set<std::string> needed_keys_names;

	std::vector<std::shared_ptr<KeyFile>> user_keys;
	std::set<std::string> needed_masterkeys_names;

	std::vector<std::tuple<std::shared_ptr<MasterKeyFile>, std::string>> user_masterkeys_and_sid;

	std::cout << "[+] Looking for certificates" << std::endl;

	for (auto user_dir : user_dirs)
	{
		auto certificate_files = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates"), false, true);
		for (auto certificate_file : certificate_files)
		{
			auto record_certificate_file = explorer->mft()->record_from_number(std::get<1>(certificate_file));
			auto data = record_certificate_file->data();

			std::shared_ptr<CertificateFile> cert = std::make_shared<CertificateFile>(data->data(), data->size());
			if (cert->is_loaded())
			{
				for (auto element : cert->fields())
				{
					DWORD prop_id = std::get<0>(element);
					if (prop_id == CERT_KEY_PROV_INFO_PROP_ID)
					{
						PMY_CRYPT_KEY_PROV_INFO info = reinterpret_cast<PMY_CRYPT_KEY_PROV_INFO>(std::get<1>(element)->data());
						if (((info->Flags & CRYPT_MACHINE_KEYSET) == 0) &&
							(info->ProvType == PROV_RSA_FULL) &&
							(info->KeySpec == AT_KEYEXCHANGE))
						{
							user_certificates.push_back(cert);
							needed_keys_names.insert(cert->info()->container_name);
							std::wcout << L"    - " + std::get<0>(certificate_file) << std::endl;
						}
					}
				}
			}
		}
	}

	if (needed_keys_names.size() == 0)
	{
		std::cout << "[-] No EFS cerfificate found" << std::endl;
		return 0;
	}

	std::cout << "[+] Looking for corresponding private keys" << std::endl;

	for (auto user_dir : user_dirs)
	{
		if (needed_keys_names.size() == 0)
		{
			break;
		}
		auto sid_dirs = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\Crypto\\RSA"), true, false);
		for (auto sid_dir : sid_dirs)
		{
			if (needed_keys_names.size() == 0)
			{
				break;
			}
			auto key_files = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\Crypto\\RSA\\" + std::get<0>(sid_dir)), false, true);
			for (auto key_file : key_files)
			{
				auto record_keyfile = explorer->mft()->record_from_number(std::get<1>(key_file));
				auto data = record_keyfile->data();

				std::shared_ptr<KeyFile> kf = std::make_shared<KeyFile>(data->data(), data->size());
				if (kf->is_loaded())
				{
					if (needed_keys_names.find(kf->name()) != needed_keys_names.end())
					{
						user_keys.push_back(kf);
						std::wcout << L"    - " + std::get<0>(key_file) << std::endl;
						auto private_enc = kf->private_key();
						if (private_enc)
						{
							needed_masterkeys_names.insert(utils::id::guid_to_string(private_enc->header()->MasterKeyGuid));
						}
						needed_keys_names.erase(kf->name());
						if (needed_keys_names.size() == 0)
						{
							break;
						}
					}
				}
			}
		}
	}

	if (needed_masterkeys_names.size() == 0)
	{
		std::cout << "[-] No corresponding private key found" << std::endl;
		return 0;
	}

	std::cout << "[+] Looking for corresponding masterkeys" << std::endl;

	for (auto user_dir : user_dirs)
	{
		if (needed_masterkeys_names.size() == 0)
		{
			break;
		}
		auto sid_dirs = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\Protect"), true, false);
		for (auto sid_dir : sid_dirs)
		{
			if (needed_masterkeys_names.size() == 0)
			{
				break;
			}
			auto masterkey_files = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\Protect\\" + std::get<0>(sid_dir)), false, true);
			for (auto masterkey_file : masterkey_files)
			{
				auto record_masterkeyfile = explorer->mft()->record_from_number(std::get<1>(masterkey_file));
				auto data = record_masterkeyfile->data();

				if (std::get<0>(masterkey_file) != L"Preferred")
				{
					std::shared_ptr<MasterKeyFile> mkf = std::make_shared<MasterKeyFile>(data->data(), data->size());
					if (mkf->is_loaded())
					{
						if (needed_masterkeys_names.find("{" + mkf->guid() + "}") != needed_masterkeys_names.end())
						{
							user_masterkeys_and_sid.push_back(std::make_tuple(mkf, utils::strings::to_utf8(std::get<0>(sid_dir))));
							std::wcout << L"    - " + std::get<0>(masterkey_file) << std::endl;
						}
						needed_masterkeys_names.erase("{" + mkf->guid() + "}");
						if (needed_masterkeys_names.size() == 0)
						{
							break;
						}
					}
				}
			}
		}
	}

	if (user_masterkeys_and_sid.size() == 0)
	{
		std::cout << "[-] No corresponding master key found" << std::endl;
		return 0;
	}

	std::cout << "[+] Exporting " << user_certificates.size() << " certificates and keys (pass: backup)" << std::endl;

	for (auto cert : user_certificates)
	{
		std::cout << "    - " << cert->hash();

		std::shared_ptr<KeyFile> keyfile = nullptr;
		std::shared_ptr<MasterKeyFile> masterkeyfile = nullptr;
		std::string sid;
		for (auto key : user_keys)
		{
			if (key->name() == cert->info()->container_name)
			{
				keyfile = key;
				break;
			}
		}
		if (keyfile)
		{
			auto private_enc = keyfile->private_key();
			if (private_enc)
			{
				for (auto user_masterkey : user_masterkeys_and_sid)
				{
					if ("{" + std::get<0>(user_masterkey)->guid() + "}" == utils::id::guid_to_string(private_enc->header()->MasterKeyGuid))
					{
						masterkeyfile = std::get<0>(user_masterkey);
						sid = std::get<1>(user_masterkey);
						break;
					}
				}
			}
		}
		if (keyfile && masterkeyfile && sid.length())
		{
			auto masterkey = masterkeyfile->master_key()->decrypt_with_password(sid, opts->password);
			if (masterkey)
			{
				auto decrypted_private_key = keyfile->private_key()->decrypt_with_masterkey(masterkey);
				if (decrypted_private_key != nullptr)
				{
					std::shared_ptr<PKCS12Archive> pkcs12 = std::make_shared<PKCS12Archive>(cert, decrypted_private_key);
					if (opts->output == "")
					{
						opts->output = cert->hash();
					}
					opts->output = utils::files::ensure_file_ext(opts->output, "pfx");

					if (pkcs12->export_to_pfx(opts->output, "backup"))
					{
						std::cout << " : Fail" << std::endl;
						std::cerr << "[!] Unable to export the backup key." << std::endl;
					}
					else
					{
						std::cout << " : Ok" << std::endl;
						std::cout << "      Exported to " << opts->output << std::endl;
					}
				}
				else
				{
					std::cout << " : Fail" << std::endl;
					std::cerr << "[!] Unable to decrypt the private key." << std::endl;
				}
			}
			else
			{
				std::cout << " : Fail" << std::endl;
				std::cerr << "[!] Unable to decrypt the masterkey using provided password." << std::endl;
			}
		}
	}

	return 0;
}

namespace commands
{
	namespace efs
	{
		namespace backup
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
						if (opts->password != "")
						{
							backup_keys(disk, volume, opts);
						}
						else
						{
							invalid_option(opts, "password", opts->password);
						}
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
