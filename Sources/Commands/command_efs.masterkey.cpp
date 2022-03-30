#include "commands.h"
#include "EFS/masterkey_file.h"
#include "NTFS/ntfs_explorer.h"
#include <Utils/table.h>
#include <Utils/constant_names.h>


int decrypt_masterkey(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("Decrypt masterkey for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);
	std::shared_ptr<MFTRecord> masterkey_file_record = commands::helpers::find_record(explorer, opts);
	auto data = masterkey_file_record->data();

	std::shared_ptr<MasterKeyFile> masterkey_file = std::make_shared<MasterKeyFile>(data->data(), data->size());
	if (!masterkey_file->is_loaded())
	{
		std::cerr << "[!] Failed to parse masterkey file from record: " << opts->inode << std::endl;
		return 3;
	}

	auto master_key = masterkey_file->master_key();
	if (master_key)
	{
		std::cout << "[-] Masterkey" << std::endl;
		std::cout << "    Encryption Algorithm : " << constants::efs::enc_algorithm(master_key->header()->Enc_algorithm) << std::endl;
		std::cout << "    Hash Algorithm       : " << constants::efs::hash_algorithm(master_key->header()->Hash_algorithm) << std::endl;
		std::cout << "    Rounds               : " << std::to_string(master_key->header()->Rounds) << std::endl;
		std::cout << "    Salt                 : " << utils::convert::to_hex(master_key->header()->Salt, 16) << std::endl;

		std::cout << "[+] Decrypting masterkey" << std::endl;
		auto res = master_key->decrypt_with_password(opts->sid, opts->password);
		if (res == nullptr)
		{
			std::cout << "[!] Failed to decrypt. Check SID or password." << std::endl;
		}
		else
		{
			std::cout << "[+] Clear masterkey (" << res->size() * 4 << "bits):" << std::endl;

			int i, size = res->size();
			for (i = 0; i < size; i += 32)
			{
				std::cout << "    " << utils::convert::to_hex(res->data() + i, min(32, size - i)) << std::endl;
			}
		}
	}
	else
	{
		std::cerr << "[!] No masterkey in specified file." << std::endl;
		return 3;
	}

	return 0;
}


int show_masterkey(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("Display masterkey for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);
	std::shared_ptr<MFTRecord> masterkey_file_record = commands::helpers::find_record(explorer, opts);

	auto data = masterkey_file_record->data();
	std::shared_ptr<MasterKeyFile> masterkey_file = std::make_shared<MasterKeyFile>(data->data(), data->size());
	if (!masterkey_file->is_loaded())
	{
		std::cerr << "[!] Failed to parse masterkey file from record: " << opts->inode << std::endl;
		return 3;
	}

	std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
	tab->set_margin_left(4);
	tab->set_interline(true);
	tab->add_header_line("Id", utils::ui::TableAlign::RIGHT);
	tab->add_header_line("Property");
	tab->add_header_line("Value");

	std::string date;
	PMFT_RECORD_ATTRIBUTE_HEADER stdinfo_att = masterkey_file_record->attribute_header($STANDARD_INFORMATION);
	if (stdinfo_att)
	{
		PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION stdinfo = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, stdinfo_att, stdinfo_att->Form.Resident.ValueOffset);
		SYSTEMTIME st = { 0 };
		utils::times::ull_to_local_systemtime(stdinfo->CreateTime, &st);
		date = utils::times::display_systemtime(st);
	}

	int i = 0;
	tab->add_item_line(std::to_string(i++));
	tab->add_item_line("File");
	tab->add_item_multiline(
		{
			"Creation : " + date,
			"Size     : " + utils::format::size(data->size())
		}
	);

	tab->new_line();

	tab->add_item_line(std::to_string(i++));
	tab->add_item_line("Version");
	tab->add_item_line(std::to_string(masterkey_file->version()));

	tab->new_line();

	tab->add_item_line(std::to_string(i++));
	tab->add_item_line("GUID");
	tab->add_item_line(masterkey_file->guid());

	tab->new_line();

	tab->add_item_line(std::to_string(i++));
	tab->add_item_line("Policy");
	tab->add_item_line(utils::format::hex(masterkey_file->policy(), true));

	tab->new_line();

	auto master_key = masterkey_file->master_key();
	if (master_key)
	{
		tab->add_item_line(std::to_string(i++));
		tab->add_item_line("MasterKey");
		tab->add_item_multiline(
			{
				"Version  : " + std::to_string(master_key->header()->Version),
				"Salt     : " + utils::convert::to_hex(master_key->header()->Salt, 16),
				"Rounds   : " + std::to_string(master_key->header()->Rounds),
				"Hash Alg : " + constants::efs::hash_algorithm(master_key->header()->Hash_algorithm),
				"Enc Alg  : " + constants::efs::enc_algorithm(master_key->header()->Enc_algorithm),
				"Enc Key  : " + utils::convert::to_hex(master_key->key()->data(), master_key->key()->size())
			}
		);

		tab->new_line();
	}

	auto backup_key = masterkey_file->backup_key();
	if (backup_key)
	{
		tab->add_item_line(std::to_string(i++));
		tab->add_item_line("BackupKey");
		tab->add_item_multiline(
			{
				"Version  : " + std::to_string(backup_key->header()->Version),
				"Salt     : " + utils::convert::to_hex(backup_key->header()->Salt, 16),
				"Rounds   : " + std::to_string(backup_key->header()->Rounds),
				"Hash Alg : " + constants::efs::hash_algorithm(backup_key->header()->Hash_algorithm),
				"Enc Alg  : " + constants::efs::enc_algorithm(backup_key->header()->Enc_algorithm),
				"Enc Key  : " + utils::convert::to_hex(backup_key->key()->data(), backup_key->key()->size())
			}
		);

		tab->new_line();
	}

	auto domain_key = masterkey_file->domain_key();
	if (domain_key)
	{
		tab->add_item_line(std::to_string(i++));
		tab->add_item_line("DomainKey");
		tab->add_item_multiline(
			{
				"Version     : " + std::to_string(domain_key->header()->Version),
				"GUID        : " + utils::id::guid_to_string(domain_key->header()->Guid),
				"Secret      : " + utils::convert::to_hex(domain_key->secret()->data(), domain_key->secret()->size()),
				"AccessCheck : " + utils::convert::to_hex(domain_key->access_check()->data(), domain_key->access_check()->size())
			}
		);

		tab->new_line();
	}

	auto credhist = masterkey_file->credential_history();
	if (credhist)
	{
		tab->add_item_line(std::to_string(i++));
		tab->add_item_line("CredHist");
		tab->add_item_multiline(
			{
				"Version  : " + std::to_string(credhist->header()->Version),
				"GUID     : " + utils::id::guid_to_string(credhist->header()->Guid)
			}
		);

		tab->new_line();
	}

	std::cout << "[+] MasterKey" << std::endl;
	tab->render(std::cout);

	return 0;
}

int list_masterkeys(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("List masterkeys for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Listing user directories" << std::endl;
	auto user_dirs = explorer->mft()->list("C:\\Users", true, false);
	std::cout << "    " << user_dirs.size() << " directories found" << std::endl;

	std::cout << "[+] Searching for keys" << std::endl;

	int masterkey_count = 0;
	int preferred_count = 0;

	std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
	tab->set_margin_left(4);
	tab->set_interline(true);
	tab->add_header_line("Id", utils::ui::TableAlign::RIGHT);
	tab->add_header_line("User");
	tab->add_header_line("Keyfile");
	tab->add_header_line("Key(s)");
	tab->add_header_line("Creation Date");

	for (auto user_dir : user_dirs)
	{
		auto sid_dirs = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\Protect"), true, false);
		for (auto sid_dir : sid_dirs)
		{
			auto key_files = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\Protect\\" + std::get<0>(sid_dir)), false, true);
			for (auto key_file : key_files)
			{
				auto record_keyfile = explorer->mft()->record_from_number(std::get<1>(key_file));
				auto data = record_keyfile->data();

				tab->add_item_line(std::to_string(masterkey_count + preferred_count));
				tab->add_item_line(utils::strings::to_utf8(std::get<0>(user_dir)));
				tab->add_item_multiline(
					{
						"Name   : " + utils::strings::to_utf8(std::get<0>(key_file)),
						"Record : " + utils::format::hex6(record_keyfile->header()->MFTRecordIndex, true),
						"Size   : " + utils::format::size(data->size())
					}
				);

				std::vector<std::string> cell;

				if (std::get<0>(key_file) == L"Preferred")
				{
					preferred_count++;
					PEFS_PREFERRED_FILE pref = reinterpret_cast<PEFS_PREFERRED_FILE>(data->data());
					SYSTEMTIME st;
					utils::times::filetime_to_systemtime(pref->timestamp, &st);

					cell.push_back("Preferred ");
					cell.push_back("    GUID    : " + utils::id::guid_to_string(pref->Guid));
					cell.push_back("    Renew   : " + utils::times::display_systemtime(st));
				}
				else
				{
					masterkey_count++;
					std::shared_ptr<MasterKeyFile> mkf = std::make_shared<MasterKeyFile>(data->data(), data->size());
					if (mkf->is_loaded())
					{
						cell.push_back("GUID        : " + mkf->guid());
						cell.push_back("");

						auto master_key = mkf->master_key();
						if (master_key)
						{
							cell.push_back("MasterKey ");
							cell.push_back("    Version : " + std::to_string(master_key->header()->Version));
							cell.push_back("    Algo    : " + constants::efs::hash_algorithm(master_key->header()->Hash_algorithm) + " - " + constants::efs::enc_algorithm(master_key->header()->Enc_algorithm));
							cell.push_back("    Salt    : " + utils::convert::to_hex(master_key->header()->Salt, 16));
							cell.push_back("    Rounds  : " + std::to_string(master_key->header()->Rounds));
						}
						auto backup_key = mkf->backup_key();
						if (backup_key)
						{
							cell.push_back("BackupKey ");
							cell.push_back("    Version : " + std::to_string(backup_key->header()->Version));
							cell.push_back("    Algo    : " + constants::efs::hash_algorithm(backup_key->header()->Hash_algorithm) + " - " + constants::efs::enc_algorithm(backup_key->header()->Enc_algorithm));
							cell.push_back("    Salt    : " + utils::convert::to_hex(backup_key->header()->Salt, 16));
							cell.push_back("    Rounds  : " + std::to_string(backup_key->header()->Rounds));
						}
						auto cred_hist = mkf->credential_history();
						if (cred_hist)
						{
							cell.push_back("CredHist");
							cell.push_back("    Version : " + std::to_string(cred_hist->header()->Version));
							cell.push_back("    GUID    : " + utils::id::guid_to_string(cred_hist->header()->Guid));
						}
						auto domain_key = mkf->domain_key();
						if (domain_key)
						{
							cell.push_back("DomainKey");
							cell.push_back("    Version : " + std::to_string(domain_key->header()->Version));
							cell.push_back("    GUID    : " + utils::id::guid_to_string(domain_key->header()->Guid));
						}
					}
					else
					{
						cell.push_back("Invalid MasterKey File");
					}
				}
				tab->add_item_multiline(cell);

				PMFT_RECORD_ATTRIBUTE_HEADER stdinfo_att = record_keyfile->attribute_header($STANDARD_INFORMATION);
				if (stdinfo_att)
				{
					PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION stdinfo = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, stdinfo_att, stdinfo_att->Form.Resident.ValueOffset);
					SYSTEMTIME st = { 0 };
					utils::times::ull_to_local_systemtime(stdinfo->CreateTime, &st);
					tab->add_item_line(utils::times::display_systemtime(st));
				}
				else
				{
					tab->add_item_line("");
				}

				tab->new_line();
			}
		}
	}

	if (masterkey_count == 0)
	{
		std::cout << "[+] No masterkey found" << std::endl;
	}
	else
	{
		std::cout << "    " << masterkey_count << " key(s), " << preferred_count << " preferred file(s) found" << std::endl;
		std::cout << "[+] MasterKeys" << std::endl;
		tab->render(std::cout);
	}

	return 0;
}

namespace commands
{
	namespace efs
	{
		namespace masterkey
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
						if (opts->inode >= 0 || opts->from != "")
						{
							if (opts->password != "" && opts->sid != "")
							{
								decrypt_masterkey(disk, volume, opts);
							}
							else
							{
								show_masterkey(disk, volume, opts);
							}
						}
						else
						{
							list_masterkeys(disk, volume, opts);
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
