#include "commands.h"
#include "EFS/masterkey_file.h"
#include "NTFS/ntfs_explorer.h"
#include <Utils/table.h>
#include <Utils/constant_names.h>
#include <EFS/key_file.h>

int decrypt_key(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	return 0;
}

std::vector<std::string> print_private_key(std::shared_ptr<PrivateKey> private_key)
{
	std::vector<std::string> cell =
	{
		"Version           : " + std::to_string(private_key->header()->Version),
		"Provider GUID     : " + utils::id::guid_to_string(private_key->header()->ProviderGuid),
		"MasterKey Version : " + std::to_string(private_key->header()->MasterKeyVersion),
		"MasterKey GUID    : " + utils::id::guid_to_string(private_key->header()->MasterKeyGuid),
		"",
		"Description       : " + private_key->description(),
		"Flags             : " + utils::format::hex(private_key->header()->Flags, true),
		"",
		"Encryption Alg    : " + constants::efs::enc_algorithm(private_key->header()->EncryptionAlgorithm),
		"Hash Alg          : " + constants::efs::hash_algorithm(private_key->header()->HashAlgorithm),
		"",
		"Salt              : " + utils::convert::to_hex(private_key->salt()->data(), private_key->salt()->size()),
		""
	};

	if (private_key->header()->HMACLen)
	{
		cell.push_back("HMAC              : " + utils::convert::to_hex(private_key->hmac()->data(), private_key->hmac()->size()));
	}
	else
	{
		cell.push_back("HMAC              : -");
	}

	cell.push_back("HMAC2             : " + utils::convert::to_hex(private_key->hmac2()->data(), private_key->hmac2()->size()));
	cell.push_back("");
	cell.push_back("Encrypted Data    : " + utils::convert::to_hex(private_key->data()->data(), private_key->data()->size()));
	cell.push_back("");
	cell.push_back("Signature Data    : " + utils::convert::to_hex(private_key->signature()->data(), private_key->signature()->size()));

	return cell;
}


int show_key(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	std::cout << std::setfill('0');
	utils::ui::title("Display key from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Reading key file record: " << opts->inode << std::endl;
	auto key_file_record = explorer->mft()->record_from_number(opts->inode);
	if (key_file_record == nullptr)
	{
		std::cerr << "[!] Err: Failed to read record: " << opts->inode << std::endl;
		return 2;
	}
	else
	{
		auto data = key_file_record->data();
		std::shared_ptr<KeyFile> key_file = std::make_shared<KeyFile>(data->data(), data->size());
		if (!key_file->is_loaded())
		{
			std::cerr << "[!] Err: Failed to parse key file from record: " << opts->inode << std::endl;
			return 3;
		}

		std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
		tab->set_margin_left(4);
		tab->set_interline(true);
		tab->add_header_line("Id", utils::ui::TableAlign::RIGHT);
		tab->add_header_line("Property");
		tab->add_header_line("Value");

		std::string date;
		PMFT_RECORD_ATTRIBUTE_HEADER stdinfo_att = key_file_record->attribute_header($STANDARD_INFORMATION);
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
		tab->add_item_line(std::to_string(key_file->version()));

		tab->new_line();

		tab->add_item_line(std::to_string(i++));
		tab->add_item_line("Name");
		tab->add_item_line(key_file->name());

		tab->new_line();

		tab->add_item_line(std::to_string(i++));
		tab->add_item_line("Flags");
		tab->add_item_line(utils::format::hex(key_file->flags(), true));

		tab->new_line();

		auto sign_public_key = key_file->sign_public_key();
		if (sign_public_key)
		{
			tab->add_item_line(std::to_string(i++));
			tab->add_item_line("PublicKey Signature");
			tab->add_item_line(utils::convert::to_hex(sign_public_key->data(), sign_public_key->size()));
			tab->new_line();
		}

		auto sign_private_key = key_file->sign_private_key();
		if (sign_private_key)
		{
			tab->add_item_line(std::to_string(i++));
			tab->add_item_line("PrivateKey Signature");
			tab->add_item_line(utils::convert::to_hex(sign_private_key->data(), sign_private_key->size()));
			tab->new_line();
		}

		auto public_key = key_file->public_key();
		if (public_key)
		{
			tab->add_item_line(std::to_string(i++));
			tab->add_item_line("PublicKey");

			auto magic = public_key->header()->Magic;
			std::vector<std::string> cell =
			{
					"Magic       : " + utils::format::hex(magic, true) + " (" + ((char*)&magic)[0] + ((char*)&magic)[1] + ((char*)&magic)[2] + ((char*)&magic)[3] + ")",
					"Size        : " + std::to_string(public_key->header()->Bitsize),
					"Exponent    : " + std::to_string(public_key->header()->Exponent),
			};
			auto permissions_str = constants::efs::permissions(public_key->header()->Permissions);
			for (int pi = 0; pi < permissions_str.size(); pi++)
			{
				if (pi == 0) {
					cell.push_back("");
					cell.push_back("Permissions : " + permissions_str[pi]);
				}
				else
				{
					cell.push_back("              " + permissions_str[pi]);
				}
			}
			cell.push_back("");
			cell.push_back("Modulus     : " + utils::convert::to_hex(public_key->modulus()->data(), public_key->modulus()->size()));
			tab->add_item_multiline(cell);
			tab->new_line();
		}

		auto private_key = key_file->private_key();
		if (private_key)
		{
			tab->add_item_line(std::to_string(i++));
			tab->add_item_line("Encrypted PrivateKey");

			auto cell = print_private_key(private_key);
			tab->add_item_multiline(cell);

			tab->new_line();
		}

		auto hash = key_file->hash();
		if (hash)
		{
			tab->add_item_line(std::to_string(i++));
			tab->add_item_line("Hash");
			tab->add_item_line(utils::convert::to_hex(hash->data(), hash->size()));
			tab->new_line();
		}

		auto export_flag = key_file->export_flag();
		if (export_flag)
		{
			tab->add_item_line(std::to_string(i++));
			tab->add_item_line("ExportFlag");

			auto cell = print_private_key(export_flag);
			tab->add_item_multiline(cell);

			tab->new_line();
		}

		std::cout << "[+] Key" << std::endl;
		tab->render(std::cout);
	}
	return 0;
}

int list_keys(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	std::cout << std::setfill('0');
	utils::ui::title("List keys from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Listing user directories" << std::endl;
	auto user_dirs = explorer->mft()->list("C:\\Users", true, false);
	std::cout << "    " << user_dirs.size() << " directories found" << std::endl;

	std::cout << "[+] Searching for keys" << std::endl;

	int key_count = 0;
	int preferred_count = 0;

	std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
	tab->set_margin_left(4);
	tab->set_interline(true);
	tab->add_header_line("Id", utils::ui::TableAlign::RIGHT);
	tab->add_header_line("User");
	tab->add_header_line("Keyfile");
	tab->add_header_line("Name");
	tab->add_header_line("Creation Date");

	for (auto user_dir : user_dirs)
	{
		auto sid_dirs = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\Crypto\\RSA"), true, false);
		for (auto sid_dir : sid_dirs)
		{
			auto key_files = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\Crypto\\RSA\\" + std::get<0>(sid_dir)), false, true);
			for (auto key_file : key_files)
			{
				auto record_keyfile = explorer->mft()->record_from_number(std::get<1>(key_file));
				auto data = record_keyfile->data();

				tab->add_item_line(std::to_string(key_count + preferred_count));
				tab->add_item_line(utils::strings::to_utf8(std::get<0>(user_dir)));
				tab->add_item_multiline(
					{
						"Name   : " + utils::strings::to_utf8(std::get<0>(key_file)),
						"Record : " + utils::format::hex6(record_keyfile->header()->MFTRecordIndex, true),
						"Size   : " + utils::format::size(data->size())
					}
				);

				std::vector<std::string> cell;

				key_count++;
				std::shared_ptr<KeyFile> kf = std::make_shared<KeyFile>(data->data(), data->size());
				if (kf->is_loaded())
				{
					tab->add_item_line(kf->name());
				}
				else
				{
					cell.push_back("Invalid Key File");
				}

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

	if (key_count == 0)
	{
		std::cout << "[+] No key found" << std::endl;
	}
	else
	{
		std::cout << "    " << key_count << " key(s), " << preferred_count << " preferred file(s) found" << std::endl;
		std::cout << "[+] Keys" << std::endl;
		tab->render(std::cout);
	}

	return 0;
}

namespace commands
{
	namespace efs
	{
		namespace key
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
						if (opts->inode != 0)
						{
							if (opts->password != "" && opts->sid != "")
							{
								decrypt_key(disk, volume, opts);
							}
							else
							{
								show_key(disk, volume, opts);
							}
						}
						else
						{
							list_keys(disk, volume, opts);
						}
					}
					else
					{
						std::cerr << "[!] Invalid or missing volume option" << std::endl;
						opts->subcommand = "efs";
						commands::help::dispatch(opts);
					}
				}
				else
				{
					std::cerr << "[!] Invalid or missing disk option" << std::endl;
					opts->subcommand = "efs";
					commands::help::dispatch(opts);
				}

				std::cout.flags(flag_backup);
				return 0;
			}
		}
	}
}
