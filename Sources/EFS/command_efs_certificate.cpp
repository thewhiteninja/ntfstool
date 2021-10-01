#include "Commands/commands.h"
#include "NTFS/ntfs_explorer.h"
#include <Utils/table.h>
#include <Utils/constant_names.h>
#include "EFS/certificate.h"


int show_certificate(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{

	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	std::cout << std::setfill('0');
	utils::ui::title("Display certificate from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Reading certificate file record: " << opts->inode << std::endl;
	auto certificate_file_record = explorer->mft()->record_from_number(opts->inode);
	if (certificate_file_record == nullptr)
	{
		std::cerr << "[!] Err: Failed to read record: " << opts->inode << std::endl;
		return 2;
	}
	else
	{
		auto data = certificate_file_record->data();
		std::shared_ptr<Certificate> certificate_file = std::make_shared<Certificate>(data->data(), data->size());
		if (!certificate_file->is_loaded())
		{
			std::cerr << "[!] Err: Failed to parse certificate file from record: " << opts->inode << std::endl;
			return 3;
		}

		std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
		tab->set_margin_left(4);
		tab->set_interline(true);
		tab->add_header_line("Id", utils::ui::TableAlign::RIGHT);
		tab->add_header_line("Property");
		tab->add_header_line("Value");

		std::string date;
		PMFT_RECORD_ATTRIBUTE_HEADER stdinfo_att = certificate_file_record->attribute_header($STANDARD_INFORMATION);
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

		for (auto element : certificate_file->fields())
		{
			tab->add_item_line(std::to_string(i++));

			DWORD prop_id = std::get<0>(element);
			tab->add_item_line(constants::efs::cert_prop_id(prop_id));

			if (prop_id == CERT_KEY_PROV_INFO_PROP_ID)
			{
				PMY_CRYPT_KEY_PROV_INFO info = reinterpret_cast<PMY_CRYPT_KEY_PROV_INFO>(std::get<1>(element)->data());

				std::vector<std::string> cell = {
					"Container Name : " + utils::strings::to_utf8(POINTER_ADD(wchar_t*, info, info->ContainerNameOffset)),
					"Provider Name  : " + utils::strings::to_utf8(POINTER_ADD(wchar_t*, info, info->ProvNameOffset)),
					"Provider Type  : " + constants::efs::cert_prop_provider_type(info->ProvType),
					"Flags          : " + constants::efs::cert_prop_flags(info->Flags),
					"KeySpec        : " + constants::efs::cert_prop_keyspec(info->KeySpec)
				};
				if (info->ProvParam)
				{
					cell.push_back("");
					auto params = POINTER_ADD(PMY_CRYPT_KEY_PROV_PARAM, info, info->ProvParamOffset);
					for (unsigned int i = 0; i < info->ProvParam; i++)
					{
						auto param = params[i];
						cell.push_back(utils::format::hex(param.dwParam) + " : " + utils::format::hex(param.dwFlags) + " : " + utils::format::hex(param.cbData) + " : " + utils::format::hex(param.pbDataOffset));
					}
				}

				tab->add_item_multiline(cell);
			}
			else if (prop_id == CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID)
			{
				tab->add_item_line(std::to_string(((PDWORD)(std::get<1>(element)->data()))[0]));
			}
			else
			{
				tab->add_item_line(utils::convert::to_hex(std::get<1>(element)->data(), std::get<1>(element)->size()));
			}

			tab->new_line();
		}

		std::cout << "[+] Certificate" << std::endl;
		tab->render(std::cout);
	}
	return 0;
}

int list_certificates(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	/*
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

				key_count++;
				std::shared_ptr<KeyFile> kf = std::make_shared<KeyFile>(data->data(), data->size());
				if (kf->is_loaded())
				{
					tab->add_item_line(kf->name());
				}
				else
				{
					tab->add_item_line("Invalid Key File");
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
	}*/

	return 0;
}

namespace commands
{
	namespace efs
	{
		namespace certificate
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
							show_certificate(disk, volume, opts);
						}
						else
						{
							list_certificates(disk, volume, opts);
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
