#include "Commands/commands.h"
#include "NTFS/ntfs_explorer.h"
#include <Utils/table.h>
#include <Utils/constant_names.h>
#include "EFS/certificate_file.h"


int show_certificate(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("Display certificate for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);
	std::shared_ptr<MFTRecord> certificate_file_record = commands::helpers::find_record(explorer, opts);
	auto data = certificate_file_record->data();

	std::shared_ptr<CertificateFile> certificate_file = std::make_shared<CertificateFile>(data->data(), data->size());
	if (!certificate_file->is_loaded())
	{
		std::cerr << "[!] Failed to parse certificate file from record: " << opts->inode << std::endl;
		return 3;
	}

	if (opts->output == "")
	{
		std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
		tab->set_margin_left(4);
		tab->set_cell_max_size(78);
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
			else if (prop_id == CERT_FRIENDLY_NAME_PROP_ID)
			{
				tab->add_item_line(utils::strings::to_utf8(reinterpret_cast<wchar_t*>(std::get<1>(element)->data())));
			}
			else if (prop_id == CERT_CERTIFICATE_FILE)
			{
				auto desc = certificate_file->certificate_ossl_description();
				if (!desc.empty())
				{
					tab->add_item_multiline(desc);
				}
				else
				{
					tab->add_item_line(utils::convert::to_hex(std::get<1>(element)->data(), std::get<1>(element)->size()));
				}
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
	else
	{
		if (certificate_file->export_to_PEM(opts->output) == 0)
		{
			std::cout << "[+] Certificate exported to " << opts->output << ".pem" << std::endl;
		}
		else
		{
			std::cerr << "[!] Unable to export the certificate" << std::endl;
		}
	}

	return 0;
}

int list_certificates(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("List certificates for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Listing user directories" << std::endl;
	auto user_dirs = explorer->mft()->list("C:\\Users", true, false);
	std::cout << "    " << user_dirs.size() << " directories found" << std::endl;

	std::cout << "[+] Looking for certificates" << std::endl;

	int certificate_count = 0;

	std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
	tab->set_margin_left(4);
	tab->set_interline(true);
	tab->add_header_line("Id", utils::ui::TableAlign::RIGHT);
	tab->add_header_line("User");
	tab->add_header_line("File");
	tab->add_header_line("Certificate");

	for (auto user_dir : user_dirs)
	{
		auto certificate_files = explorer->mft()->list(utils::strings::to_utf8(L"C:\\Users\\" + std::get<0>(user_dir) + L"\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates"), false, true);
		for (auto certificate_file : certificate_files)
		{
			auto record_certificate_file = explorer->mft()->record_from_number(std::get<1>(certificate_file));
			auto data = record_certificate_file->data();

			tab->add_item_line(std::to_string(certificate_count));
			tab->add_item_line(utils::strings::to_utf8(std::get<0>(user_dir)));

			std::string date;
			PMFT_RECORD_ATTRIBUTE_HEADER stdinfo_att = record_certificate_file->attribute_header($STANDARD_INFORMATION);
			if (stdinfo_att)
			{
				PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION stdinfo = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, stdinfo_att, stdinfo_att->Form.Resident.ValueOffset);
				SYSTEMTIME st = { 0 };
				utils::times::ull_to_local_systemtime(stdinfo->CreateTime, &st);
				date = utils::times::display_systemtime(st);
			}

			tab->add_item_multiline(
				{
					"Name     : " + utils::strings::to_utf8(std::get<0>(certificate_file)),
					"Record   : " + utils::format::hex6(record_certificate_file->header()->MFTRecordIndex, true),
					"Size     : " + utils::format::size(data->size()),
					"",
					"Creation : " + date
				}
			);

			certificate_count++;
			std::shared_ptr<CertificateFile> cert = std::make_shared<CertificateFile>(data->data(), data->size());
			if (cert->is_loaded())
			{
				auto info = cert->info();
				std::vector<std::string> cell;
				if (info->friendly_name != "")
				{
					cell.push_back("Friendly Name : " + info->friendly_name);
					cell.push_back("");
				}
				if (info->container_name != "") cell.push_back("Container     : " + info->container_name);
				if (info->provider_name != "") cell.push_back("Provider      : " + info->provider_name);
				if (info->provider_type != "") cell.push_back("Type          : " + info->provider_type);
				if (info->keyspec != "") cell.push_back("KeySpec       : " + info->keyspec);
				tab->add_item_multiline(cell);
			}
			else
			{
				tab->add_item_line("Invalid certificate file");
			}

			tab->new_line();
		}
	}

	if (certificate_count == 0)
	{
		std::cout << "[+] No certificate found" << std::endl;
	}
	else
	{
		std::cout << "    " << certificate_count << " certificate(s) found" << std::endl;
		std::cout << "[+] Certificates" << std::endl;
		tab->render(std::cout);
	}

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
						if (opts->inode >= 0 || opts->from != "")
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
