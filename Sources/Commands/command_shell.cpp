#include <iostream>
#include <memory>

#include "Commands/commands.h"
#include "NTFS/ntfs_explorer.h"

#include "options.h"
#include "disk.h"
#include "volume.h"
#include "Utils/table.h"

#include <iterator>
#include <iomanip>
#include <sstream>
#include <filesystem>

#define CTRL_PLUS_D	("\x04")

std::pair<std::string, std::string> parse_cmd_line(std::string cmdline)
{
	std::string cmd, args;
	std::istringstream iss(cmdline);
	std::vector<std::string> result{ std::istream_iterator<std::string>(iss), {} };
	if (result.size() > 0)
	{
		cmd = result[0];
		for (size_t i = 1; i < result.size(); i++)
		{
			args += result[i] + " ";
		}
		if (args.size() > 0)
		{
			args.pop_back();
		}
	}

	return std::pair<std::string, std::string>(cmd, args);
}

std::string remove_trailing_path_delimiter(const std::string& s)
{
	std::string ret = s;
	ret.pop_back();
	return ret;
}

int explorer(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol)
{
	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}
	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(utils::strings::from_string(vol->name()));
	std::shared_ptr<MFTRecord> current_dir_record = explorer->mft()->record_from_number(ROOT_FILE_NAME_INDEX_NUMBER);
	std::string current_dir = "\\";

	std::string cmdline;
	bool quit = false;
	while (!quit)
	{
		std::cout << "disk" << disk->index() << ":volume" << vol->index() << ":" << remove_trailing_path_delimiter(current_dir) << "> ";
		std::getline(std::cin, cmdline);
		std::pair<std::string, std::string> cmds = parse_cmd_line(cmdline);

		if (cmds.first != "")
		{
			if ((cmds.first == "exit") || (cmds.first == "quit") || (cmds.first == CTRL_PLUS_D))
			{
				quit = true;
				continue;
			}
			if (cmds.first == "cd")
			{
				if (cmds.second != "")
				{
					std::string next_path = cmds.second;
					std::filesystem::path path(next_path);
					if (path.root_path() != "\\")
					{
						next_path = current_dir + next_path;
					}
					std::shared_ptr<MFTRecord> next_dir = explorer->mft()->record_from_path(next_path);
					if (next_dir != nullptr)
					{
						current_dir_record = next_dir;
						current_dir = next_path;
						if (current_dir.back() != '\\') current_dir += "\\";
					}
					else
					{
						std::cout << cmds.second << ": Directory not found" << std::endl;
					}
				}
				continue;
			}
			if (cmds.first == "ls")
			{
				std::vector<std::shared_ptr<IndexEntry>>& index = current_dir_record->index();
				if (index.size() > 0)
				{
					std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
					tab->set_margin_left(0);
					tab->set_interline(false);
					tab->set_border(false);
					tab->add_header_line("Inode", utils::ui::TableAlign::RIGHT);
					tab->add_header_line("Type");
					tab->add_header_line("Name");
					tab->add_header_line("Size", utils::ui::TableAlign::RIGHT);
					tab->add_header_line("Creation Date");
					tab->add_header_line("Attributes");
					for (auto& entry : index)
					{
						std::shared_ptr<MFTRecord> entry_rec = explorer->mft()->record_from_number(entry->record_number());
						std::vector<std::string> ads_names = entry_rec->alternate_data_names();

						tab->add_item_line(std::to_string(entry_rec->header()->MFTRecordIndex));
						if (entry_rec->header()->flag & MFT_RECORD_IS_DIRECTORY)
						{
							tab->add_item_line("DIR");
						}
						else
						{
							std::vector<std::string> types;
							types.push_back("");
							for (auto& ads : ads_names)
							{
								types.push_back("ADS");
							}
							tab->add_item_multiline(types);
						}
						std::vector<std::string> names;
						names.push_back(utils::strings::wide_to_utf8(entry->name()));
						for (auto& ads : ads_names)
						{
							names.push_back("  " + ads);
						}
						tab->add_item_multiline(names);
						if (entry_rec->header()->flag & MFT_RECORD_IS_DIRECTORY)
						{
							tab->add_item_line("");
						}
						else
						{
							std::vector<std::string> sizes;
							sizes.push_back(std::to_string(entry_rec->datasize()));
							for (auto& ads : ads_names)
							{
								sizes.push_back(std::to_string(entry_rec->datasize(ads)));
							}
							tab->add_item_multiline(sizes);
						}
						PMFT_RECORD_ATTRIBUTE_HEADER stdinfo_att = entry_rec->attribute_header($STANDARD_INFORMATION);
						if (stdinfo_att)
						{
							PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION stdinfo = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, stdinfo_att, stdinfo_att->Form.Resident.ValueOffset);
							SYSTEMTIME st = { 0 };
							utils::times::ull_to_local_systemtime(stdinfo->CreateTime, &st);
							tab->add_item_line(utils::times::display_systemtime(st));

							std::vector<std::string> perms;
							if (stdinfo->Permission.archive) perms.push_back("Ar");
							if (stdinfo->Permission.compressed) perms.push_back("Co");
							if (stdinfo->Permission.device) perms.push_back("De");
							if (stdinfo->Permission.encrypted) perms.push_back("En");
							if (stdinfo->Permission.hidden) perms.push_back("Hi");
							if (stdinfo->Permission.normal) perms.push_back("No");
							if (stdinfo->Permission.not_indexed) perms.push_back("Ni");
							if (stdinfo->Permission.offline) perms.push_back("Of");
							if (stdinfo->Permission.readonly) perms.push_back("Ro");
							if (stdinfo->Permission.reparse) perms.push_back("Re");
							if (stdinfo->Permission.sparse) perms.push_back("Sp");
							if (stdinfo->Permission.system) perms.push_back("Sy");
							if (stdinfo->Permission.temp) perms.push_back("Tm");

							tab->add_item_line(utils::strings::join(perms, " "));
						}
						else
						{
							tab->add_item_line("");
							tab->add_item_line("");
						}

						tab->new_line();
					}
					std::cout << std::endl;
					tab->render(std::cout);
					std::cout << std::endl;
				}
				continue;
			}
			if (cmds.first == "cat")
			{
				if (cmds.second != "")
				{
					std::string filetocat = cmds.second;

					bool found = false;
					std::vector<std::shared_ptr<IndexEntry>> index = current_dir_record->index();
					for (std::shared_ptr<IndexEntry>& entry : index)
					{
						if (utils::strings::wide_to_utf8(entry->name()) == filetocat)
						{
							std::shared_ptr<MFTRecord> filetocat_record = explorer->mft()->record_from_number(entry->record_number());
							if (!(filetocat_record->header()->flag & MFT_RECORD_IS_DIRECTORY))
							{
								found = true;
								if (filetocat_record->datasize() <= 1 * 1024 * 1024)
								{
									std::string content = std::string((PCHAR)filetocat_record->data()->data());
									content.resize(filetocat_record->data()->size());
									std::cout << content << std::endl;
								}
								else
								{
									std::cout << cmds.second << ": File too big to be cat-ed" << std::endl;
								}
							}
							break;
						}
					}
					if (!found)
					{
						std::cout << cmds.second << ": File not found" << std::endl;
					}
				}
				continue;
			}
			if (cmds.first == "pwd")
			{
				if (current_dir.size() == 1) std::cout << current_dir << std::endl;
				else std::cout << remove_trailing_path_delimiter(current_dir) << std::endl;
				continue;
			}
			std::cout << "unknown command : " << cmds.first << std::endl;
		}
	}
	return 0;
}

namespace commands {

	namespace shell {

		int go(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					explorer(disk, volume);
				}
			}
			std::cout.flags(flag_backup);
			return 0;
		}

	}

}