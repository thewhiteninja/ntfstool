#include <iostream>
#include <memory>

#include "Commands/commands.h"
#include "NTFS/ntfs_explorer.h"

#include "options.h"
#include "Drive/disk.h"
#include "Drive/volume.h"
#include "Utils/table.h"

#include <iterator>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <csignal>

#define CTRL_PLUS_D	("\x04")

void signal_callback_handler(int signum) {
	exit(signum);
}

std::vector<std::string> parse_cmd_line(std::string cmdline)
{
	std::vector<std::string> cmds;
	std::istringstream iss(cmdline);

	std::string s;
	while (iss >> std::quoted(s)) {
		cmds.push_back(s);
	}

	return cmds;
}

std::string remove_trailing_path_delimiter(const std::string& s)
{
	std::string ret = s;
	if (ret != "\\")
	{
		ret.pop_back();
	}
	return ret;
}

const std::map<std::string, std::string> help_strings = {
	{"cat", "Print file content (limited to 1Mb file)"},
	{"cp", "Copy file"},
	{"cd", "Change directory"},
	{"exit", "See \"quit\" command."},
	{"ls","List directory content"},
	{"pwd","Print current working directory"},
	{"quit","Quit program"},
	{"help","This command"} };

void help(std::string cmd)
{
	std::cout << "= Commands" << std::endl;

	for (auto command : help_strings)
	{
		std::cout << "    " << command.first << "\t\t: " << command.second << std::endl;
	}
}

std::string clean_disk_name(std::shared_ptr<Disk> disk)
{
	if (disk->index() == DISK_INDEX_IMAGE)
	{
		return "(" + std::filesystem::path(disk->name()).filename().string() + ")";
	}
	else
	{
		return std::to_string(disk->index());
	}
}

int explorer(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol)
{
	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}
	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);
	std::shared_ptr<MFTRecord> current_dir_record = explorer->mft()->record_from_number(ROOT_FILE_NAME_INDEX_NUMBER);
	std::string current_dir = "\\";

	signal(SIGINT, signal_callback_handler);

	std::string cmdline;
	bool quit = false;
	while (!quit)
	{
		std::cout << "disk" << clean_disk_name(disk) << ":volume" << vol->index() << ":" << remove_trailing_path_delimiter(current_dir) << "> ";
		std::cout.flush();
		std::getline(std::cin, cmdline);
		if (std::cin.fail() || std::cin.eof())
		{
			std::cin.clear();
			break;
		}
		std::vector<std::string> cmds = parse_cmd_line(cmdline);

		if (!cmds.empty() && cmds[0] != "")
		{
			if ((cmds[0] == "exit") || (cmds[0] == "quit") || (cmds[0] == CTRL_PLUS_D))
			{
				quit = true;
				continue;
			}
			if (cmds[0] == "cd" && cmds.size() == 2)
			{
				if (cmds[1] == ".")
				{
					continue;
				}
				if (cmds[1] == "..")
				{
					std::filesystem::path path(remove_trailing_path_delimiter(current_dir));
					std::string next_path = path.parent_path().string();

					std::shared_ptr<MFTRecord> next_dir = explorer->mft()->record_from_path(next_path);
					if (next_dir != nullptr)
					{
						current_dir_record = next_dir;
						current_dir = next_path;
						if (current_dir.back() != '\\') current_dir += "\\";
					}
					else
					{
						std::cout << cmds[1] << ": Directory not found" << std::endl;
					}
					continue;
				}
				if (cmds[1] != "")
				{
					std::string next_path = cmds[1];
					std::filesystem::path path(next_path);
					if (path.root_directory() != "\\")
					{
						next_path = current_dir + next_path;
					}
					std::shared_ptr<MFTRecord> next_dir = explorer->mft()->record_from_path(next_path);
					if (next_dir != nullptr)
					{
						if (next_dir->header()->flag & MFT_RECORD_IS_DIRECTORY)
						{
							current_dir_record = next_dir;
							current_dir = next_path;
							if (current_dir.back() != '\\') current_dir += "\\";
						}
						else
						{
							std::cout << cmds[1] << ": Is not a directory" << std::endl;
						}
					}
					else
					{
						std::cout << cmds[1] << ": Directory not found" << std::endl;
					}
				}
				continue;
			}
			if (cmds[0] == "help")
			{
				help(cmds[0]);
				continue;
			}
			if (cmds[0] == "ls")
			{
				std::vector<std::shared_ptr<IndexEntry>> index = current_dir_record->index();
				std::set<DWORD64> win32_named_entries;
				for (auto i : index)
				{
					if (i->name_type() != 2)
					{
						win32_named_entries.insert(i->record_number());
					}
				}

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
						// Skip if there is an entry with non DOS name type
						if ((entry->name_type() == 2) && (win32_named_entries.find(entry->record_number()) != win32_named_entries.end())) continue;

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
							for (unsigned int i = 0; i < ads_names.size(); i++)
							{
								types.push_back("ADS");
							}
							tab->add_item_multiline(types);
						}
						std::vector<std::string> names;
						names.push_back(utils::strings::to_utf8(entry->name()));
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
							if (stdinfo->u.Permission.archive) perms.push_back("Ar");
							if (stdinfo->u.Permission.compressed) perms.push_back("Co");
							if (stdinfo->u.Permission.device) perms.push_back("De");
							if (stdinfo->u.Permission.encrypted) perms.push_back("En");
							if (stdinfo->u.Permission.hidden) perms.push_back("Hi");
							if (stdinfo->u.Permission.normal) perms.push_back("No");
							if (stdinfo->u.Permission.not_indexed) perms.push_back("Ni");
							if (stdinfo->u.Permission.offline) perms.push_back("Of");
							if (stdinfo->u.Permission.readonly) perms.push_back("Ro");
							if (stdinfo->u.Permission.reparse) perms.push_back("Re");
							if (stdinfo->u.Permission.sparse) perms.push_back("Sp");
							if (stdinfo->u.Permission.system) perms.push_back("Sy");
							if (stdinfo->u.Permission.temp) perms.push_back("Tm");

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
			if (cmds[0] == "cat" && cmds.size() == 2)
			{
				if (cmds[1] != "")
				{
					auto from_file = utils::files::split_file_and_stream(cmds[1]);

					bool found = false;
					std::vector<std::shared_ptr<IndexEntry>> index = current_dir_record->index();
					for (std::shared_ptr<IndexEntry>& entry : index)
					{
						if (_strcmpi(utils::strings::to_utf8(entry->name()).c_str(), from_file.first.c_str()) == 0)
						{
							std::shared_ptr<MFTRecord> filetocat_record = explorer->mft()->record_from_number(entry->record_number());
							if (!(filetocat_record->header()->flag & MFT_RECORD_IS_DIRECTORY))
							{
								found = true;
								if (filetocat_record->datasize(from_file.second) <= 1 * 1024 * 1024)
								{
									auto databuf = filetocat_record->data(from_file.second);
									std::string content = std::string((PCHAR)databuf->data(), databuf->size());
									std::cout << content << std::endl;
								}
								else
								{
									std::cout << cmds[1] << ": File too big to be cat-ed" << std::endl;
								}
							}
							break;
						}
					}
					if (!found)
					{
						std::cout << cmds[1] << ": File not found" << std::endl;
					}
				}
				continue;
			}
			if (cmds[0] == "cp" && cmds.size() == 3)
			{
				if (cmds[1] != "" && cmds[2] != "")
				{
					auto from_file = utils::files::split_file_and_stream(cmds[1]);
					std::string copyto = cmds[2];

					bool found = false;
					std::vector<std::shared_ptr<IndexEntry>> index = current_dir_record->index();
					for (std::shared_ptr<IndexEntry>& entry : index)
					{
						if (_strcmpi(utils::strings::to_utf8(entry->name()).c_str(), from_file.first.c_str()) == 0)
						{
							found = true;
							std::shared_ptr<MFTRecord> copyfrom_record = explorer->mft()->record_from_number(entry->record_number());
							if (!(copyfrom_record->header()->flag & MFT_RECORD_IS_DIRECTORY))
							{
								if (copyfrom_record->data_to_file(utils::strings::from_string(copyto).c_str(), from_file.second))
								{
									std::cout << "1 file copied" << std::endl;
								}
							}
							else
							{
								std::cout << cmds[1] << ": Is not a file" << std::endl;
							}
							break;
						}
					}
					if (!found)
					{
						std::cout << cmds[1] << ": File not found" << std::endl;
					}
				}
				continue;
			}
			if (cmds[0] == "pwd")
			{
				if (current_dir.size() == 1) std::cout << current_dir << std::endl;
				else std::cout << remove_trailing_path_delimiter(current_dir) << std::endl;
				continue;
			}
			std::cout << "Unknown command : " << cmds[0] << ". Type \"help\" for command list." << std::endl;
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