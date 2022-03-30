#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
#include "Commands/commands.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "Utils/constant_names.h"
#include <Utils/csv_file.h>
#include "Utils/table.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <Utils/usn_rules.h>
#include <Utils/path_finder.h>
#include <Utils/usn_stats.h>


void process_usn_offline(std::shared_ptr<Buffer<PBYTE>> filebuf, std::string from_file, std::shared_ptr<FormatteddFile> output_file, std::shared_ptr<USNRules> usn_rules, std::map<std::string, ULONG64>& matches, std::shared_ptr<USNStats> usn_stats, bool full_mode)
{
	std::cout << "[-] Mode: " << (full_mode ? "full" : "fast") << std::endl;
	if (full_mode)
	{
		std::cout << "[-] Full mode is disabled for usn dump";
		full_mode = false;
	}

	std::cout << "[+] Opening " << from_file << std::endl;

	ULONG64 total_size = filebuf->size();
	ULONG64 filled_size = 0;

	std::cout << "[-] USN dump filesize: " << utils::format::size(total_size) << std::endl;
	ULONG64 processed_size = 0;
	ULONG64 processed_count = 0;
	ULONG64 matches_count = 0;
	DWORD cluster_size = 4096;
	Buffer<PBYTE> clusterBuf((DWORD64)2 * cluster_size);

	for (auto& block : filebuf->process_data(cluster_size))
	{
		processed_size += block.second;

		std::cout << "\r[+] Processing USN records: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ") - " << matches_count << " matches     ";

		if (filled_size)
		{
			break;
		}

		memcpy(clusterBuf.data() + filled_size, block.first, block.second);
		filled_size += block.second;

		PUSN_RECORD_COMMON_HEADER header = (PUSN_RECORD_COMMON_HEADER)clusterBuf.data();
		while ((filled_size > 0) && (header->RecordLength <= filled_size))
		{
			switch (header->MajorVersion)
			{
			case 0:
			{
				DWORD i = 0;
				while ((i < filled_size) && (POINTER_ADD(PWORD, header, i)[0] == 0))
				{
					i += 2;
				}
				header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, i);
				filled_size -= i;
				break;
			}
			case 2:
			{
				PUSN_RECORD_V2 usn_record = (PUSN_RECORD_V2)header;
				std::wstring wfilename = std::wstring(usn_record->FileName);
				wfilename.resize(usn_record->FileNameLength / sizeof(WCHAR));
				std::string filename = utils::strings::to_utf8(wfilename);

				usn_stats->add_record(filename, usn_record);

				std::vector<std::string> matched_rules;
				for (auto& rule : usn_rules->rules())
				{
					if (rule->match(filename, usn_record))
					{
						matched_rules.push_back(rule->id());
						matches_count++;
						if (matches.find(rule->id()) != matches.end())
						{
							matches[rule->id()] += 1;
						}
						else
						{
							matches[rule->id()] = 1;
						}
					}
				}
				if (!matched_rules.empty())
				{
					output_file->add_item(usn_record->MajorVersion);
					output_file->add_item(usn_record->MinorVersion);
					output_file->add_item(usn_record->FileReferenceNumber & 0xffffffffffff);
					output_file->add_item(usn_record->FileReferenceNumber >> 48);
					output_file->add_item(usn_record->ParentFileReferenceNumber & 0xffffffffffff);
					output_file->add_item(usn_record->ParentFileReferenceNumber >> 48);
					output_file->add_item(usn_record->Usn);

					SYSTEMTIME st = { 0 };
					utils::times::ull_to_local_systemtime(usn_record->TimeStamp.QuadPart, &st);
					output_file->add_item(utils::times::display_systemtime(st));
					output_file->add_item(constants::disk::usn::reasons(usn_record->Reason));
					output_file->add_item((usn_record->SourceInfo));
					output_file->add_item((usn_record->SecurityId));
					output_file->add_item(constants::disk::usn::fileattributes(usn_record->FileAttributes));

					output_file->add_item(utils::strings::to_utf8(wfilename));

					output_file->add_item(utils::strings::join_vec(matched_rules, "|"));

					output_file->new_line();
				}

				processed_count++;

				filled_size -= usn_record->RecordLength;
				header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, usn_record->RecordLength);
				break;
			}
			default:
				return;
			}
		}

		if (filled_size <= clusterBuf.size())
		{
			memcpy(clusterBuf.data(), header, (size_t)filled_size);
		}
	}
	std::cout << "\r[+] Processing USN records: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ") - " << matches_count << " matches     ";
}

void process_usn_live(std::shared_ptr<Volume> vol, std::shared_ptr<FormatteddFile> ffile, std::shared_ptr<USNRules> usn_rules, std::map<std::string, ULONG64>& matches, std::shared_ptr<USNStats> usn_stats, bool full_mode)
{
	std::cout << "[-] Mode: " << (full_mode ? "full" : "fast") << std::endl;
	std::shared_ptr<PathFinder> path_finder = nullptr;
	if (full_mode)
	{
		path_finder = std::make_shared<PathFinder>(vol);
		std::cout << "[+] " << path_finder->count() << " $MFT records loaded" << std::endl;
	}

	std::cout << "[+] Opening " << vol->name() << std::endl;
	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Searching for $Extend\\$UsnJrnl" << std::endl;

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path("\\$Extend\\$UsnJrnl");
	if (record == nullptr)
	{
		std::cout << "[!] Not found" << std::endl;
		return;
	}

	std::cout << "[-] Found in file record: " << std::to_string(record->header()->MFTRecordIndex) << std::endl;


	ULONG64 total_size = record->datasize(MFT_ATTRIBUTE_DATA_USN_NAME, true);
	ULONG64 filled_size = 0;

	std::cout << "[-] $J stream size: " << utils::format::size(total_size) << " (could be sparse)" << std::endl;
	ULONG64 processed_size = 0;
	ULONG64 processed_count = 0;
	ULONG64 matches_count = 0;
	DWORD cluster_size = explorer->reader()->sizes.cluster_size;
	Buffer<PBYTE> clusterBuf((DWORD64)2 * cluster_size);

	for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME, cluster_size, true))
	{
		processed_size += block.second;

		std::cout << "\r[+] Processing USN records: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ") - " << matches_count << " matches     ";

		if (filled_size)
		{
			break;
		}

		memcpy(clusterBuf.data() + filled_size, block.first, block.second);
		filled_size += block.second;

		PUSN_RECORD_COMMON_HEADER header = (PUSN_RECORD_COMMON_HEADER)clusterBuf.data();
		while ((filled_size > 0) && (header->RecordLength <= filled_size))
		{
			switch (header->MajorVersion)
			{
			case 0:
			{
				DWORD i = 0;
				while ((i < filled_size) && (POINTER_ADD(PWORD, header, i)[0] == 0))
				{
					i += 2;
				}
				header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, i);
				filled_size -= i;
				break;
			}
			case 2:
			{
				PUSN_RECORD_V2 usn_record = (PUSN_RECORD_V2)header;
				std::wstring wfilename = std::wstring(usn_record->FileName);
				wfilename.resize(usn_record->FileNameLength / sizeof(WCHAR));
				std::string filename = utils::strings::to_utf8(wfilename);

				usn_stats->add_record(filename, usn_record);

				std::vector<std::string> matched_rules;
				for (auto& rule : usn_rules->rules())
				{
					if (rule->match(filename, usn_record))
					{
						matched_rules.push_back(rule->id());
						matches_count++;
						if (matches.find(rule->id()) != matches.end())
						{
							matches[rule->id()] += 1;
						}
						else
						{
							matches[rule->id()] = 1;
						}
					}
				}
				if (!matched_rules.empty())
				{
					ffile->add_item(usn_record->MajorVersion);
					ffile->add_item(usn_record->MinorVersion);
					ffile->add_item(usn_record->FileReferenceNumber & 0xffffffffffff);
					ffile->add_item(usn_record->FileReferenceNumber >> 48);
					ffile->add_item(usn_record->ParentFileReferenceNumber & 0xffffffffffff);
					ffile->add_item(usn_record->ParentFileReferenceNumber >> 48);
					ffile->add_item(usn_record->Usn);

					SYSTEMTIME st = { 0 };
					utils::times::ull_to_local_systemtime(usn_record->TimeStamp.QuadPart, &st);
					ffile->add_item(utils::times::display_systemtime(st));
					ffile->add_item(constants::disk::usn::reasons(usn_record->Reason));
					ffile->add_item((usn_record->SourceInfo));
					ffile->add_item((usn_record->SecurityId));
					ffile->add_item(constants::disk::usn::fileattributes(usn_record->FileAttributes));

					if (full_mode)
					{
						ffile->add_item(path_finder->get_file_path(utils::strings::to_utf8(wfilename), usn_record->ParentFileReferenceNumber));
					}
					else
					{
						ffile->add_item(utils::strings::to_utf8(wfilename));
					}

					ffile->add_item(utils::strings::join_vec(matched_rules, "|"));

					ffile->new_line();
				}

				processed_count++;

				filled_size -= usn_record->RecordLength;
				header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, usn_record->RecordLength);
				break;
			}
			default:
				return;
			}
		}

		if (filled_size <= clusterBuf.size())
		{
			memcpy(clusterBuf.data(), header, (size_t)filled_size);
		}
	}
	std::cout << "\r[+] Processing USN records: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ") - " << matches_count << " matches     ";
}

std::shared_ptr<USNRules> load_rules(std::shared_ptr<Options> opts)
{
	std::cout << "[+] Loading rules from: " << opts->rules << std::endl;
	return std::make_shared<USNRules>(opts->rules);
}

int analyze_usn_journal(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Buffer<PBYTE>> filebuf, std::shared_ptr<Options> opts)
{
	if (disk == nullptr && vol == nullptr)
	{
		utils::ui::title("Analyze USN journal for " + opts->from);
	}
	else
	{
		if (!commands::helpers::is_ntfs(disk, vol)) return 1;
		utils::ui::title("Analyze USN journal for " + disk->name() + " > Volume:" + std::to_string(vol->index()));
	}

	std::shared_ptr<USNRules> usn_rules = load_rules(opts);
	if (usn_rules && usn_rules->size() > 0)
	{
		std::cout << "[-] " << usn_rules->size() << " rules loaded" << std::endl;
	}
	else
	{
		std::cout << "[!] No rule loaded. Exiting." << std::endl;
		return 1;
	}

	std::cout << "[+] Creating " << opts->output << std::endl;

	std::shared_ptr<FormatteddFile> output_file = std::make_shared<CSVFile>(opts->output);

	output_file->set_columns(
		{
		"MajorVersion",
		"MinorVersion",
		"FileReferenceNumber",
		"FileReferenceSequenceNumber",
		"ParentFileReferenceNumber",
		"ParentFileReferenceSequenceNumber",
		"Usn",
		"Timestamp",
		"Reason",
		"SourceInfo",
		"SecurityId",
		"FileAttributes",
		"Filename",
		"Rules"
		}
	);

	std::map<std::string, ULONG64> matches;
	std::shared_ptr<USNStats> usn_stats = std::make_shared<USNStats>();

	if (filebuf != nullptr)
	{
		process_usn_offline(filebuf, opts->from, output_file, usn_rules, matches, usn_stats, opts->mode == "full");
	}
	else
	{
		process_usn_live(vol, output_file, usn_rules, matches, usn_stats, opts->mode == "full");
	}

	std::cout << std::endl << "[+] Closing volume" << std::endl;

	std::cout << "[+] Summary:" << std::endl;

	std::shared_ptr<utils::ui::Table> summary = std::make_shared<utils::ui::Table>();
	summary->set_margin_left(4);

	summary->add_header_line("Index");
	summary->add_header_line("Category");
	summary->add_header_line("Value", utils::ui::TableAlign::RIGHT);
	summary->add_header_line("%", utils::ui::TableAlign::RIGHT);

	auto count = usn_stats->get_stat("records count");

	int index = 0;
	std::stringstream ss;
	for (auto& element : usn_stats->get_stats())
	{
		summary->add_item_line(std::to_string(index++));
		summary->add_item_line(element.first);

		if (usn_stats->is_date(element))
		{
			SYSTEMTIME st = { 0 };
			utils::times::ull_to_local_systemtime(element.second, &st);
			ss.str(std::string());
			ss << utils::times::display_systemtime(st);
			summary->add_item_line(ss.str());
		}
		else
		{
			summary->add_item_line(std::to_string(element.second));
		}

		ss.str(std::string());
		if (usn_stats->is_count(element))
		{
			ss << std::fixed << std::setprecision(2) << (100.0 * element.second / count);
		}
		summary->add_item_line(ss.str());

		summary->new_line();
	}
	summary->render(std::cout);

	if (!matches.empty())
	{
		std::cout << "[+] Rules results:" << std::endl;

		std::shared_ptr<utils::ui::Table> results = std::make_shared<utils::ui::Table>();
		results->set_margin_left(4);

		results->add_header_line("Index");
		results->add_header_line("Rule ID");
		results->add_header_line("Count", utils::ui::TableAlign::RIGHT);
		results->add_header_line("%", utils::ui::TableAlign::RIGHT);

		int index = 0;
		std::stringstream ss;
		for (std::pair<std::string, ULONG64> element : matches)
		{
			results->add_item_line(std::to_string(index++));
			results->add_item_line(element.first);
			results->add_item_line(std::to_string(element.second));

			ss.str(std::string());
			ss << std::fixed << std::setprecision(2) << (100.0 * element.second / count);
			results->add_item_line(ss.str());

			results->new_line();
		}
		results->render(std::cout);
	}
	else
	{
		std::cout << "[+] No match" << std::endl;
	}

	return 0;
}

namespace commands
{
	namespace usn
	{
		namespace analyze
		{
			int dispatch(std::shared_ptr<Options> opts)
			{
				std::ios_base::fmtflags flag_backup(std::cout.flags());

				if (opts->output != "")
				{
					if (opts->rules != "")
					{
						if (opts->mode != "full" && opts->mode != "fast")
						{
							opts->mode = "fast";
						}
					}
					else
					{
						invalid_option(opts, "rules", opts->rules);
					}
				}
				else
				{
					invalid_option(opts, "output", opts->output);
				}

				if (opts->from != "")
				{
					std::shared_ptr<Buffer<PBYTE>> filebuf = Buffer<PBYTE>::from_file(utils::strings::from_string(opts->from));
					if (filebuf != nullptr)
					{
						analyze_usn_journal(nullptr, nullptr, filebuf, opts);
					}
					else
					{
						invalid_option(opts, "from", opts->from);
					}
				}
				else
				{
					std::shared_ptr<Disk> disk = get_disk(opts);
					if (disk != nullptr)
					{
						std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
						if (volume != nullptr)
						{
							analyze_usn_journal(disk, volume, nullptr, opts);
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
				}
				std::cout.flags(flag_backup);
				return 0;
			}
		}
	}
}