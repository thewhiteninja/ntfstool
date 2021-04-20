#include <algorithm>
#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <stdexcept>

#include "Drive/disk.h"
#include "options.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "NTFS/ntfs.h"
#include "Utils/utils.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"

bool valid_record(PMFT_RECORD_HEADER ph)
{
	return (
		(memcmp(ph->signature, "FILE", 4) == 0) &&
		(ph->attributeOffset > 0x30) &&
		(ph->attributeOffset < 0x400) &&
		(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, ph, ph->attributeOffset)->TypeCode >= 10) &&
		(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, ph, ph->attributeOffset)->TypeCode <= 100)
		);
}

std::string get_full_path(DWORD index, std::map<DWORD, std::string>& index_to_name, std::map<DWORD, DWORD>& index_to_parent)
{
	DWORD cur_index = index;
	std::string cur_path = index_to_name[cur_index];

	while (cur_index != ROOT_FILE_NAME_INDEX_NUMBER)
	{
		if (index_to_parent.find(cur_index) != index_to_parent.end())
		{
			cur_index = index_to_parent[cur_index];
			if (index_to_name.find(cur_index) != index_to_name.end())
			{
				cur_path = index_to_name[cur_index] + "\\" + cur_path;
			}
			else
			{
				cur_path = "?\\" + cur_path;
				break;
			}
		}
	}
	return cur_path;
}

LONGLONG check_cluster_used(std::shared_ptr<Buffer<PBYTE>> bitmap, PMFT_DATARUN dt)
{
	DWORD reused = 0;
	LONGLONG start_byte = dt->offset / 8;
	DWORD start_bit = dt->offset % 8;
	LONGLONG stop_byte = (dt->offset + dt->length) / 8;
	DWORD stop_bit = (dt->offset + dt->length) % 8;
	if (stop_bit == 0)
	{
		stop_byte++;
	}

	while (start_byte != stop_byte && start_bit != stop_bit)
	{
		if (bitmap->data()[start_byte] & (0x80 >> start_bit))
		{
			reused++;
		}

		start_bit++;
		if (start_bit == 8)
		{
			start_bit = 0;
			start_byte++;
		}
	}

	return reused;
}

bool check_dataruns_still_valid(ULONG64 datasize, ULONG64 clustersize, const std::vector<MFT_DATARUN>& dataruns)
{
	ULONG64 size_from_dataruns = 0;

	for (auto& dt : dataruns)
	{
		size_from_dataruns += dt.length * clustersize;
	}

	return (datasize >= size_from_dataruns - clustersize) && (datasize <= size_from_dataruns);
}

int print_deleted_files(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts) {
	if (vol->filesystem() != "NTFS" && vol->filesystem() != "Bitlocker")
	{
		std::cerr << "[!] NTFS/Bitlocker volume required" << std::endl;
		return 1;
	}

	utils::ui::title("Undelete from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	DWORD cluster_size = ((PBOOT_SECTOR_NTFS)explorer->reader()->boot_record())->bytePerSector * ((PBOOT_SECTOR_NTFS)explorer->reader()->boot_record())->sectorPerCluster;
	DWORD record_size = ((PBOOT_SECTOR_NTFS)explorer->reader()->boot_record())->clusterPerRecord >= 0 ? ((PBOOT_SECTOR_NTFS)explorer->reader()->boot_record())->clusterPerRecord * cluster_size : 1 << -((PBOOT_SECTOR_NTFS)explorer->reader()->boot_record())->clusterPerRecord;

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(0);
	ULONG64 total_size = record->datasize();

	std::cout << "[-] $MFT size     :" << utils::format::size(total_size) << " (~" << std::to_string(total_size / record_size) << " records)" << std::endl;

	std::shared_ptr<MFTRecord> bitmap_record = explorer->mft()->record_from_number(6);

	std::cout << "[-] $BITMAP size  :" << utils::format::size(bitmap_record->datasize()) << std::endl;

	std::shared_ptr<Buffer<PBYTE>> bitmap = bitmap_record->data();

	std::cout << "[+] Searching deleted files" << std::endl;

	std::vector<std::tuple<DWORD, bool, ULONG64, SYSTEMTIME, double>> deleted_files;
	std::map<DWORD, std::string> index_to_name;
	std::map<DWORD, DWORD> index_to_parent;

	const auto& prof_start = std::chrono::high_resolution_clock::now();

	ULONG64 processed_count = 0;
	for (auto& block : record->process_data())
	{
		DWORD offset = 0;
		for (offset = 0; offset <= block.second - record_size; offset += record_size)
		{
			PMFT_RECORD_HEADER pmrh = POINTER_ADD(PMFT_RECORD_HEADER, block.first, offset);
			if (valid_record(pmrh))
			{
				std::shared_ptr<MFTRecord> f = explorer->mft()->record_from_number(pmrh->MFTRecordIndex);

				std::wstring name;
				DWORD parent = 5;
				SYSTEMTIME st = { 0 };

				PMFT_RECORD_ATTRIBUTE_HEADER pattr = f->attribute_header($FILE_NAME, "");
				if (pattr != nullptr)
				{
					auto pattr_filename = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
					if (pattr_filename->NameType == 2)
					{
						PMFT_RECORD_ATTRIBUTE_HEADER pattr_long = f->attribute_header($FILE_NAME, "", 1);
						if (pattr_long != nullptr)
						{
							pattr = pattr_long;
						}
					}
				}

				if (pattr != nullptr)
				{
					PMFT_RECORD_ATTRIBUTE_FILENAME psubattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
					name = std::wstring(psubattr->Name);
					name.resize(psubattr->NameLength);
					parent = psubattr->ParentDirectory.FileRecordNumber;
				}
				pattr = f->attribute_header($STANDARD_INFORMATION);
				if (pattr != nullptr)
				{
					PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION psubattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, pattr, pattr->Form.Resident.ValueOffset);
					utils::times::ull_to_local_systemtime(psubattr->MFTTime, &st);
				}

				index_to_name.insert(std::make_pair(pmrh->MFTRecordIndex, utils::strings::to_utf8(name)));
				index_to_parent.insert(std::make_pair(pmrh->MFTRecordIndex, parent));

				if ((pmrh->flag & FILE_RECORD_FLAG_INUSE) == 0)
				{
					double recover_percent = 0.0;
					if ((pmrh->flag & FILE_RECORD_FLAG_DIR) == 0)
					{
						pattr = f->attribute_header($DATA);
						if (pattr != nullptr)
						{
							if (pattr->FormCode == NON_RESIDENT_FORM)
							{
								std::vector<MFT_DATARUN> dataruns = MFTRecord::read_dataruns(pattr);
								if (check_dataruns_still_valid(f->datasize(), cluster_size, dataruns))
								{
									LONGLONG cluster_needed = 0;
									LONGLONG cluster_reused = 0;

									for (auto& dt : dataruns)
									{
										cluster_needed += dt.length;
										cluster_reused += check_cluster_used(bitmap, &dt);
									}

									recover_percent = 100.0 * ((double)cluster_needed - (double)cluster_reused) / (double)cluster_needed;
								}
							}
							else
							{
								recover_percent = 100.0;
							}
						}
					}
					deleted_files.push_back(std::tuple<DWORD, bool, ULONG64, SYSTEMTIME, double>(pmrh->MFTRecordIndex, (pmrh->flag & FILE_RECORD_FLAG_DIR), f->datasize(), st, recover_percent));
				}
			}
		}
		processed_count += block.second;
		std::cout << "\r[-] Processed data: " << std::to_string(processed_count) << " (" << std::to_string(100 * processed_count / total_size) << "%)";
	}
	std::cout << std::endl;

	std::cout << "[-] Duration      : " << std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - prof_start).count() / 1000 << "ms" << std::endl;

	std::cout << "[+] Deleted Files : " << deleted_files.size() << std::endl;

	if (deleted_files.size() > 0)
	{
		std::cout << std::endl;

		std::shared_ptr<utils::ui::Table> df_table = std::make_shared<utils::ui::Table>();
		df_table->set_interline(true);

		df_table->add_header_line("Id");
		df_table->add_header_line("MFT Index");
		df_table->add_header_line("Type");
		df_table->add_header_line("Filename");
		df_table->add_header_line("Size");
		df_table->add_header_line("Deletion Date");
		df_table->add_header_line("% Recoverable");

		ULONG n = 0;
		for (auto& deleted_file : deleted_files)
		{
			df_table->add_item_line(std::to_string(n++));
			df_table->add_item_line(utils::format::hex(std::get<0>(deleted_file)));
			df_table->add_item_line((std::get<1>(deleted_file) ? "Dir" : " "));
			df_table->add_item_line(get_full_path(std::get<0>(deleted_file), index_to_name, index_to_parent));
			df_table->add_item_line((std::get<1>(deleted_file) ? " " : utils::format::size(std::get<2>(deleted_file))));
			df_table->add_item_line(utils::times::display_systemtime(std::get<3>(deleted_file)));

			std::ostringstream percent;
			percent << std::fixed << std::setprecision(2) << std::get<4>(deleted_file);
			df_table->add_item_line(percent.str());
			df_table->new_line();
		}

		df_table->render(std::cout);
		std::cout << std::endl;
	}
	return 0;
}

int extract_deleted_file(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	std::cout << std::setfill('0');
	utils::ui::title("Extract deleted file from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Reading file record : " << std::to_string(opts->inode) << std::endl;

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(opts->inode);

	auto pattr = record->attribute_header($FILE_NAME);
	if (pattr != nullptr)
	{
		PMFT_RECORD_ATTRIBUTE_FILENAME psubattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
		auto name = std::wstring(psubattr->Name);
		name.resize(psubattr->NameLength);

		std::cout << "[+] Extracting ";
		std::wcout << name;
		std::cout << " to " << opts->out << std::endl;

		std::wstring output(opts->out.begin(), opts->out.end());
		record->data_to_file(output);

		std::cout << "[+] " << record->datasize() << " bytes written" << std::endl;
	}

	return 0;
}

namespace commands
{
	namespace undelete
	{
		int print_deleted_file(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					if (opts->inode != 0 && !opts->out.empty())
					{
						extract_deleted_file(disk, volume, opts);
					}
					else
					{
						print_deleted_files(disk, volume, opts);
					}
				}
			}
			std::cout.flags(flag_backup);
			return 0;
		}
	}
}