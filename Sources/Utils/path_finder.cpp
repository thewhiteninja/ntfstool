#include "path_finder.h"

PathFinder::PathFinder(std::shared_ptr<Volume> volume)
{

	{
		std::cout << "[+] Loading $MFT records" << std::endl;

		std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(volume);

		_map_name.clear();
		_map_parent.clear();

		std::shared_ptr<MFTRecord> record_mft = explorer->mft()->record_from_number(0);
		if (record_mft == nullptr)
		{
			std::cout << "[!] Error accessing record 0" << std::endl;
			return;
		}
		ULONG64 total_size_mft = record_mft->datasize();
		DWORD record_size = explorer->reader()->sizes.record_size;

		std::shared_ptr<MFTRecord> record = nullptr;

		auto index = 0ULL;
		for (index = 0ULL; index < (total_size_mft / record_size); index++)
		{
			std::cout << "\r[+] Processing $MFT records: " << utils::format::size(index * record_size) << "     ";

			record = explorer->mft()->record_from_number(index);

			if (record == nullptr || !MFTRecord::is_valid(record->header()))
			{
				continue;
			}

			ULONGLONG file_info_parentid = 0;
			PMFT_RECORD_ATTRIBUTE_HEADER pattr = record->attribute_header($FILE_NAME, "", 0);
			if (pattr != nullptr)
			{
				auto pattr_filename = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
				file_info_parentid = pattr_filename->ParentDirectory.SequenceNumber << 48 | pattr_filename->ParentDirectory.FileRecordNumber;
			}

			ULONGLONG file_record_num = record->header()->sequenceNumber;
			file_record_num = file_record_num << 48 | record->header()->MFTRecordIndex;

			_map_parent[file_record_num] = file_info_parentid;
			_map_name[file_record_num] = utils::strings::to_utf8(record->filename());
		}
		std::cout << "\r[+] Processing $MFT records: " << utils::format::size(index * record_size) << "     " << std::endl;
	}
}

std::string PathFinder::get_file_path(std::string filename, DWORD64 parent_inode)
{
	std::string path = filename;

	while ((parent_inode & 0xffffffffffff) != 5)
	{
		auto tmp = _map_parent.find(parent_inode);
		if (tmp != _map_parent.end())
		{
			path = _map_name[parent_inode] + "\\" + path;
			parent_inode = tmp->second;
		}
		else
		{
			break;
		}
	}
	if ((parent_inode & 0xffffffffffff) == 5)
	{
		path = "volume:\\" + path;
	}
	else
	{
		path = "orphan:\\" + path;
	}

	return path;
}
