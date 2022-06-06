#pragma once


#include <Windows.h>

#include <vector>
#include <string>
#include <memory>

#include <filesystem>

#include "ntfs.h"
#include "ntfs_mft_record.h"
#include "ntfs_explorer.h"
#include "Utils/utils.h"
#include "Utils/buffer.h"

class MFT
{
private:
	std::shared_ptr<MFTRecord> _record;

	std::shared_ptr<NTFSReader> _reader;

	std::vector<MFT_DATARUN> _dataruns;

public:
	explicit MFT(std::shared_ptr<NTFSReader> reader);
	~MFT();

	std::shared_ptr<MFTRecord> record() { return _record; }

	std::shared_ptr<MFTRecord> record_from_path(std::string path, ULONG64 directory_record_number = ROOT_FILE_NAME_INDEX_NUMBER);

	std::shared_ptr<MFTRecord> record_from_number(ULONG64 record_number);

	std::vector<std::tuple<std::wstring, ULONG64>> list(std::string path, bool directory = true, bool files = true);
};