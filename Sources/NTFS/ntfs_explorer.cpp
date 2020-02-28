#include "ntfs_explorer.h"

#include "ntfs_mft_record.h"
#include "ntfs_mft.h"

NTFSExplorer::NTFSExplorer(std::wstring volume_name)
{
	_reader = std::make_shared<NTFSReader>(volume_name);
	_MFT = std::make_shared<MFT>(_reader);
}

NTFSExplorer::~NTFSExplorer()
{
}

std::vector<std::wstring> NTFSExplorer::list(std::wstring directory)
{
	wprintf(L"Listing directory");

	std::vector<std::wstring> ret;

	std::shared_ptr<MFTRecord> rec = _MFT->record_from_path(directory);
	for (std::shared_ptr<IndexEntry> entry : rec->index())
	{
		ret.push_back(entry->name());
	}

	return ret;
}