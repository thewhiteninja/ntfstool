#pragma once


#include <Windows.h>
#include <string>
#include <map>
#include <vector>

#include "NTFS/ntfs.h"
#include "NTFS/ntfs_mft_record.h"
#include <Utils/btree.h>

class IndexDetails
{
private:
	std::shared_ptr<MFTRecord> _record = nullptr;
	bool _index_large = false;
	std::shared_ptr<node> _VCNtree = nullptr;
	std::map <DWORD64, std::tuple<uint64_t, DWORD, std::vector<std::tuple<uint64_t, std::wstring>>>> _VCNinfo;

	std::vector<std::tuple<uint64_t, std::wstring>> _parse_entries_block(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY pIndexEntry, std::string type);

	std::shared_ptr<node> _parse_entries_tree(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY pIndexEntry, std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> vcnToBlock, uint64_t vcn, std::string type);

public:
	explicit IndexDetails(std::shared_ptr<MFTRecord> pRecord);

	bool is_large() { return _index_large; }

	std::shared_ptr<node> VCNtree() { return _VCNtree; }

	std::map <DWORD64, std::tuple<uint64_t, DWORD, std::vector<std::tuple<uint64_t, std::wstring>>>> VCN_info() { return _VCNinfo; }
};
