#pragma once

#include <WinSock2.h>
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
	uint64_t _cluster_size;
	bool _index_large = false;
	std::vector<MFT_DATARUN> _blockDataruns;
	std::shared_ptr<node> _VCNtree = nullptr;
	std::map <DWORD64, std::tuple<uint64_t, DWORD, std::vector<std::tuple<uint64_t, std::wstring>>>> _VCNinfo;

	uint64_t _get_raw_address(uint64_t offset);

public:
	explicit IndexDetails(std::shared_ptr<MFTRecord> pMFT, uint64_t cluster_size);

	bool is_large() { return _index_large; }

	std::vector<MFT_DATARUN>& dataruns() { return _blockDataruns; }

	std::shared_ptr<node> VCNtree() { return _VCNtree; }

	std::map <DWORD64, std::tuple<uint64_t, DWORD, std::vector<std::tuple<uint64_t, std::wstring>>>> VCN_info() { return _VCNinfo; }

	std::vector<std::tuple<uint64_t, std::wstring>> parse_entries_block(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY pIndexEntry, std::string type);

	std::shared_ptr<node> parse_entries_tree(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY pIndexEntry, std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> vcnToBlock, uint64_t vcn, std::string type);


};
