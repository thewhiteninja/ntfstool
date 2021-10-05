#include "Utils/index_details.h"

#include <map>
#include <memory>

#include "Utils/utils.h"



IndexDetails::IndexDetails(std::shared_ptr<MFTRecord> pMFT)
{
	_record = pMFT;

	if (pMFT == nullptr)
	{
		return;
	}

	std::string type = MFT_ATTRIBUTE_INDEX_FILENAME;
	PMFT_RECORD_ATTRIBUTE_HEADER pAttr = pMFT->attribute_header($INDEX_ROOT, type);
	if (pAttr == nullptr)
	{
		type = MFT_ATTRIBUTE_INDEX_REPARSE;
		pAttr = pMFT->attribute_header($INDEX_ROOT, type);
	}

	if (pAttr != nullptr)
	{
		PMFT_RECORD_ATTRIBUTE_INDEX_ROOT pAttrIndexRoot = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ROOT, pAttr, pAttr->Form.Resident.ValueOffset);

		std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>> indexBlocks = nullptr;

		if (pAttrIndexRoot->Flags & MFT_ATTRIBUTE_INDEX_ROOT_FLAG_LARGE)
		{
			_index_large = true;
			std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> vcnToBlock;

			PMFT_RECORD_ATTRIBUTE_HEADER pAttrAllocation = pMFT->attribute_header($INDEX_ALLOCATION, type);
			if (pAttrAllocation != nullptr)
			{
				indexBlocks = pMFT->attribute_data<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>(pAttrAllocation);

				PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK pIndexSubBlockData = indexBlocks->data();
				DWORD IndexSubBlockDataSize = indexBlocks->size();
				DWORD blockPos = 0;
				while (blockPos < indexBlocks->size())
				{
					if (pIndexSubBlockData->Magic == MAGIC_INDX)
					{
						pMFT->apply_fixups(pIndexSubBlockData, IndexSubBlockDataSize - blockPos, pIndexSubBlockData->OffsetOfUS, pIndexSubBlockData->SizeOfUS);
						vcnToBlock[pIndexSubBlockData->VCN] = pIndexSubBlockData;

						auto entries = _parse_entries_block(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pIndexSubBlockData, pIndexSubBlockData->EntryOffset + 0x18), type);
						auto offset = reinterpret_cast<uint64_t>(vcnToBlock[pIndexSubBlockData->VCN]) - reinterpret_cast<uint64_t>(vcnToBlock[0]);

						_VCNinfo[pIndexSubBlockData->VCN] = std::tuple<uint64_t, DWORD, std::vector<std::tuple<uint64_t, std::wstring>>>(pMFT->raw_address(pAttrAllocation, offset), pIndexSubBlockData->AllocEntrySize + 0x18, entries);
					}

					blockPos += pIndexSubBlockData->AllocEntrySize + 0x18;
					pIndexSubBlockData = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK, pIndexSubBlockData, pIndexSubBlockData->AllocEntrySize + 0x18);
				}

				_VCNtree = _parse_entries_tree(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pAttrIndexRoot, pAttrIndexRoot->EntryOffset + 0x10), vcnToBlock, 0, type);

			}
			else
			{
				wprintf(L"Attribute $INDEX_ALLOCATION not found");
			}
		}
		else
		{
			_index_large = false;
			uint64_t index_offset = reinterpret_cast<uint64_t>(pAttrIndexRoot) - reinterpret_cast<uint64_t>(pMFT->header()) + pAttrIndexRoot->EntryOffset + 0x10;
			auto entries = _parse_entries_block(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pAttrIndexRoot, pAttrIndexRoot->EntryOffset + 0x10), type);

			_VCNinfo[0] = std::tuple<uint64_t, DWORD, std::vector<std::tuple<uint64_t, std::wstring>>>(index_offset, pAttrIndexRoot->AllocEntrySize + 0x18, entries);
		}
	}
}

std::vector<std::tuple<uint64_t, std::wstring>> IndexDetails::_parse_entries_block(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY pIndexEntry, std::string type)
{
	std::vector<std::tuple<uint64_t, std::wstring>> ret;
	if (pIndexEntry != nullptr)
	{
		std::vector<std::shared_ptr<IndexEntry>> entries;
		while (TRUE)
		{
			std::shared_ptr<IndexEntry> e = std::make_shared<IndexEntry>(pIndexEntry, type);

			if (pIndexEntry->Flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_LAST)
			{
				if (pIndexEntry->FileReference != 0) entries.push_back(e);
				break;
			}

			entries.push_back(e);

			if (pIndexEntry->Length > 0)
			{
				pIndexEntry = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pIndexEntry, pIndexEntry->Length);
			}
			else
			{
				break;
			}
		}
		for (auto& entry : entries)
		{
			ret.push_back(std::tuple<uint64_t, std::wstring>(entry->record_number(), entry->name()));
		}
	}

	return ret;
}

std::shared_ptr<node> IndexDetails::_parse_entries_tree(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY pIndexEntry, std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> vcnToBlock, uint64_t vcn, std::string type)
{
	std::shared_ptr<node> ret = std::make_shared<node>(vcn);

	if (pIndexEntry != nullptr)
	{
		while (TRUE)
		{
			std::shared_ptr<IndexEntry> e = std::make_shared<IndexEntry>(pIndexEntry, type);
			std::shared_ptr<node> subnodes = nullptr;

			if (pIndexEntry->Flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_SUBNODE)
			{
				PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK block = vcnToBlock[e->vcn()];
				if ((block != nullptr) && (block->Magic == MAGIC_INDX))
				{
					PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY nextEntries = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, block, block->EntryOffset + 0x18);
					subnodes = _parse_entries_tree(nextEntries, vcnToBlock, e->vcn(), type);
				}
			}

			ret->add_item(e, subnodes);

			if (pIndexEntry->Flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_LAST)
			{
				break;
			}

			if (pIndexEntry->Length > 0)
			{
				pIndexEntry = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pIndexEntry, pIndexEntry->Length);
			}
			else
			{
				break;
			}
		}
	}

	return ret;
}


