#include "ntfs_mft_record.h"

#include <memory>

#include "Compression/ntdll_defs.h"

#include "Utils/utils.h"
#include "Utils/buffer.h"
#include "NTFS/ntfs_mft.h"
#include "NTFS/ntfs_reader.h"
#include "NTFS/ntfs_index_entry.h"
#include "NTFS/ntfs_explorer.h"
#include <Compression/lznt1.h>
#include <Compression/xpress.h>
#include <Compression/lzx.h>


MFTRecord::MFTRecord(PMFT_RECORD_HEADER pRecordHeader, MFT* mft, std::shared_ptr<NTFSReader> reader)
{
	_reader = reader;
	_mft = mft;

	if (pRecordHeader != NULL)
	{
		_record = std::make_shared<Buffer<PMFT_RECORD_HEADER>>(_reader->sizes.record_size);
		memcpy(_record->data(), pRecordHeader, _reader->sizes.record_size);

		apply_fixups(_record->data(), _record->size(), _record->data()->updateOffset, _record->data()->updateNumber);
	}
}

MFTRecord::~MFTRecord()
{
	_record = nullptr;
}

uint64_t MFTRecord::raw_address()
{
	return _reader->get_volume_offset() + (_reader->boot_record()->MFTCluster * _reader->sizes.cluster_size + (_record->data()->MFTRecordIndex * _reader->sizes.record_size));
}

uint64_t MFTRecord::raw_address(PMFT_RECORD_ATTRIBUTE_HEADER pAttr, uint64_t offset)
{
	for (auto& dt : read_dataruns(pAttr))
	{
		if (offset >= (dt.length * _reader->sizes.cluster_size))
		{
			offset -= (dt.length * _reader->sizes.cluster_size);
		}
		else
		{
			return (dt.offset * _reader->sizes.cluster_size) + offset;
		}
	}
	return 0;
}

ULONG64 MFTRecord::datasize(std::string stream_name, bool real_size)
{
	if (_record->data()->flag & FILE_RECORD_FLAG_DIR)
	{
		return 0;
	}

	PMFT_RECORD_ATTRIBUTE_HEADER pAttribute = attribute_header($DATA, stream_name);
	if (pAttribute != NULL)
	{
		if (pAttribute->FormCode == RESIDENT_FORM)
		{
			return pAttribute->Form.Resident.ValueLength;
		}
		else
		{
			if (real_size) return pAttribute->Form.Nonresident.FileSize;
			else return pAttribute->Form.Nonresident.AllocatedLength;
		}
	}
	else
	{
		PMFT_RECORD_ATTRIBUTE_HEADER pAttributeList = attribute_header($ATTRIBUTE_LIST);
		if (pAttributeList != NULL)
		{
			std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE>> attribute_list_data = attribute_data<PMFT_RECORD_ATTRIBUTE>(pAttributeList);
			if (attribute_list_data != nullptr)
			{
				DWORD offset = 0;
				while (offset + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= attribute_list_data->size())
				{
					PMFT_RECORD_ATTRIBUTE pAttr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, attribute_list_data->data(), offset);
					if (pAttr->typeID == $DATA)
					{
						std::wstring attr_name = std::wstring(POINTER_ADD(PWCHAR, pAttr, pAttr->nameOffset));
						attr_name.resize(pAttr->nameLength);
						if (((pAttr->nameLength == 0) && (stream_name == "")) || ((pAttr->nameLength > 0) && (stream_name == utils::strings::to_utf8(attr_name))))
						{
							if ((pAttr->recordNumber & 0xffffffffffff) != (header()->MFTRecordIndex & 0xffffffffffff))
							{
								std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttr->recordNumber & 0xffffffffffff);
								if (extRecordHeader != nullptr)
								{
									return extRecordHeader->datasize(stream_name, real_size);
								}
								else
								{
									break;
								}
							}
							else
							{
								break;
							}
						}
					}

					if (pAttr->recordLength > 0)
					{
						offset += pAttr->recordLength;
					}
					else
					{
						break;
					}
				}
			}
		}
	}
	return 0;
}

std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> MFTRecord::_parse_index_block(std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>> pIndexBlock)
{
	std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> mapVCNToIndexBlock;

	PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK pIndexSubBlockData = pIndexBlock->data();
	DWORD IndexSubBlockDataSize = pIndexBlock->size();
	DWORD blockPos = 0;
	while (blockPos < pIndexBlock->size())
	{
		if (pIndexSubBlockData->Magic == MAGIC_INDX)
		{
			apply_fixups(pIndexSubBlockData, IndexSubBlockDataSize - blockPos, pIndexSubBlockData->OffsetOfUS, pIndexSubBlockData->SizeOfUS);
			mapVCNToIndexBlock[pIndexSubBlockData->VCN] = pIndexSubBlockData;
		}

		blockPos += pIndexSubBlockData->AllocEntrySize + 0x18;
		pIndexSubBlockData = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK, pIndexSubBlockData, pIndexSubBlockData->AllocEntrySize + 0x18);
	}

	return mapVCNToIndexBlock;
}

std::vector<std::shared_ptr<IndexEntry>> parse_entries(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY pIndexEntry, std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> vcnToBlock, std::string type)
{
	std::vector<std::shared_ptr<IndexEntry>> ret;
	if (pIndexEntry != nullptr)
	{
		while (TRUE)
		{
			std::shared_ptr<IndexEntry> e = std::make_shared<IndexEntry>(pIndexEntry, type);

			if (pIndexEntry->Flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_SUBNODE)
			{
				PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK block = vcnToBlock[e->vcn()];
				if ((block != nullptr) && (block->Magic == MAGIC_INDX))
				{
					PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY nextEntries = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, block, block->EntryOffset + 0x18);
					std::vector<std::shared_ptr<IndexEntry>> subentries = parse_entries(nextEntries, vcnToBlock, type);
					ret.insert(ret.end(), subentries.begin(), subentries.end());
				}
			}

			if (pIndexEntry->Flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_LAST)
			{
				if (pIndexEntry->FileReference != 0) ret.push_back(e);
				break;
			}

			ret.push_back(e);

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

std::wstring MFTRecord::filename()
{
	PMFT_RECORD_ATTRIBUTE_HEADER pattr = attribute_header($FILE_NAME, "");
	if (pattr != nullptr)
	{
		auto pattr_filename = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
		if (pattr_filename->NameType == 2)
		{
			PMFT_RECORD_ATTRIBUTE_HEADER pattr_long = attribute_header($FILE_NAME, "", 1);
			if (pattr_long != nullptr)
			{
				pattr = pattr_long;
			}
		}
	}

	std::wstring filename;

	if (pattr != nullptr)
	{
		PMFT_RECORD_ATTRIBUTE_FILENAME psubattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
		filename = std::wstring(psubattr->Name);
		filename.resize(psubattr->NameLength);
	}

	return filename;
}

std::vector<std::shared_ptr<IndexEntry>> MFTRecord::index()
{
	std::vector<std::shared_ptr<IndexEntry>> ret;

	std::string type = MFT_ATTRIBUTE_INDEX_FILENAME;
	PMFT_RECORD_ATTRIBUTE_HEADER pAttr = attribute_header($INDEX_ROOT, type);
	if (pAttr == nullptr)
	{
		type = MFT_ATTRIBUTE_INDEX_REPARSE;
		pAttr = attribute_header($INDEX_ROOT, type);
	}
	if (pAttr == nullptr)
	{
		PMFT_RECORD_ATTRIBUTE_HEADER pAttributeList = attribute_header($ATTRIBUTE_LIST);
		if (pAttributeList != NULL)
		{
			std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE>> attribute_list_data = attribute_data<PMFT_RECORD_ATTRIBUTE>(pAttributeList);
			if (attribute_list_data != nullptr)
			{
				DWORD offset = 0;
				while (offset + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= attribute_list_data->size())
				{
					PMFT_RECORD_ATTRIBUTE pAttrListI = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, attribute_list_data->data(), offset);
					if (pAttrListI->typeID == $INDEX_ROOT)
					{
						DWORD64 next_inode = pAttrListI->recordNumber & 0xffffffffffff;
						if (next_inode != _record->data()->MFTRecordIndex)
						{
							std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(next_inode);
							return extRecordHeader->index();
						}
					}

					if (pAttrListI->recordLength > 0)
					{
						offset += pAttrListI->recordLength;
					}
					else
					{
						break;
					}
				}
			}
		}
	}

	if (pAttr != nullptr)
	{
		PMFT_RECORD_ATTRIBUTE_INDEX_ROOT pAttrIndexRoot = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ROOT, pAttr, pAttr->Form.Resident.ValueOffset);

		std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>> indexBlocks = nullptr;
		std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> VCNToBlock;

		if (pAttrIndexRoot->Flags & MFT_ATTRIBUTE_INDEX_ROOT_FLAG_LARGE)
		{
			PMFT_RECORD_ATTRIBUTE_HEADER pAttrAllocation = attribute_header($INDEX_ALLOCATION, type);
			if (pAttrAllocation != nullptr)
			{
				indexBlocks = attribute_data<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>(pAttrAllocation);

				VCNToBlock = _parse_index_block(indexBlocks);
			}
			else
			{
				wprintf(L"Attribute $INDEX_ALLOCATION not found");
			}
		}

		ret = parse_entries(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pAttrIndexRoot, pAttrIndexRoot->EntryOffset + 0x10), VCNToBlock, type);
	}

	return ret;
}

bool MFTRecord::is_valid(PMFT_RECORD_HEADER pmfth)
{
	return (
		(memcmp(pmfth->signature, "FILE", 4) == 0) &&
		(pmfth->attributeOffset > 0x30) &&
		(pmfth->attributeOffset < 0x400) &&
		(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pmfth, pmfth->attributeOffset)->TypeCode >= 10) &&
		(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pmfth, pmfth->attributeOffset)->TypeCode <= 100)
		);

}

std::vector<MFT_DATARUN> MFTRecord::read_dataruns(PMFT_RECORD_ATTRIBUTE_HEADER pAttribute)
{
	std::vector<MFT_DATARUN> result;
	LPBYTE runList = POINTER_ADD(LPBYTE, pAttribute, pAttribute->Form.Nonresident.MappingPairsOffset);
	LONGLONG offset = 0LL;

	while (runList[0] != MFT_DATARUN_END)
	{
		int offset_len = runList[0] >> 4;
		int length_len = runList[0] & 0xf;
		runList++;

		ULONGLONG length = 0;
		for (int i = 0; i < length_len; i++)
		{
			length |= (LONGLONG)(runList++[0]) << (i * 8);
		}

		if (offset_len)
		{
			LONGLONG offsetDiff = 0;
			for (int i = 0; i < offset_len; i++)
			{
				offsetDiff |= (LONGLONG)(runList++[0]) << (i * 8);
			}

			if (offsetDiff >= (1LL << ((offset_len * 8) - 1)))
				offsetDiff -= 1LL << (offset_len * 8);

			offset += offsetDiff;
		}

		result.push_back({ offset, length });
	}

	return result;
}

void MFTRecord::apply_fixups(PVOID buffer, DWORD buffer_size, WORD updateOffset, WORD updateSize)
{
	PWORD usarray = POINTER_ADD(PWORD, buffer, updateOffset);
	PWORD sector = (PWORD)buffer;

	DWORD offset = _reader->sizes.sector_size;
	for (DWORD i = 1; i < updateSize; i++)
	{
		if (offset <= buffer_size)
		{
			sector[(offset - 2) / sizeof(WORD)] = usarray[i];
			offset += _reader->sizes.sector_size;
		}
		else
		{
			break;
		}
	}
}

PMFT_RECORD_ATTRIBUTE_HEADER MFTRecord::attribute_header(DWORD type, std::string name, int index)
{
	PMFT_RECORD_ATTRIBUTE_HEADER pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, _record->data(), _record->data()->attributeOffset);

	while ((pAttribute->TypeCode != $END) && (pAttribute->RecordLength > 0))
	{
		if (pAttribute->TypeCode == type)
		{
			std::string attr_name = utils::strings::to_utf8(std::wstring(POINTER_ADD(PWCHAR, pAttribute, pAttribute->NameOffset), pAttribute->NameLength));
			if (attr_name == name)
			{
				if (index == 0)
				{
					return pAttribute;
				}
				else
				{
					index--;
				}
			}
		}
		pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pAttribute, pAttribute->RecordLength);
	}
	return nullptr;
}

ULONG64 MFTRecord::data_to_file(std::wstring dest_filename, std::string stream_name, bool skip_sparse)
{
	ULONG64 written_bytes = 0ULL;

	HANDLE output = CreateFileW(dest_filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (output != INVALID_HANDLE_VALUE)
	{
		for (auto& data_block : process_data(stream_name, 1024 * 1024, skip_sparse))
		{
			DWORD written_block;
			if (!WriteFile(output, data_block.first, data_block.second, &written_block, NULL))
			{
				std::cout << "[!] WriteFile failed (0x" << utils::format::hex(GetLastError()) << ")" << std::endl;
				break;
			}
			else
			{
				written_bytes += written_block;
			}
		}
		CloseHandle(output);
	}
	else
	{
		std::cout << "[!] CreateFile failed (0x" << utils::format::hex(GetLastError()) << ")" << std::endl;
	}
	return written_bytes;
}

cppcoro::generator<std::pair<PBYTE, DWORD>> MFTRecord::_process_data_raw(std::string stream_name, DWORD block_size, bool skip_sparse)
{
	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData = attribute_header($DATA, stream_name);
	if (pAttributeData != NULL)
	{
		DWORD64 writeSize = 0;
		DWORD64 fixed_blocksize;

		if (pAttributeData->FormCode == RESIDENT_FORM)
		{
			if (pAttributeData->Form.Resident.ValueOffset + pAttributeData->Form.Resident.ValueLength <= pAttributeData->RecordLength)
			{
				PBYTE data = POINTER_ADD(PBYTE, pAttributeData, pAttributeData->Form.Resident.ValueOffset);
				for (DWORD offset = 0; offset < pAttributeData->Form.Resident.ValueLength; offset += block_size)
				{
					co_yield std::pair<PBYTE, DWORD>(data + offset, min(block_size, pAttributeData->Form.Resident.ValueLength - offset));
				}
			}
			else
			{
				std::cout << "[!] Invalid size of resident data" << std::endl;
			}
		}
		else if (pAttributeData->FormCode == NON_RESIDENT_FORM)
		{
			bool err = false;
			std::vector<MFT_DATARUN> data_runs = read_dataruns(pAttributeData);

			if (pAttributeData->Flags & ATTRIBUTE_FLAG_COMPRESSED)
			{
				auto expansion_factor = 0x10ULL;

				LONGLONG last_offset = 0;

				for (const MFT_DATARUN& run : data_runs)
				{
					if (err) break; //-V547

					if (last_offset == run.offset) // Padding run
					{
						continue;
					}
					last_offset = run.offset;

					if (run.offset == 0)
					{
						Buffer<PBYTE> buffer_decompressed(static_cast<DWORD>(block_size));

						RtlZeroMemory(buffer_decompressed.data(), block_size);
						DWORD64 total_size = run.length * _reader->sizes.cluster_size;
						for (DWORD64 i = 0; i < total_size; i += block_size)
						{
							fixed_blocksize = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, block_size));
							co_yield std::pair<PBYTE, DWORD>(buffer_decompressed.data(), static_cast<DWORD>(fixed_blocksize));
							writeSize += fixed_blocksize;
						}
					}
					else
					{
						_reader->seek(run.offset * _reader->sizes.cluster_size);
						DWORD64 total_size = run.length * _reader->sizes.cluster_size;

						std::shared_ptr<Buffer<PBYTE>> buffer_compressed = std::make_shared<Buffer<PBYTE>>(static_cast<DWORD>(total_size));
						if (!_reader->read(buffer_compressed->data(), static_cast<DWORD>(total_size)))
						{
							std::cout << "[!] ReadFile compressed failed" << std::endl;
							err = true;
							break;
						}

						if (run.length > 0x10) // Uncompressed
						{
							co_yield std::pair<PBYTE, DWORD>(buffer_compressed->data(), buffer_compressed->size());
							writeSize += buffer_compressed->size();
						}
						else
						{
							std::shared_ptr<Buffer<PBYTE>> buffer_decompressed = std::make_shared<Buffer<PBYTE>>(static_cast<DWORD>(total_size * expansion_factor));

							DWORD final_size = 0;
							int dec_status = decompress_lznt1(buffer_compressed, buffer_decompressed, &final_size);

							if (!dec_status)
							{
								co_yield std::pair<PBYTE, DWORD>(buffer_decompressed->data(), final_size);
								writeSize += final_size;
							}
							else
							{
								break;
							}
						}
					}
				}
			}
			else if (stream_name == "WofCompressedData")
			{
				DWORD window_size = 0;
				DWORD is_xpress_compressed = true;

				PMFT_RECORD_ATTRIBUTE_HEADER pAttributeHeaderRP = attribute_header($REPARSE_POINT);
				if (pAttributeHeaderRP != NULL)
				{
					auto pAttributeRP = attribute_data<PMFT_RECORD_ATTRIBUTE_REPARSE_POINT>(pAttributeHeaderRP);
					if (pAttributeRP->data()->ReparseTag == IO_REPARSE_TAG_WOF)
					{
						switch (pAttributeRP->data()->WindowsOverlayFilterBuffer.CompressionAlgorithm)
						{
						case 0: window_size = 4 * 1024; is_xpress_compressed = true; break;
						case 1: window_size = 32 * 1024; is_xpress_compressed = false; break;
						case 2: window_size = 8 * 1024; is_xpress_compressed = true; break;
						case 3: window_size = 16 * 1024; is_xpress_compressed = true; break;
						default:
							window_size = 0;
						}
					}
				}

				if (window_size == 0)
				{
					co_return;
				}

				std::shared_ptr<Buffer<PBYTE>> buffer_compressed = data(stream_name);
				std::shared_ptr<Buffer<PBYTE>> buffer_decompressed = std::make_shared<Buffer<PBYTE>>(datasize("", false));

				DWORD final_size = static_cast<DWORD>(datasize());
				int dec_status = 0;

				if (is_xpress_compressed)
				{
					decompress_xpress(buffer_compressed, buffer_decompressed, window_size, final_size);
				}
				else
				{
					decompress_lzx(buffer_compressed, buffer_decompressed, window_size);
				}

				if (!dec_status)
				{
					co_yield std::pair<PBYTE, DWORD>(buffer_decompressed->data(), buffer_decompressed->size());
					writeSize += buffer_decompressed->size();
				}
			}
			else
			{
				Buffer<PBYTE> buffer(block_size);

				for (const MFT_DATARUN& run : data_runs)
				{
					if (err) break;

					if (run.offset == 0)
					{
						if (!skip_sparse)
						{
							RtlZeroMemory(buffer.data(), block_size);
							DWORD64 total_size = run.length * _reader->sizes.cluster_size;
							for (DWORD64 i = 0; i < total_size; i += block_size)
							{
								fixed_blocksize = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, block_size));
								co_yield std::pair<PBYTE, DWORD>(buffer.data(), static_cast<DWORD>(fixed_blocksize));
								writeSize += fixed_blocksize;
							}
						}
					}
					else
					{
						_reader->seek(run.offset * _reader->sizes.cluster_size);
						DWORD64 total_size = run.length * _reader->sizes.cluster_size;
						DWORD64 read_block_size = static_cast<DWORD>(min(block_size, total_size));
						for (DWORD64 i = 0; i < total_size; i += read_block_size)
						{
							if (!_reader->read(buffer.data(), static_cast<DWORD>(read_block_size)))
							{
								std::cout << "[!] ReadFile failed" << std::endl;
								err = true;
								break;
							}
							read_block_size = min(read_block_size, total_size - i);
							fixed_blocksize = read_block_size;
							co_yield std::pair<PBYTE, DWORD>(buffer.data(), static_cast<DWORD>(fixed_blocksize));
							writeSize += fixed_blocksize;
						}
					}
				}
			}
		}
	}
	else
	{
		bool data_attribute_found = false;

		PMFT_RECORD_ATTRIBUTE_HEADER pAttributeList = attribute_header($ATTRIBUTE_LIST);
		if (pAttributeList != NULL)
		{
			std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE>> attribute_list_data = attribute_data<PMFT_RECORD_ATTRIBUTE>(pAttributeList);
			if (attribute_list_data != nullptr)
			{
				DWORD offset = 0;

				while (offset + sizeof(MFT_RECORD_ATTRIBUTE) <= attribute_list_data->size())
				{
					PMFT_RECORD_ATTRIBUTE pAttrListI = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, attribute_list_data->data(), offset);
					if (pAttrListI->typeID == $DATA)
					{
						data_attribute_found = true;

						DWORD64 next_inode = pAttrListI->recordNumber & 0xffffffffffff;
						if (next_inode != _record->data()->MFTRecordIndex)
						{
							std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttrListI->recordNumber & 0xffffffffffff);
							for (std::pair<PBYTE, DWORD> b : extRecordHeader->_process_data_raw(stream_name, block_size, skip_sparse))
							{
								co_yield b;
							}
						}
					}

					offset += pAttrListI->recordLength;

					if (pAttrListI->recordLength == 0)
					{
						break;
					}
				}
			}
		}

		if (!data_attribute_found)
		{
			std::cout << "[!] Unable to find corresponding $DATA attribute" << std::endl;
		}
	}
}

cppcoro::generator<std::pair<PBYTE, DWORD>> MFTRecord::process_data(std::string stream_name, DWORD block_size, bool skip_sparse)
{
	ULONG64 final_datasize = datasize(stream_name, true);
	bool check_size = final_datasize != 0; // ex: no real size for usn

	for (auto& block : _process_data_raw(stream_name, block_size, skip_sparse))
	{
		if (block.second > final_datasize && check_size)
		{
			block.second = static_cast<DWORD>(final_datasize);
		}

		co_yield block;

		if (check_size)
		{
			final_datasize -= block.second;
		}
	}
}

cppcoro::generator<std::pair<PBYTE, DWORD>> MFTRecord::process_virtual_data(std::string stream_name, DWORD block_size, bool skip_sparse)
{
	ULONG64 final_datasize = datasize(stream_name, false);
	bool check_size = final_datasize != 0; // ex: no real size for usn

	for (auto& block : _process_data_raw(stream_name, block_size, skip_sparse))
	{
		if (block.second > final_datasize && check_size)
		{
			block.second = static_cast<DWORD>(final_datasize);
		}

		co_yield block;

		if (check_size)
		{
			final_datasize -= block.second;
		}
	}
}

std::shared_ptr<Buffer<PBYTE>> MFTRecord::data(std::string stream_name, bool real_size)
{
	std::shared_ptr<Buffer<PBYTE>> ret = nullptr;

	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData = attribute_header($DATA, stream_name);
	if (pAttributeData != NULL)
	{
		return attribute_data<PBYTE>(pAttributeData, real_size);
	}
	else
	{
		PMFT_RECORD_ATTRIBUTE_HEADER pAttributeList = attribute_header($ATTRIBUTE_LIST);
		if (pAttributeList != NULL)
		{
			std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE>> attribute_list_data = attribute_data<PMFT_RECORD_ATTRIBUTE>(pAttributeList, real_size);
			if (attribute_list_data != nullptr)
			{
				DWORD offset = 0;
				while (offset + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= attribute_list_data->size())
				{
					PMFT_RECORD_ATTRIBUTE pAttrListI = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, attribute_list_data->data(), offset);
					if (pAttrListI->typeID == $DATA)
					{
						std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttrListI->recordNumber & 0xffffffffffff);
						return extRecordHeader->data(stream_name);
					}

					if (pAttrListI->recordLength > 0)
					{
						offset += pAttrListI->recordLength;
					}
					else
					{
						break;
					}
				}
			}
		}
		std::cout << "[!] Unable to find $DATA attribute" << std::endl;
	}
	return ret;
}

std::vector<std::string> MFTRecord::ads_names()
{
	std::vector<std::string> ret;

	PMFT_RECORD_ATTRIBUTE_HEADER pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, _record->data(), _record->data()->attributeOffset);
	while (pAttribute->TypeCode != $END)
	{
		if (pAttribute->TypeCode == $DATA)
		{
			if (pAttribute->NameLength != 0)
			{
				std::wstring name = std::wstring(POINTER_ADD(PWCHAR, pAttribute, pAttribute->NameOffset));
				name.resize(pAttribute->NameLength);
				ret.push_back(utils::strings::to_utf8(name));
			}
		}

		if (pAttribute->RecordLength > 0)
		{
			pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pAttribute, pAttribute->RecordLength);
		}
		else
		{
			break;
		}

	}

	return ret;
}
