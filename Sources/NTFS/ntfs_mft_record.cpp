#include "ntfs_mft_record.h"

#include <memory>

#include "Utils/utils.h"
#include "Utils/buffer.h"
#include "NTFS/ntfs_mft.h"
#include "NTFS/ntfs_reader.h"
#include "NTFS/ntfs_index_entry.h"
#include "Compression/definitions.h"
#include "NTFS/ntfs_explorer.h"

MFTRecord::MFTRecord(PMFT_RECORD_HEADER pRecordHeader, MFT* mft, std::shared_ptr<NTFSReader> reader)
{
	_reader = reader;
	_mft = mft;

	if (pRecordHeader != NULL)
	{
		_record = std::make_shared<Buffer<PMFT_RECORD_HEADER>>(_reader->sizes.record_size);
		memcpy(_record->data(), pRecordHeader, _reader->sizes.record_size);

		apply_fixups(_record->data(), _record->data()->updateOffset, _record->data()->updateNumber);
	}
}

MFTRecord::~MFTRecord()
{
	_record = nullptr;
}

ULONG64 MFTRecord::datasize(std::string stream_name)
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
			return pAttribute->Form.Nonresident.FileSize;
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
							std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttr->recordNumber & 0xffffffffffff);
							return extRecordHeader->datasize();
						}
					}

					offset += pAttr->recordLength;
				}
			}
		}
	}
	return 0;
}

std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> MFTRecord::parse_index_block(std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>> pIndexBlock, DWORD blocksize, DWORD sectorsize)
{
	std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> mapVCNToIndexBlock;

	PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK pIndexSubBlockData = pIndexBlock->data();
	DWORD blockPos = 0;
	while (blockPos < pIndexBlock->size())
	{
		if (RtlCompareMemory(&pIndexSubBlockData->Magic, "INDX", 4) == 4)
		{
			apply_fixups(pIndexSubBlockData, pIndexSubBlockData->OffsetOfUS, pIndexSubBlockData->SizeOfUS);
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
	while (TRUE)
	{
		std::shared_ptr<IndexEntry> e = std::make_shared<IndexEntry>(pIndexEntry, type);

		if (pIndexEntry->Flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_SUBNODE)
		{
			PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK block = vcnToBlock[e->vcn()];
			if ((block != nullptr) && (block->Magic == 0x58444e49))
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
		pIndexEntry = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pIndexEntry, pIndexEntry->Length);
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

				VCNToBlock = parse_index_block(indexBlocks, _reader->sizes.block_size, _reader->boot_record()->bytePerSector);
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

template<typename T>
std::shared_ptr<Buffer<T>> MFTRecord::attribute_data(PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData)
{
	std::shared_ptr<Buffer<T>> ret = nullptr;

	if (pAttributeData->FormCode == RESIDENT_FORM)
	{
		ret = std::make_shared<Buffer<T>>(pAttributeData->Form.Resident.ValueLength);
		memcpy_s(ret->data(), ret->size(), POINTER_ADD(LPBYTE, pAttributeData, pAttributeData->Form.Resident.ValueOffset), pAttributeData->Form.Resident.ValueLength);
	}
	else if (pAttributeData->FormCode == NON_RESIDENT_FORM)
	{
		ULONGLONG readSize = 0;
		ULONGLONG filesize = pAttributeData->Form.Nonresident.FileSize;

		ret = std::make_shared<Buffer<T>>(pAttributeData->Form.Nonresident.AllocatedLength);

		bool err = false;

		std::vector<MFT_DATARUN> runList = read_dataruns(pAttributeData);
		for (const MFT_DATARUN& run : runList)
		{
			if (err) break; //-V547

			if (run.offset == 0)
			{
				for (ULONGLONG i = 0; i < run.length; i++)
				{
					readSize += min(filesize - readSize, _reader->sizes.cluster_size);
				}
			}
			else
			{
				_reader->seek(run.offset * _reader->sizes.cluster_size);

				if (!_reader->read(POINTER_ADD(PBYTE, ret->data(), DWORD(readSize)), static_cast<DWORD>(run.length) * _reader->sizes.cluster_size))
				{
					std::cout << "[!] ReadFile failed" << std::endl;
					err = true;
					break;
				}
				else
				{
					readSize += min(filesize - readSize, static_cast<DWORD>(run.length) * _reader->sizes.cluster_size);
				}
			}
		}
		if (readSize != filesize)
		{
			std::cout << "[!] Invalid read file size" << std::endl;
			ret = nullptr;
		}
	}

	return ret;
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

void MFTRecord::apply_fixups(PVOID buffer, WORD updateOffset, WORD updateSize)
{
	PWORD usarray = POINTER_ADD(PWORD, buffer, updateOffset);
	PWORD sector = (PWORD)buffer;

	for (DWORD i = 1; i < updateSize; i++)
	{
		sector[(_reader->sizes.sector_size - 2) / sizeof(WORD)] = usarray[i];
		sector = POINTER_ADD(PWORD, sector, _reader->sizes.sector_size);
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

ULONG64 MFTRecord::data_to_file(std::wstring dest_filename, std::string stream_name)
{
	ULONG64 written_bytes = 0ULL;

	HANDLE output = CreateFileW(dest_filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (output != INVALID_HANDLE_VALUE)
	{
		for (auto data_block : process_data(stream_name))
		{
			DWORD written_block;
			if (!WriteFile(output, data_block.first, data_block.second, &written_block, NULL))
			{
				std::cout << "[!] WriteFile failed" << std::endl;
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
		std::cout << "[!] CreateFile failed" << std::endl;
	}
	return written_bytes;
}

cppcoro::generator<std::pair<PBYTE, DWORD>> MFTRecord::process_data(std::string stream_name, DWORD block_size)
{
	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData = attribute_header($DATA, stream_name);
	if (pAttributeData != NULL)
	{
		DWORD64 writeSize = 0;
		DWORD fixed_blocksize;

		if (pAttributeData->FormCode == RESIDENT_FORM)
		{
			if (pAttributeData->Form.Resident.ValueOffset + pAttributeData->Form.Resident.ValueLength <= pAttributeData->RecordLength)
			{
				PBYTE data = POINTER_ADD(PBYTE, pAttributeData, pAttributeData->Form.Resident.ValueOffset);
				co_yield std::pair<PBYTE, DWORD>(data, pAttributeData->Form.Resident.ValueLength);
			}
			else
			{
				std::cout << "[!] Invalid size of resident data" << std::endl;
			}
		}
		else if (pAttributeData->FormCode == NON_RESIDENT_FORM)
		{
			bool compressed = pAttributeData->Flags & ATTRIBUTE_FLAG_COMPRESSED;

			bool err = false;
			std::vector<MFT_DATARUN> data_runs = read_dataruns(pAttributeData);

			if (compressed)
			{
				_RtlDecompressBuffer RtlDecompressBuffer = nullptr;

				auto ntdll = GetModuleHandle("ntdll.dll");
				if (ntdll != nullptr)
				{
					RtlDecompressBuffer = (_RtlDecompressBuffer)GetProcAddress(ntdll, "RtlDecompressBuffer");

					if (RtlDecompressBuffer == nullptr)
					{
						std::cout << "[!] Loading RtlDecompressBuffer failed" << std::endl;
						co_return;
					}
				}
				else
				{
					std::cout << "[!] Loading ntdll for runtime functions failed" << std::endl;
					co_return;
				}

				auto compression_unit = max(1ULL << pAttributeData->Form.Nonresident.CompressionUnit, 16);
				auto expansion_factor = 15ULL;

				Buffer<PBYTE> buffer_decompressed(static_cast<DWORD>(static_cast<DWORD>(expansion_factor * 1024ULL * 1024ULL)));
				Buffer<PBYTE> buffer_compressed(static_cast<DWORD>(compression_unit * _reader->sizes.cluster_size));
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
						RtlZeroMemory(buffer_compressed.data(), block_size);
						DWORD64 total_size = run.length * _reader->sizes.cluster_size;
						for (DWORD64 i = 0; i < total_size; i += block_size)
						{
							fixed_blocksize = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, block_size));
							co_yield std::pair<PBYTE, DWORD>(buffer_compressed.data(), fixed_blocksize);
							writeSize += fixed_blocksize;
						}
					}
					else
					{
						_reader->seek(run.offset * _reader->sizes.cluster_size);
						DWORD64 total_size = run.length * _reader->sizes.cluster_size;

						if (!_reader->read(buffer_compressed.data(), static_cast<DWORD>(total_size)))
						{
							std::cout << "[!] ReadFile failed" << std::endl;
							err = true;
							break;
						}

						ULONG Final = 0;
						NTSTATUS status;
						if (status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, buffer_decompressed.data(), buffer_decompressed.size(), buffer_compressed.data(), static_cast<DWORD>(total_size), &Final))
						{
							std::cout << "[!] Decompression failed" << std::endl;
							err = true;
							break;
						}

						if (Final == 0)
						{
							std::cout << "[!] Invalid compressed buffer" << std::endl;
							err = true;
							break;
						}

						co_yield std::pair<PBYTE, DWORD>(buffer_decompressed.data(), Final);
						writeSize += Final;

					}
				}
			}
			else if (pAttributeData->FormCode == NON_RESIDENT_FORM)
			{
				Buffer<PBYTE> buffer(block_size);

				for (const MFT_DATARUN& run : data_runs)
				{
					if (err) break;

					if (run.offset == 0)
					{
						RtlZeroMemory(buffer.data(), block_size);
						DWORD64 total_size = run.length * _reader->sizes.cluster_size;
						for (DWORD64 i = 0; i < total_size; i += block_size)
						{
							fixed_blocksize = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, block_size));
							co_yield std::pair<PBYTE, DWORD>(buffer.data(), fixed_blocksize);
							writeSize += fixed_blocksize;
						}
					}
					else
					{
						_reader->seek(run.offset * _reader->sizes.cluster_size);
						DWORD64 total_size = run.length * _reader->sizes.cluster_size;
						for (DWORD64 i = 0; i < total_size; i += block_size)
						{
							if (!_reader->read(buffer.data(), block_size))
							{
								std::cout << "[!] ReadFile failed" << std::endl;
								err = true;
								break;
							}
							fixed_blocksize = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, block_size));
							co_yield std::pair<PBYTE, DWORD>(buffer.data(), fixed_blocksize);
							writeSize += fixed_blocksize;
						}
					}
				}

				if (writeSize != pAttributeData->Form.Nonresident.FileSize)
				{
					std::cout << "[!] Invalid read file size" << std::endl;
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
				bool is_first_data = true;
				ULONG64 filesize_left = 0;

				while (offset + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= attribute_list_data->size())
				{
					PMFT_RECORD_ATTRIBUTE pAttrListI = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, attribute_list_data->data(), offset);
					if (pAttrListI->typeID == $DATA)
					{
						data_attribute_found = true;

						std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttrListI->recordNumber & 0xffffffffffff);

						if (is_first_data)
						{
							filesize_left = extRecordHeader->datasize();
							is_first_data = false;
						}

						for (std::pair<PBYTE, DWORD> b : extRecordHeader->process_data(stream_name, block_size))
						{
							if (filesize_left < b.second)
							{
								b.second = static_cast<DWORD>(filesize_left);
							}
							co_yield b;
							filesize_left -= b.second;
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
			std::cout << "[!] Unable to find $DATA attribute" << std::endl;
		}
	}
}

std::shared_ptr<Buffer<PBYTE>> MFTRecord::data(std::string stream_name)
{
	std::shared_ptr<Buffer<PBYTE>> ret = nullptr;

	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData = attribute_header($DATA, stream_name);
	if (pAttributeData != NULL)
	{
		return attribute_data<PBYTE>(pAttributeData);
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
					PMFT_RECORD_ATTRIBUTE pAttrListI = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, attribute_list_data->data(), offset);
					if (pAttrListI->typeID == $DATA)
					{
						std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttrListI->recordNumber & 0xffffffffffff);
						return extRecordHeader->data(stream_name);
					}

					offset += pAttrListI->recordLength;
				}
			}
		}
		std::cout << "[!] Unable to find $DATA attribute" << std::endl;
	}
	return ret;
}

std::vector<std::string> MFTRecord::alternate_data_names()
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
		pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pAttribute, pAttribute->RecordLength);
	}

	return ret;
}

