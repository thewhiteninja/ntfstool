#include "ntfs_mft_record.h"

#include <memory>

#include "Utils/utils.h"
#include "Utils/buffer.h"
#include "ntfs_mft.h"
#include "ntfs_index_entry.h"

#include "ntfs_explorer.h"

MFTRecord::MFTRecord(PMFT_RECORD_HEADER pRH, MFT* mft, std::shared_ptr<NTFSReader> reader)
{
	_reader = reader;
	_mft = mft;

	if (pRH != NULL)
	{
		_record.resize(_reader->sizes.record_size);
		memcpy(_record.data(), pRH, _reader->sizes.record_size);

		if (RtlCompareMemory(_record.data()->signature, "FILE", 4) != 4)
		{
			wprintf(L"Invalid MFT record magic (FILE)");
		}
	}
}

ULONG64 MFTRecord::datasize(std::string stream_name)
{
	if (_record.data()->flag & FILE_RECORD_FLAG_DIR)
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
			if (pAttributeList->FormCode == NON_RESIDENT_FORM)
			{
				DWORD filesize = 0;
				if (ULongLongToDWord(pAttributeList->Form.Nonresident.FileSize, &filesize) != S_OK)
				{
					filesize = static_cast<DWORD>(pAttributeList->Form.Nonresident.FileSize);
				}
				auto nr_data = std::make_shared<Buffer<PMFT_RECORD_ATTRIBUTE_HEADER>>(filesize);

				Buffer<PBYTE> cluster(_reader->sizes.cluster_size);
				ULONGLONG readSize = 0;

				bool err = false;
				std::vector<MFT_DATARUN> runList = read_dataruns(pAttributeList);
				for (const MFT_DATARUN& run : runList)
				{
					if (err) break;

					if (run.offset == 0)
					{
						RtlZeroMemory(cluster.data(), _reader->sizes.cluster_size);
						for (ULONGLONG i = 0; i < run.length; i++)
						{
							size_t size = 0;
							if (ULongLongToSizeT(min(filesize - readSize, _reader->sizes.cluster_size), &size) == S_OK)
							{
								memcpy(POINTER_ADD(PBYTE, nr_data->data(), DWORD(readSize)), cluster.data(), size);
								readSize += size;
							}
						}
					}
					else
					{
						_reader->seek(run.offset * _reader->sizes.cluster_size);
						for (ULONGLONG i = 0; i < run.length; i++)
						{
							if (!_reader->read(cluster.data(), _reader->sizes.cluster_size))
							{
								wprintf(L"ReadFile failed");
								err = TRUE;
								break;
							}

							size_t size = 0;
							if (ULongLongToSizeT(min(filesize - readSize, _reader->sizes.cluster_size), &size) == S_OK)
							{
								memcpy(POINTER_ADD(PBYTE, nr_data->data(), DWORD(readSize)), cluster.data(), size);
								readSize += size;
							}
						}
					}
				}
				if (readSize != filesize)
				{
					wprintf(L"Invalid read size");
				}
				else
				{
					DWORD offset = 0;
					while (offset + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= filesize)
					{
						PMFT_RECORD_ATTRIBUTE pAttr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, nr_data->address(), offset);
						if (pAttr->typeID == $DATA)
						{
							std::wstring attr_name = std::wstring(POINTER_ADD(PWCHAR, pAttr, pAttr->nameOffset));
							attr_name.resize(pAttr->nameLength);
							if (((pAttr->nameLength == 0) && (stream_name == "")) || ((pAttr->nameLength > 0) && (stream_name == utils::strings::wide_to_utf8(attr_name))))
							{
								std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttr->recordNumber & 0xffffffffffff);
								return extRecordHeader->datasize();
							}
						}

						offset += pAttr->recordLength;
					}
				}
			}
			else
			{
				PMFT_RECORD_ATTRIBUTE content = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, pAttributeList, pAttributeList->Form.Resident.ValueOffset);
				DWORD p = 0;
				while (p + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= pAttributeList->Form.Resident.ValueLength)
				{
					PMFT_RECORD_ATTRIBUTE pAttr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, content, p);
					if (pAttr->typeID == $DATA)
					{
						std::wstring attr_name = std::wstring(POINTER_ADD(PWCHAR, pAttr, pAttr->nameOffset));
						attr_name.resize(pAttr->nameLength);
						if (((pAttr->nameLength == 0) && (stream_name == "")) || ((pAttr->nameLength > 0) && (stream_name == utils::strings::wide_to_utf8(attr_name))))
						{
							std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttr->recordNumber & 0xffffffffffff);
							return extRecordHeader->datasize();
						}
					}

					p += pAttr->recordLength;
				}
			}
		}
	}
	return 0;
}

std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> parse_index_block(std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>> pIndexBlock, DWORD blocksize, DWORD sectorsize)
{
	std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> mapVCNToIndexBlock;

	PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK pIndexBlockData = pIndexBlock->data();
	if (pIndexBlockData != NULL)
	{
		if (RtlCompareMemory(&pIndexBlockData->Magic, "INDX", 4) != 4)
		{
			wprintf(L"Invalid MFT record magic (FILE)");
		}
		else
		{
			PWORD usnaddr = POINTER_ADD(PWORD, pIndexBlockData, pIndexBlockData->OffsetOfUS);
			PWORD usarray = usnaddr + 1;
			DWORD sectors = blocksize / sectorsize;

			PWORD sector = (PWORD)pIndexBlockData;
			for (DWORD i = 0; i < sectors; i++)
			{
				sector += ((sectorsize >> 1) - 1);
				*sector = usarray[i];
				sector++;
			}

			DWORD64 allocSize = pIndexBlock->size();

			DWORD64 curSize = 0;
			while (curSize < allocSize)
			{
				mapVCNToIndexBlock[pIndexBlockData->VCN] = pIndexBlockData;
				curSize += (DWORD64)pIndexBlockData->AllocEntrySize + 0x18;

				pIndexBlockData = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK, pIndexBlockData, pIndexBlockData->AllocEntrySize + 0x18);
			}
		}
	}
	return mapVCNToIndexBlock;
}

std::vector<std::shared_ptr<IndexEntry>> parse_entries(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY pIndexEntry, std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> vcnToBlock)
{
	std::vector<std::shared_ptr<IndexEntry>> ret;
	while (TRUE)
	{
		std::shared_ptr<IndexEntry> e = std::make_shared<IndexEntry>(pIndexEntry);

		if (pIndexEntry->Flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_SUBNODE)
		{
			PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK block = vcnToBlock[e->vcn()];
			PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY nextEntries = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, block, block->EntryOffset + 0x18);
			std::vector<std::shared_ptr<IndexEntry>> subentries = parse_entries(nextEntries, vcnToBlock);
			ret.insert(ret.end(), subentries.begin(), subentries.end());
		}

		if (pIndexEntry->Flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_LAST)
		{
			if (e->record_number() != 0) ret.push_back(e);
			break;
		}

		ret.push_back(e);
		pIndexEntry = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pIndexEntry, pIndexEntry->Length);
	}
	return ret;
}


std::vector<std::shared_ptr<IndexEntry>> MFTRecord::index()
{
	std::vector<std::shared_ptr<IndexEntry>> ret;
	if (_record.data()->flag & MFT_RECORD_IS_DIRECTORY)
	{
		PMFT_RECORD_ATTRIBUTE_HEADER pAttr = attribute_header($INDEX_ROOT, MFT_ATTRIBUTE_NAME_INDEX);
		if (pAttr != nullptr)
		{
			PMFT_RECORD_ATTRIBUTE_INDEX_ROOT pAttrIndexRoot = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ROOT, pAttr, pAttr->Form.Resident.ValueOffset);
			if (pAttrIndexRoot->AttrType == $I30)
			{
				std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>> indexBlocks = nullptr;
				std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> VCNToBlock;

				if (pAttrIndexRoot->Flags & MFT_ATTRIBUTE_INDEX_ROOT_FLAG_LARGE)
				{
					PMFT_RECORD_ATTRIBUTE_HEADER pAttrAllocation = attribute_header($INDEX_ALLOCATION, MFT_ATTRIBUTE_NAME_INDEX);
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

				ret = parse_entries(POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY, pAttrIndexRoot, pAttrIndexRoot->EntryOffset + 0x10), VCNToBlock);
			}
			else
			{
				wprintf(L"Attribute $INDEX_ROOT is not a $I30 index");
			}
		}
		else
		{
			wprintf(L"Attribute $INDEX_ROOT not found");
		}
	}
	return ret;
}

template<typename T>
std::shared_ptr<Buffer<T>> MFTRecord::attribute_data(PMFT_RECORD_ATTRIBUTE_HEADER attr)
{
	std::shared_ptr<Buffer<T>> ret = nullptr;

	if (attr->FormCode == RESIDENT_FORM)
	{
		ret = std::make_shared<Buffer<T>>(attr->Form.Resident.ValueLength);
		memcpy(ret->data(), POINTER_ADD(LPBYTE, attr, attr->Form.Resident.ValueOffset), attr->Form.Resident.ValueLength);
	}
	else
	{
		ret = std::make_shared<Buffer<T>>(attr->Form.Nonresident.FileSize);

		Buffer<PBYTE> cluster(_reader->sizes.cluster_size);
		ULONGLONG readSize = 0;

		bool err = false;
		std::vector<MFT_DATARUN> runList = read_dataruns(attr);
		for (const MFT_DATARUN& run : runList)
		{
			if (err) break;

			if (run.offset == 0)
			{
				RtlZeroMemory(cluster.data(), _reader->sizes.cluster_size);
				for (ULONGLONG i = 0; i < run.length; i++)
				{
					size_t size = 0;
					if (ULongLongToSizeT(min(attr->Form.Nonresident.FileSize - readSize, _reader->sizes.cluster_size), &size) == S_OK)
					{
						memcpy(POINTER_ADD(PBYTE, ret->data(), DWORD(readSize)), cluster.data(), size);
						readSize += size;
					}
				}
			}
			else
			{
				_reader->seek(run.offset * _reader->sizes.cluster_size);
				for (ULONGLONG i = 0; i < run.length; i++)
				{
					if (!_reader->read(cluster.data(), _reader->sizes.cluster_size))
					{
						wprintf(L"ReadFile failed");
						err = TRUE;
						break;
					}

					size_t size = 0;
					if (ULongLongToSizeT(min(attr->Form.Nonresident.FileSize - readSize, _reader->sizes.cluster_size), &size) == S_OK)
					{
						memcpy(POINTER_ADD(PBYTE, ret->data(), DWORD(readSize)), cluster.data(), size);
						readSize += size;
					}
				}
			}
		}
		if (readSize != attr->Form.Nonresident.FileSize)
		{
			wprintf(L"Invalid read size");
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

PMFT_RECORD_ATTRIBUTE_HEADER MFTRecord::attribute_header(DWORD type, std::string name, int index)
{
	PMFT_RECORD_ATTRIBUTE_HEADER pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, _record.data(), _record.data()->attributeOffset);
	while ((pAttribute->TypeCode != $END) && (pAttribute->RecordLength > 0))
	{
		if (pAttribute->TypeCode == type)
		{
			if (pAttribute->NameLength == 0)
			{
				if ((name == "") && (index == 0)) return pAttribute;
				else index--;
			}
			else
			{
				std::wstring attr_name = std::wstring(POINTER_ADD(PWCHAR, pAttribute, pAttribute->NameOffset));
				attr_name.resize(pAttribute->NameLength);
				if ((utils::strings::wide_to_utf8(attr_name) == name) && (index == 0)) return pAttribute;
				else index--;
			}
		}
		pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pAttribute, pAttribute->RecordLength);
	}
	return nullptr;
}

bool MFTRecord::copy_data_to_file(std::wstring filename, std::string stream_name)
{
	bool ret = false;

	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeList = attribute_header($ATTRIBUTE_LIST);
	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData = attribute_header($DATA, stream_name);

	HANDLE output = CreateFileW(filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (output != INVALID_HANDLE_VALUE)
	{
		if (pAttributeData != NULL)
		{
			ULONGLONG writeSize = 0;
			if (pAttributeData->FormCode == RESIDENT_FORM)
			{
				if (pAttributeData->Form.Resident.ValueOffset + pAttributeData->Form.Resident.ValueLength <= pAttributeData->RecordLength)
				{
					DWORD written;
					if (WriteFile(output, LPBYTE(pAttributeData) + pAttributeData->Form.Resident.ValueOffset, pAttributeData->Form.Resident.ValueLength, &written, NULL))
					{
						ret = true;
					}
					else
					{
						wprintf(L"WriteFile failed");
					}
					writeSize += written;
				}
				else
				{
					wprintf(L"Invalid size of resident data");
				}
				if (writeSize != pAttributeData->Form.Resident.ValueLength)
				{
					wprintf(L"Invalid written file size");
					ret = false;
				}
			}
			else if (pAttributeData->FormCode == NON_RESIDENT_FORM)
			{
				Buffer<PBYTE> cluster(_reader->sizes.cluster_size);

				bool err = false;
				std::vector<MFT_DATARUN> data_runs = read_dataruns(pAttributeData);
				for (const MFT_DATARUN& run : data_runs)
				{
					if (err) break;

					if (run.offset == 0)
					{
						RtlZeroMemory(cluster.data(), _reader->sizes.cluster_size);
						for (ULONGLONG i = 0; i < run.length; i++)
						{
							DWORD s = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, _reader->sizes.cluster_size));
							DWORD written = 0;
							if (!WriteFile(output, cluster.data(), s, &written, NULL))
							{
								wprintf(L"WriteFile failed");
								err = true;
								break;
							}

							writeSize += written;
						}
					}
					else
					{
						_reader->seek(run.offset * _reader->sizes.cluster_size);
						for (ULONGLONG i = 0; i < run.length; i++)
						{
							if (!_reader->read(cluster.data(), _reader->sizes.cluster_size))
							{
								wprintf(L"ReadFile failed");
								err = true;
								break;
							}

							DWORD s = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, _reader->sizes.cluster_size));
							DWORD written = 0;
							if (!WriteFile(output, cluster.data(), s, &written, NULL))
							{
								wprintf(L"WriteFile failed");
								err = true;
								break;
							}

							writeSize += written;
						}
					}
				}
				if (!err)
				{
					ret = true;
				}
				if (writeSize != pAttributeData->Form.Nonresident.FileSize)
				{
					wprintf(L"Invalid written file size");
					ret = false;
				}
			}
		}
		else if (pAttributeList != NULL)
		{
			if (pAttributeList->FormCode == NON_RESIDENT_FORM)
			{
				PMFT_RECORD_ATTRIBUTE content = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, pAttributeList, pAttributeList->Form.Resident.ValueOffset);
				DWORD p = 0;
				while (p + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= pAttributeList->Form.Resident.ValueLength)
				{
					PMFT_RECORD_ATTRIBUTE pAttr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, content, p);

					if (pAttr->typeID == $DATA)
					{
						std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttr->recordNumber & 0xffffffffffff);
						ret = extRecordHeader->copy_data_to_file(filename, stream_name);
						break;
					}

					p += pAttr->recordLength;
				}
			}
			else
			{
				wprintf(L"Non-resident $Attribute_List is not supported");
			}
		}
		else
		{
			wprintf(L"Unable to find attribute data");
		}
		CloseHandle(output);
	}
	else
	{
		wprintf(L"CreateFile for output file failed");
	}
	return ret;
}

cppcoro::generator<std::pair<PBYTE, DWORD>> MFTRecord::process_data(DWORD blocksize, std::string stream_name)
{
	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeList = attribute_header($ATTRIBUTE_LIST);
	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData = attribute_header($DATA, stream_name);

	if (pAttributeData != NULL)
	{
		ULONGLONG writeSize = 0;
		if (pAttributeData->FormCode == RESIDENT_FORM)
		{
			if (pAttributeData->Form.Resident.ValueOffset + pAttributeData->Form.Resident.ValueLength <= pAttributeData->RecordLength)
			{
				PBYTE data = POINTER_ADD(PBYTE, pAttributeData, pAttributeData->Form.Resident.ValueOffset);
				ULONG len = pAttributeData->Form.Resident.ValueLength;
				for (ULONG pos = 0; pos < len; pos += blocksize)
				{
					co_yield std::pair<PBYTE, DWORD>(POINTER_ADD(PBYTE, data, pos), min(blocksize, len - pos));
				}
			}
			else
			{
				wprintf(L"Invalid size of resident data");
			}
		}
		else if (pAttributeData->FormCode == NON_RESIDENT_FORM)
		{
			Buffer<PBYTE> buffer(blocksize);

			bool err = false;
			std::vector<MFT_DATARUN> data_runs = read_dataruns(pAttributeData);
			for (const MFT_DATARUN& run : data_runs)
			{
				if (err) break;

				if (run.offset == 0)
				{
					RtlZeroMemory(buffer.data(), blocksize);
					ULONGLONG total_size = run.length * _reader->sizes.cluster_size;
					for (ULONGLONG i = 0; i < total_size; i += blocksize)
					{
						DWORD s = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, blocksize));
						co_yield std::pair<PBYTE, DWORD>(buffer.data(), s);
						writeSize += s;
					}
				}
				else
				{
					_reader->seek(run.offset * _reader->sizes.cluster_size);
					ULONGLONG total_size = run.length * _reader->sizes.cluster_size;
					for (ULONGLONG i = 0; i < total_size; i += blocksize)
					{
						if (!_reader->read(buffer.data(), blocksize))
						{
							wprintf(L"ReadFile failed");
							err = true;
							break;
						}
						DWORD s = DWORD(min(pAttributeData->Form.Nonresident.FileSize - writeSize, blocksize));
						co_yield std::pair<PBYTE, DWORD>(buffer.data(), s);
						writeSize += s;
					}
				}
			}
		}
		if (writeSize != pAttributeData->Form.Nonresident.FileSize)
		{
			wprintf(L"Invalid written file size");
		}
	}
	else if (pAttributeList != NULL)
	{
		if (pAttributeList->FormCode == NON_RESIDENT_FORM)
		{
			PMFT_RECORD_ATTRIBUTE content = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, pAttributeList, pAttributeList->Form.Resident.ValueOffset);
			DWORD p = 0;
			while (p + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= pAttributeList->Form.Resident.ValueLength)
			{
				PMFT_RECORD_ATTRIBUTE pAttr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, content, p);

				if (pAttr->typeID == $DATA)
				{
					std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttr->recordNumber & 0xffffffffffff);
					for (std::pair<PBYTE, DWORD>& b : extRecordHeader->process_data(blocksize, stream_name))
					{
						co_yield b;
					}
					break;
				}

				p += pAttr->recordLength;
			}
		}
		else
		{
			wprintf(L"Non-resident $Attribute_List is not supported");
		}
	}
	else
	{
		wprintf(L"Unable to find attribute data");
	}
}

std::shared_ptr<Buffer<PBYTE>> MFTRecord::data(std::string stream_name)
{
	std::shared_ptr<Buffer<PBYTE>> ret = nullptr;

	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeList = attribute_header($ATTRIBUTE_LIST);
	PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData = attribute_header($DATA, stream_name);

	if (pAttributeData != NULL)
	{
		ret = attribute_data<PBYTE>(pAttributeData);
	}
	else if (pAttributeList != NULL)
	{
		if (pAttributeList->FormCode == NON_RESIDENT_FORM)
		{
			PMFT_RECORD_ATTRIBUTE content = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, pAttributeList, pAttributeList->Form.Resident.ValueOffset);
			DWORD p = 0;
			while (p + sizeof(MFT_RECORD_ATTRIBUTE_HEADER) <= pAttributeList->Form.Resident.ValueLength)
			{
				PMFT_RECORD_ATTRIBUTE pAttr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, content, p);
				if (pAttr->typeID == $DATA)
				{
					std::shared_ptr<MFTRecord> extRecordHeader = _mft->record_from_number(pAttr->recordNumber & 0xffffffffffff);
					ret = extRecordHeader->data(stream_name);
					break;
				}
				p += pAttr->recordLength;
			}
		}
		else
		{
			wprintf(L"Non-resident $Attribute_List is not supported");
		}
	}
	else
	{
		wprintf(L"Unable to find attribute data");
	}

	return ret;
}

std::vector<std::string> MFTRecord::alternate_data_names()
{
	std::vector<std::string> ret;

	PMFT_RECORD_ATTRIBUTE_HEADER pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, _record.data(), _record.data()->attributeOffset);
	while (pAttribute->TypeCode != $END)
	{
		if (pAttribute->TypeCode == $DATA)
		{
			if (pAttribute->NameLength != 0)
			{
				std::wstring name = std::wstring(POINTER_ADD(PWCHAR, pAttribute, pAttribute->NameOffset));
				name.resize(pAttribute->NameLength);
				ret.push_back(utils::strings::wide_to_utf8(name));
			}
		}
		pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pAttribute, pAttribute->RecordLength);
	}

	return ret;
}

