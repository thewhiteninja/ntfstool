#pragma once


#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <memory>
#include <map>
#include <functional>

#include "ntfs.h"
#include "ntfs_index_entry.h"
#include "ntfs_reader.h"

#include "Utils/buffer.h"
#include "Utils/utils.h"

#include <cppcoro/generator.hpp>

#include <memory>
#include <functional>

#define MAGIC_FILE 0x454C4946
#define MAGIC_INDX 0x58444E49

class MFTRecord
{
private:
	std::shared_ptr<NTFSReader> _reader;

	std::shared_ptr<Buffer<PMFT_RECORD_HEADER>> _record = nullptr;

	MFT* _mft = nullptr;

	std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> _parse_index_block(std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>> pIndexBlock);

	cppcoro::generator<std::pair<PBYTE, DWORD>> _process_data_raw(std::string stream_name = "", DWORD blocksize = 1024 * 1024, bool skip_sparse = false);

public:

	MFTRecord(PMFT_RECORD_HEADER pRH, MFT* mft, std::shared_ptr<NTFSReader> reader);
	~MFTRecord();

	uint64_t raw_address();

	uint64_t raw_address(PMFT_RECORD_ATTRIBUTE_HEADER pAttr, uint64_t offset);

	PMFT_RECORD_HEADER header() { return _record->data(); }

	void apply_fixups(PVOID buffer, DWORD buffer_size, WORD updateOffset, WORD updateSize);

	PMFT_RECORD_ATTRIBUTE_HEADER attribute_header(DWORD type, std::string name = "", int index = 0);

	template<typename T>
	std::shared_ptr<Buffer<T>> attribute_data(PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData, bool real_size = true)
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
			if (real_size)
			{
				ret->shrink(static_cast<DWORD>(filesize));
			}
		}

		return ret;
	}

	std::wstring filename();

	ULONG64 datasize(std::string stream_name = "", bool real_size = true);

	std::shared_ptr<Buffer<PBYTE>> data(std::string stream_name = "", bool real_size = true);

	ULONG64 data_to_file(std::wstring dest_filename, std::string stream_name = "", bool skip_sparse = false);

	cppcoro::generator<std::pair<PBYTE, DWORD>> process_data(std::string stream_name = "", DWORD blocksize = 1024 * 1024, bool skip_sparse = false);

	cppcoro::generator<std::pair<PBYTE, DWORD>> process_virtual_data(std::string stream_name = "", DWORD blocksize = 1024 * 1024, bool skip_sparse = false);

	std::vector<std::string> ads_names();

	std::vector<std::shared_ptr<IndexEntry>> index();

	static bool is_valid(PMFT_RECORD_HEADER pmfth);

	static std::vector<MFT_DATARUN> read_dataruns(PMFT_RECORD_ATTRIBUTE_HEADER pAttribute);
};