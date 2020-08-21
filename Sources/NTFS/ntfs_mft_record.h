#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <memory>
#include <map>
#include <functional>

#include "ntfs.h"
#include "Utils/buffer.h"

#include "ntfs_index_entry.h"

#include "ntfs_reader.h"

#include <cppcoro/generator.hpp>

#include <memory>
#include <functional>

class MFTRecord
{
private:
	std::shared_ptr<NTFSReader> _reader;

	std::shared_ptr<Buffer<PMFT_RECORD_HEADER>> _record = nullptr;

	MFT* _mft = nullptr;

	void apply_fixups(PVOID buffer, WORD updateOffset, WORD updateSize);

	std::map<DWORD64, PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK> parse_index_block(std::shared_ptr<Buffer<PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK>> pIndexBlock, DWORD blocksize, DWORD sectorsize);

public:

	MFTRecord(PMFT_RECORD_HEADER pRH, MFT* mft, std::shared_ptr<NTFSReader> reader);
	~MFTRecord();

	PMFT_RECORD_HEADER header() { return _record->data(); }

	PMFT_RECORD_ATTRIBUTE_HEADER attribute_header(DWORD type, std::string name = "", int index = 0);

	template < typename T >
	std::shared_ptr<Buffer<T>> attribute_data(PMFT_RECORD_ATTRIBUTE_HEADER attr);

	ULONG64 datasize(std::string stream_name = "");

	std::shared_ptr<Buffer<PBYTE>> data(std::string stream_name = "");

	ULONG64 data_to_file(std::wstring dest_filename, std::string stream_name = "");

	cppcoro::generator<std::pair<PBYTE, DWORD>> process_data(std::string stream_name = "", DWORD blocksize = 1024 * 1024);

	std::vector<std::string> alternate_data_names();

	std::vector<std::shared_ptr<IndexEntry>> index();

	static std::vector<MFT_DATARUN> read_dataruns(PMFT_RECORD_ATTRIBUTE_HEADER pAttribute);
};