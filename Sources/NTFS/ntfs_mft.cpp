#include "ntfs_mft.h"
#include "ntfs_mft_record.h"
#include "ntfs_explorer.h"
#include "ntfs_reader.h"

#include <cstring>
#include <iostream>

MFT::MFT(std::shared_ptr<NTFSReader> reader)
{
	_reader = reader;

	_reader->seek(_reader->boot_record()->MFTCluster * _reader->sizes.cluster_size);

	Buffer<PMFT_RECORD_HEADER> rec(_reader->sizes.record_size);
	if (_reader->read(rec.data(), _reader->sizes.record_size))
	{
		_record = std::make_shared<MFTRecord>(rec.data(), this, _reader);
	}
	else
	{
		wprintf(L"ReadFile on MFTRecord[0] failed");
	}
}

MFT::~MFT()
{
}

std::shared_ptr<MFTRecord> MFT::record_from_path(std::filesystem::path path, ULONG64 directory_record_number)
{
	std::vector<std::wstring> parts;

	if (path.root_path() != L"\\")
	{
		std::cout << "Only absolute paths are supported" << std::endl;
		return nullptr;
	}

	for (const auto& part : path)
	{
		parts.push_back(part.generic_wstring());
	}

	std::shared_ptr<MFTRecord> current_dir = record_from_number(directory_record_number);
	std::shared_ptr<MFTRecord> next_dir = nullptr;

	for (size_t i = 1; i < parts.size(); i++)
	{
		bool found = false;
		next_dir = nullptr;
		std::vector<std::shared_ptr<IndexEntry>> index = current_dir->index();
		for (std::shared_ptr<IndexEntry>& entry : index)
		{
			if (entry->name() == parts[i])
			{
				next_dir = record_from_number(entry->record_number());
				found = true;
				break;
			}
		}
		if (!found)
		{
			return nullptr;
		}
		else
		{
			current_dir = next_dir;
		}
	}

	return current_dir;
}

std::shared_ptr<MFTRecord> MFT::record_from_number(ULONG64 record_number)
{
	LONGLONG  sectorOffset = record_number * _reader->sizes.record_size / _reader->boot_record()->bytePerSector;
	DWORD sectorNumber = _reader->sizes.record_size / _reader->boot_record()->bytePerSector;

	std::shared_ptr<Buffer<PMFT_RECORD_HEADER>> buffer = std::make_shared<Buffer<PMFT_RECORD_HEADER>>(_reader->sizes.record_size);

	for (DWORD sector = 0; sector < sectorNumber; sector++)
	{
		ULONGLONG cluster = (sectorOffset + sector) / (_reader->sizes.cluster_size / _reader->boot_record()->bytePerSector);
		LONGLONG vcn = 0LL;
		LONGLONG offset = -1LL;

		PMFT_RECORD_ATTRIBUTE_HEADER pAttributeData = _record->attribute_header($DATA);
		std::vector<MFT_DATARUN> data_runs = MFTRecord::read_dataruns(pAttributeData);
		for (const MFT_DATARUN& run : data_runs)
		{
			if (cluster < vcn + run.length)
			{
				offset = (run.offset + cluster - vcn) * _reader->sizes.cluster_size
					+ (sectorOffset + sector) * _reader->boot_record()->bytePerSector % _reader->sizes.cluster_size;
				break;
			}
			vcn += run.length;
		}
		if (offset == -1LL)
		{
			wprintf(L"Unable to find record offset");
			return nullptr;
		}

		_reader->seek(offset);
		if (!_reader->read(buffer->address() + sector * _reader->boot_record()->bytePerSector, _reader->boot_record()->bytePerSector))
		{
			wprintf(L"ReadFile failed");
			return nullptr;
		}
	}

	PMFT_RECORD_HEADER pHeader = (PMFT_RECORD_HEADER)buffer->data();
	LPWORD update = LPWORD(buffer->address() + pHeader->updateOffset);

	if (LPBYTE(update + pHeader->updateNumber) > LPBYTE(buffer->address() + _reader->sizes.record_size))
	{
		wprintf(L"Invalid update sequence number");
		return nullptr;
	}

	for (int i = 1; i < pHeader->updateNumber; i++)
	{
		*LPWORD(buffer->address() + i * _reader->boot_record()->bytePerSector - 2) = update[i];
	}

	std::shared_ptr<MFTRecord> ret = std::make_shared<MFTRecord>(pHeader, this, _reader);

	return ret;
}