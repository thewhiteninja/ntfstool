#include "disk.h"
#include "volume.h"
#include "Utils/buffer.h"
#include "Utils/utils.h"
#include "Utils/constant_names.h"

#include <iostream>


std::shared_ptr<Disk> try_add_disk(int i)
{
	wchar_t diskname[MAX_PATH];
	_swprintf_p(diskname, MAX_PATH, L"\\\\.\\PhysicalDrive%d", i);

	HANDLE hDisk = CreateFileW(diskname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hDisk != INVALID_HANDLE_VALUE)
	{
		std::shared_ptr<Disk> d = std::make_shared<Disk>(hDisk, i);
		CloseHandle(hDisk);
		return d;
	}
	return nullptr;
}

namespace core
{
	namespace win
	{
		namespace disks
		{
			std::vector<std::shared_ptr<Disk>> list()
			{
				std::vector<std::shared_ptr<Disk>> disks;
				int i = 0;
				for (i = 0; ; i++)
				{
					std::shared_ptr<Disk> d = try_add_disk(i);
					if (d != nullptr) disks.push_back(d);
					else break;
				}
				int check_more_disk = i + 5;
				for (i = i + 1; i < check_more_disk; i++)
				{
					std::shared_ptr<Disk> d = try_add_disk(i);
					if (d != nullptr) disks.push_back(d);
					else break;
				}

				return disks;
			}

			std::shared_ptr<Disk> by_index(DWORD index)
			{
				return try_add_disk(index);;
			}

			std::shared_ptr<Disk> from_image(std::string filename)
			{
				HANDLE hDisk = CreateFileW(utils::strings::from_string(filename).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
				if (hDisk != INVALID_HANDLE_VALUE)
				{
					std::shared_ptr<Disk> d = std::make_shared<Disk>(hDisk, filename);
					CloseHandle(hDisk);
					return d;
				}
				return nullptr;
			}
		}
	}
}

chs add_chs(chs& a, chs& b)
{
	chs r;
	r.cylinder = a.cylinder + b.cylinder;
	r.head = a.head + b.head;
	r.sector = a.sector + b.sector;
	return r;
}

void Disk::_get_mbr(HANDLE h)
{
	DWORD ior = 0;
	_protective_mbr = false;
	_partition_type = PARTITION_STYLE_RAW;

	LARGE_INTEGER pos;
	pos.QuadPart = (LONGLONG)0;
	LARGE_INTEGER result;
	SetFilePointerEx(h, pos, &result, SEEK_SET);

	if (ReadFile(h, &_mbr, sizeof(MBR), &ior, NULL))
	{
		int n_partitions = 0;
		for (int i = 0; i < 4; i++)
		{
			if (_mbr.partition[i].partition_type != PARTITION_ENTRY_UNUSED) n_partitions++;
		}

		if (n_partitions) _partition_type = PARTITION_STYLE_MBR;

		_protective_mbr = (n_partitions == 1) && (_mbr.partition[0].partition_type == PARTITION_EDI_HEADER);
		if (_protective_mbr) _partition_type = PARTITION_STYLE_GPT;


		for (int i = 0; i < 4; i++) {
			if ((_mbr.partition[i].partition_type == PARTITION_EXTENDED) || (_mbr.partition[i].partition_type == PARTITION_XINT13_EXTENDED))
			{
				EBR curr_ebr = { 0 };

				uint32_t last_lba = _mbr.partition[i].first_sector_lba;
				chs last_first = _mbr.partition[i].first_sector;
				chs last_last = _mbr.partition[i].last_sector;

				pos.QuadPart = (ULONG64)_mbr.partition[i].first_sector_lba * LOGICAL_SECTOR_SIZE;
				SetFilePointerEx(h, pos, &result, SEEK_SET);
				if (ReadFile(h, &curr_ebr, sizeof(EBR), &ior, NULL))
				{
					while (curr_ebr.mbr_signature == 0xAA55)
					{
						curr_ebr.partition[0].first_sector_lba = last_lba + curr_ebr.partition[0].first_sector_lba;
						curr_ebr.partition[0].first_sector = add_chs(last_first, curr_ebr.partition[0].first_sector);
						curr_ebr.partition[0].last_sector = add_chs(last_last, curr_ebr.partition[0].last_sector);

						last_lba = _mbr.partition[i].first_sector_lba + curr_ebr.partition[1].first_sector_lba;
						last_first = add_chs(_mbr.partition[i].first_sector, curr_ebr.partition[1].first_sector);
						last_last = add_chs(_mbr.partition[i].first_sector, curr_ebr.partition[1].first_sector);

						_ebrs.push_back(curr_ebr);

						if (curr_ebr.partition[1].first_sector_lba)
						{
							pos.QuadPart = ((ULONG64)_mbr.partition[i].first_sector_lba + (ULONG64)curr_ebr.partition[1].first_sector_lba) * LOGICAL_SECTOR_SIZE;
							SetFilePointerEx(h, pos, &result, SEEK_SET);
							if (!ReadFile(h, &curr_ebr, sizeof(EBR), &ior, NULL))
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
				break;
			}
		}
	}
}

void Disk::_get_gpt(HANDLE h) {

	DWORD ior = 0;
	LARGE_INTEGER pos;
	LARGE_INTEGER result;

	GPT_HEADER loc_gpt;

	if (_protective_mbr)
	{
		pos.QuadPart = (ULONG64)_mbr.partition[0].first_sector_lba * LOGICAL_SECTOR_SIZE;
		SetFilePointerEx(h, pos, &result, SEEK_SET);

		if (ReadFile(h, &loc_gpt, sizeof(GPT_HEADER), &ior, NULL))
		{
			memcpy(&_gpt, &loc_gpt, 512);

			Buffer<PGPT_PARTITION_ENTRY> pentries(LOGICAL_SECTOR_SIZE);
			for (ULONG64 entries_offset = 0; entries_offset < 128; entries_offset += 4)
			{
				pos.QuadPart = 2 * LOGICAL_SECTOR_SIZE + (entries_offset / 4 * LOGICAL_SECTOR_SIZE);
				SetFilePointerEx(h, pos, &result, SEEK_SET);

				if (ReadFile(h, pentries.data(), LOGICAL_SECTOR_SIZE, &ior, NULL))
				{
					PGPT_PARTITION_ENTRY pentry = nullptr;
					for (int i = 0; i < 4; i++)
					{
						pentry = pentries.data() + i;
						if (IsEqualGUID(pentry->PartitionTypeGUID, PARTITION_ENTRY_UNUSED_GUID)) return;
						else _gpt_entries.push_back(*pentry);
					}
				}
				else {
					break;
				}
			}
		}
	}
}

void Disk::_get_info_using_ioctl(HANDLE h)
{
	// Size
	DWORD ior = 0;
	_size = 0;
	if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &_geometry, sizeof(DISK_GEOMETRY_EX), &ior, NULL))
	{
		_size = _geometry.DiskSize.QuadPart;
	}
	else
	{
		LARGE_INTEGER size;
		if (GetFileSizeEx(h, &size))
		{
			_size = size.QuadPart;
		}
	}

	// SSD?

	_is_ssd = false;
	DWORD bytesReturned = 0;

	STORAGE_PROPERTY_QUERY spq;
	spq.PropertyId = (STORAGE_PROPERTY_ID)StorageDeviceTrimProperty;
	spq.QueryType = PropertyStandardQuery;

	DEVICE_TRIM_DESCRIPTOR dtd = { 0 };
	DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &spq, sizeof(spq), &dtd, sizeof(dtd), &bytesReturned, NULL);

	_is_ssd = (dtd.TrimEnabled == TRUE);

	// Device ID

	DWORD cbBytesReturned = 0;
	std::shared_ptr<Buffer<char*>> buf = std::make_shared<Buffer<char*>>(8192);

	STORAGE_PROPERTY_QUERY query = {};
	query.PropertyId = StorageDeviceProperty;
	query.QueryType = PropertyStandardQuery;

	if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), (LPVOID)buf->data(), buf->size(), &cbBytesReturned, NULL))
	{
		PSTORAGE_DEVICE_DESCRIPTOR descrip = (PSTORAGE_DEVICE_DESCRIPTOR)buf->data();
		if (descrip->VendorIdOffset != 0)
		{
			_vendor_id = std::string((char*)(buf->address() + descrip->VendorIdOffset));

			if (_vendor_id.length() > 0) {
				if (_vendor_id.back() == ',') _vendor_id.pop_back();
			}
		}
		if (descrip->ProductIdOffset != 0)
		{
			_product_id = std::string((char*)(buf->address() + descrip->ProductIdOffset));
		}
		if (descrip->ProductRevisionOffset != 0)
		{
			_product_version = std::string((char*)(buf->address() + descrip->ProductRevisionOffset));
		}
		if (descrip->SerialNumberOffset != 0)
		{
			_serial_number = std::string((char*)(buf->address() + descrip->SerialNumberOffset));
			if (_serial_number.length() > 0) {
				if (_serial_number.back() == '.') _serial_number.pop_back();
			}
			utils::strings::trim(_serial_number);
		}
	}
}

void Disk::_get_volumes(HANDLE h) {
	DWORD partitionsSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + 127 * sizeof(PARTITION_INFORMATION_EX);
	Buffer<PDRIVE_LAYOUT_INFORMATION_EX> partitions(partitionsSize);

	DWORD ior = 0;
	if (_index != DISK_INDEX_IMAGE && DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, (LPVOID)partitions.data(), partitionsSize, &ior, NULL))
	{
		_partition_type = partitions.data()->PartitionStyle;

		for (int iPart = 0; iPart < int(partitions.data()->PartitionCount); iPart++)
		{
			if (partitions.data()->PartitionEntry[iPart].PartitionLength.QuadPart > 0)
			{
				std::shared_ptr<Volume> v = std::make_shared<Volume>(h, partitions.data()->PartitionEntry[iPart], _index, this);
				if (v->name().length() > 0)
				{
					_volumes.push_back(v);
				}
			}
		}
	}
	else
	{
		PMBR pmbr = mbr();
		PGPT_HEADER pgpt = gpt();
		int partition_index = 0;
		if (has_protective_mbr())
		{
			auto entries = gpt_entries();
			for (auto& entry : entries)
			{
				PARTITION_INFORMATION_EX pex;
				pex.PartitionStyle = PARTITION_STYLE_GPT;
				pex.PartitionNumber = partition_index++;
				pex.StartingOffset.QuadPart = (LONGLONG)entry.StartingLBA * 512;
				pex.PartitionLength.QuadPart = (LONGLONG)entry.EndingLBA * 512;
				pex.Gpt.PartitionType = entry.PartitionTypeGUID;
				pex.Gpt.PartitionId = entry.UniquePartitionGUID;
				std::shared_ptr<Volume> v = std::make_shared<Volume>(h, pex, _index, this);
				_volumes.push_back(v);
			}
		}
		else
		{
			for (int i = 0; i < 4; i++) {
				if (pmbr->partition[i].partition_type != 0)
				{
					PARTITION_INFORMATION_EX pex;
					pex.PartitionStyle = PARTITION_STYLE_MBR;
					pex.PartitionNumber = partition_index++;
					pex.StartingOffset.QuadPart = (LONGLONG)pmbr->partition[i].first_sector_lba * 512;
					pex.PartitionLength.QuadPart = (LONGLONG)pmbr->partition[i].sectors * 512;
					pex.Mbr.BootIndicator = pmbr->partition[i].status == 0x80;
					pex.Mbr.PartitionType = pmbr->partition[i].partition_type;

					if (pex.Mbr.PartitionType == 0xf)
					{
						for (const auto& ebr_entry : _ebrs)
						{
							pex.PartitionNumber = partition_index++;
							pex.StartingOffset.QuadPart = (LONGLONG)ebr_entry.partition[0].first_sector_lba * 512;
							pex.PartitionLength.QuadPart = (LONGLONG)ebr_entry.partition[0].sectors * 512;
							pex.Mbr.BootIndicator = ebr_entry.partition[0].status == 0x80;
							pex.Mbr.PartitionType = ebr_entry.partition[0].partition_type;

							std::shared_ptr<Volume> v = std::make_shared<Volume>(h, pex, _index, this);
							_volumes.push_back(v);
						}
					}
					else
					{
						std::shared_ptr<Volume> v = std::make_shared<Volume>(h, pex, _index, this);
						_volumes.push_back(v);
					}
				}
			}
		}
	}
}


Disk::Disk(HANDLE h, int index)
{
	_index = index;
	_name = "\\\\.\\PhysicalDrive" + std::to_string(index);

	_get_mbr(h);

	_get_gpt(h);

	_get_info_using_ioctl(h);

	_get_volumes(h);
}

Disk::Disk(HANDLE h, std::string filename)
{
	_index = DISK_INDEX_IMAGE;
	_name = filename;

	_get_mbr(h);

	_get_gpt(h);

	_get_info_using_ioctl(h);

	_get_volumes(h);
}

std::shared_ptr<Volume> Disk::volumes(DWORD index) const
{
	std::shared_ptr<Volume> volume = nullptr;
	for (unsigned int i = 0; i < _volumes.size(); i++)
	{
		std::shared_ptr<Volume> v = _volumes[i];
		if (v->index() == index)
		{
			volume = v;
			break;
		}
	}
	if (volume == nullptr)
	{
		std::cerr << "[!] Invalid or missing volume index";
	}
	return volume;
}

HANDLE Disk::open()
{
	wchar_t diskname[MAX_PATH];
	_swprintf_p(diskname, MAX_PATH, L"\\\\.\\PhysicalDrive%d", _index);

	return CreateFileW(diskname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
}

