#pragma once

#include <WinSock2.h>
#include <Windows.h>

#include <set>
#include <string>
#include <memory>
#include <vector>

#include "volume.h"
#include "Drive/mbr_gpt.h"

#define DISK_INDEX_IMAGE			(-1)

class Disk
{
private:
	DWORD				_index;
	std::string			_name;
	DWORD64				_size;
	DWORD				_partition_type;
	DISK_GEOMETRY_EX	_geometry;

	MBR					_mbr;
	std::vector<EBR>	_ebrs;
	bool				_protective_mbr;

	GPT_HEADER			_gpt;
	std::vector<GPT_PARTITION_ENTRY> _gpt_entries;

	std::string         _vendor_id;
	std::string         _product_id;
	std::string         _product_version;
	std::string         _serial_number;
	bool				_is_ssd;
	std::vector<std::shared_ptr<Volume>>	_volumes;

	void _get_mbr(HANDLE h);

	void _get_gpt(HANDLE h);

	void _get_info_using_ioctl(HANDLE h);

	void _get_volumes(HANDLE h);

public:
	Disk(HANDLE h, int index);

	Disk(HANDLE h, std::string filename);

	DWORD index()								const { return _index; };
	std::string name()							const { return _name; };
	std::string vendor_id()						const { return _vendor_id; };
	std::string product_id()					const { return _product_id; };
	std::string product_version()				const { return _product_version; };
	std::string serial_number()					const { return _serial_number; };
	bool has_protective_mbr()						const { return _protective_mbr; }
	DWORD64 size()								const { return _size; };
	DWORD partition_type()						const { return _partition_type; };

	PDISK_GEOMETRY_EX geometry() { return &_geometry; }
	PMBR mbr() { return &_mbr; }
	PGPT_HEADER gpt() { return &_gpt; }
	std::vector<GPT_PARTITION_ENTRY> gpt_entries() { return _gpt_entries; }
	std::vector<EBR> ebrs()						const { return _ebrs; }
	bool is_ssd()								const { return _is_ssd; }

	std::vector<std::shared_ptr<Volume>> volumes()			const { return _volumes; };

	std::shared_ptr<Volume> volumes(DWORD index)	const;

	HANDLE open();
};

namespace core
{
	namespace win
	{
		namespace disks
		{
			std::vector<std::shared_ptr<Disk>> list();

			std::shared_ptr<Disk> by_index(DWORD index);

			std::shared_ptr<Disk> from_image(std::string filename);
		}
	}
}