#pragma once

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
protected:
	DWORD				_index = DISK_INDEX_IMAGE;
	std::string			_name;
	DWORD64				_size = 0;
	DWORD				_partition_type = PARTITION_STYLE_MBR;
	DISK_GEOMETRY_EX	_geometry = { 0 };

	MBR					_mbr = { 0 };
	std::vector<EBR>	_ebrs;
	bool				_protective_mbr;

	GPT_HEADER			_gpt = { 0 };
	std::vector<GPT_PARTITION_ENTRY> _gpt_entries;

	std::string         _vendor_id;
	std::string         _product_id;
	std::string         _product_version;
	std::string         _serial_number;
	bool				_is_ssd = false;
	std::vector<std::shared_ptr<Volume>>	_volumes;

	void _get_mbr(HANDLE h);

	void _get_gpt(HANDLE h);

	void _get_info_using_ioctl(HANDLE h);

	void _get_volumes(HANDLE h);

public:
	Disk() {};

	Disk(HANDLE h, int index);

	Disk(HANDLE h, std::string filename);

	DWORD index()								const { return _index; };
	void set_index(DWORD index) { _index = index; }
	std::string name()							const { return _name; };
	std::string vendor_id()						const { return _vendor_id; };
	std::string product_id()					const { return _product_id; };
	std::string product_version()				const { return _product_version; };
	std::string serial_number()					const { return _serial_number; };
	bool has_protective_mbr()					const { return _protective_mbr; }
	DWORD64 size()								const { return _size; };
	DWORD partition_type()						const { return _partition_type; };
	virtual bool is_virtual()					const { return false; }

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