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

#define READ_ATTRIBUTES				0xD0
#define IOCTL_DISK_BASE				FILE_DEVICE_DISK
#define SMART_GET_VERSION			CTL_CODE(IOCTL_DISK_BASE, 0x0020, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SMART_SEND_DRIVE_COMMAND	CTL_CODE(IOCTL_DISK_BASE, 0x0021, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define SMART_RCV_DRIVE_DATA		CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define ID_CMD						0xEC	/* Returns ID sector for ATA*/
#define IDENTIFY_BUFFER_SIZE		512
#define SMART_CYL_LOW				0x4F
#define SMART_CYL_HI				0xC2
#define DRIVE_HEAD_REG				0xA0
#define SMART_CMD					0xB0

#define INDEX_ATTRIB_RAW			5

#pragma pack(push, 1)

typedef struct
{
	BYTE  bDriverError;
	BYTE  bIDEStatus;
	BYTE  bReserved[2];
	DWORD dwReserved[2];
} ST_DRIVERSTAT;

typedef struct
{
	BYTE attributeIndex;
	WORD reserved;
	BYTE value;
	BYTE worst;
	DWORD64 rawValue : 48;
} ST_SMART_ATTRIBUTE, * PST_SMART_ATTRIBUTE;

typedef struct
{
	BYTE attributeIndex;
	BYTE threshold;
	BYTE reserved[10];
} ST_SMART_THRESHOLD, * PST_SMART_THRESHOLD;

typedef struct
{
	DWORD      cBufferSize;
	ST_DRIVERSTAT DriverStatus;
	BYTE       reserved[2];
	ST_SMART_ATTRIBUTE bBuffer[1];
} ST_ATAOUTPARAM_ATTRIBUTES, * PST_ATAOUTPARAM_ATTRIBUTES;

typedef struct
{
	DWORD      cBufferSize;
	ST_DRIVERSTAT DriverStatus;
	BYTE       reserved[2];
	ST_SMART_THRESHOLD bBuffer[1];
} ST_ATAOUTPARAM_THRESHOLDS, * PST_ATAOUTPARAM_THRESHOLDS;

typedef struct
{
	WORD wGenConfig;
	WORD wNumCyls;
	WORD wReserved;
	WORD wNumHeads;
	WORD wBytesPerTrack;
	WORD wBytesPerSector;
	WORD wSectorsPerTrack;
	WORD wVendorUnique[3];
	BYTE sSerialNumber[20];
	WORD wBufferType;
	WORD wBufferSize;
	WORD wECCSize;
	BYTE sFirmwareRev[8];
	BYTE sModelNumber[39];
	WORD wMoreVendorUnique;
	WORD wDoubleWordIO;
	WORD wCapabilities;
	WORD wReserved1;
	WORD wPIOTiming;
	WORD wDMATiming;
	WORD wBS;
	WORD wNumCurrentCyls;
	WORD wNumCurrentHeads;
	WORD wNumCurrentSectorsPerTrack;
	WORD ulCurrentSectorCapacity;
	WORD wMultSectorStuff;
	DWORD ulTotalAddressableSectors;
	WORD wSingleWordDMA;
	WORD wMultiWordDMA;
	BYTE bReserved[127];
}ST_IDSECTOR;

typedef struct
{
	BYTE m_ucAttribIndex;
	DWORD m_dwAttribValue;
	BYTE m_ucValue;
	BYTE m_ucWorst;
	DWORD m_dwThreshold;
}ST_SMART_INFO;

typedef struct
{
	GETVERSIONINPARAMS m_stGVIP;
	ST_IDSECTOR m_stInfo;
	ST_SMART_INFO m_stSmartInfo[256];
	BYTE m_ucSmartValues;
	BYTE m_ucDriveIndex;
	CHAR m_csErrorString[MAX_PATH];
}ST_DRIVE_INFO;

#pragma pack(pop)

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