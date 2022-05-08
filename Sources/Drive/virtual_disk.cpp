#include "Drive/virtual_disk.h"


std::vector<std::shared_ptr<Disk>> core::win::virtualdisk::list()
{
	std::vector<std::shared_ptr<Disk>> vdisks;

	DWORD  CharCount = 0;
	size_t last_char_index = 0;
	WCHAR  PathNames[2 * MAX_PATH] = L"";
	WCHAR  DeviceName[MAX_PATH] = L"";
	WCHAR  VolumeName[MAX_PATH] = L"";

	HANDLE FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));

	if (FindHandle != INVALID_HANDLE_VALUE)
	{
		for (;;)
		{
			last_char_index = wcslen(VolumeName) - 1;

			if ((VolumeName[0] == L'\\') && (VolumeName[1] == L'\\') && (VolumeName[2] == L'?') && (VolumeName[3] == L'\\') && (VolumeName[last_char_index] == L'\\'))
			{
				VolumeName[last_char_index] = L'\0';
				if (!QueryDosDeviceW(&VolumeName[4], DeviceName, ARRAYSIZE(DeviceName)))
				{
					break;
				}
				VolumeName[last_char_index] = L'\\';

				if (GetVolumePathNamesForVolumeNameW(VolumeName, PathNames, 2 * MAX_PATH, &CharCount))
				{
					if (!wcsncmp(DeviceName, L"\\Device\\VeraCryptVolume", 23))
					{
						vdisks.push_back(std::make_shared<VirtualDisk>(VirtualDiskType::VeraCrypt, VolumeName));
					}
					else if (!wcsncmp(DeviceName, L"\\Device\\TrueCryptVolume", 23))
					{
						vdisks.push_back(std::make_shared<VirtualDisk>(VirtualDiskType::TrueCrypt, VolumeName));
					}
				}

				if (!FindNextVolumeW(FindHandle, VolumeName, ARRAYSIZE(VolumeName)))
				{
					DWORD Error = GetLastError();

					if (Error != ERROR_NO_MORE_FILES)
					{
						break;
					}
					Error = ERROR_SUCCESS;
					break;
				}
			}
			else
			{
				break;
			}
		}

		FindVolumeClose(FindHandle);
	}

	return vdisks;
}

VirtualDisk::VirtualDisk(VirtualDiskType type, PWCHAR volume_name)
{
	_partition_type = PARTITION_STYLE_RAW;

	switch (type)
	{
	case VirtualDiskType::VeraCrypt:
	{
		_product_id = "VeraCrypt";
		_name = "VeraCrypt";
		break;
	}
	case VirtualDiskType::TrueCrypt:
	{
		_product_id = "TrueCrypt";
		_name = "TrueCrypt";
		break;
	}
	case VirtualDiskType::Dummy:
	{
		_product_id = "ImageFile";
		_name = "ImageFile";
		break;
	}
	default:
	{
		_product_id = "Unknown";
		_name = "Unknown";
	}
	}

	if ((type == VirtualDiskType::VeraCrypt) || (type == VirtualDiskType::TrueCrypt))
	{
		size_t volume_name_len = wcslen(volume_name) - 1;
		volume_name[volume_name_len] = L'\0';

		HANDLE hVol = CreateFileW(volume_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hVol != INVALID_HANDLE_VALUE)
		{
			DWORD ior = 0;
			_size = 0;
			if (DeviceIoControl(hVol, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &_geometry, sizeof(DISK_GEOMETRY_EX), &ior, NULL))
			{
				_size = _geometry.DiskSize.QuadPart;
			}

			PARTITION_INFORMATION_EX pex;
			pex.PartitionStyle = PARTITION_STYLE_RAW;
			pex.PartitionNumber = 0;
			pex.StartingOffset.QuadPart = 0;
			pex.PartitionLength.QuadPart = _geometry.DiskSize.QuadPart;

			volume_name[volume_name_len] = L'\\';

			std::shared_ptr<Volume> v = std::make_shared<Volume>(hVol, pex, 0, this, volume_name);
			_volumes.push_back(v);
			CloseHandle(hVol);
		}
	}
}

void VirtualDisk::add_volume_image(std::string filename)
{
	std::wstring wfilename = utils::strings::from_string(filename);

	HANDLE hVol = CreateFileW(wfilename.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hVol != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER fileSize = { 0 };
		_size = 0;
		if (GetFileSizeEx(hVol, &fileSize))
		{
			_size = fileSize.QuadPart;
		}

		PARTITION_INFORMATION_EX pex;
		pex.PartitionStyle = PARTITION_STYLE_RAW;
		pex.PartitionNumber = 0;
		pex.StartingOffset.QuadPart = 0;
		pex.PartitionLength.QuadPart = _size;

		std::shared_ptr<Volume> v = std::make_shared<Volume>(hVol, pex, 0, this, (PWCHAR)(wfilename.c_str()));
		_volumes.push_back(v);
		CloseHandle(hVol);
	}
}

VirtualDisk::~VirtualDisk()
{
}
