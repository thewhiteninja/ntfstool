#include "Drive/virtual_disk.h"


std::vector<std::shared_ptr<Disk>> core::win::virtualdisk::list()
{
	std::vector<std::shared_ptr<Disk>> vdisks;

	DWORD  CharCount = 0;
	size_t Index = 0;
	WCHAR  PathNames[2 * MAX_PATH] = L"";
	WCHAR  DeviceName[MAX_PATH] = L"";
	WCHAR  VolumeName[MAX_PATH] = L"";

	HANDLE FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));

	if (FindHandle != INVALID_HANDLE_VALUE)
	{
		for (;;)
		{
			Index = wcslen(VolumeName) - 1;

			if (VolumeName[0] == L'\\' || VolumeName[1] == L'\\' || VolumeName[2] == L'?' || VolumeName[3] == L'\\' || VolumeName[Index] == L'\\')
			{
				VolumeName[Index] = L'\0';
				if (!QueryDosDeviceW(&VolumeName[4], DeviceName, ARRAYSIZE(DeviceName)))
				{
					break;
				}
				VolumeName[Index] = L'\\';

				if (GetVolumePathNamesForVolumeNameW(VolumeName, PathNames, 2 * MAX_PATH, &CharCount))
				{
					if (!wcsncmp(DeviceName, L"\\Device\\VeraCryptVolume", 23))
					{
						vdisks.push_back(std::make_shared<VirtualDisk>(VirtualDiskType::VeraCrypt, DeviceName, VolumeName));
					}
					else if (!wcsncmp(DeviceName, L"\\Device\\TrueCryptVolume", 23))
					{
						vdisks.push_back(std::make_shared<VirtualDisk>(VirtualDiskType::TrueCrypt, DeviceName, VolumeName));
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

VirtualDisk::VirtualDisk(VirtualDiskType type, PWCHAR device_name, PWCHAR volume_name)
{
	_partition_type = PARTITION_STYLE_RAW;

	switch (type)
	{
	case VirtualDiskType::VeraCrypt:
	{
		_product_id = "VeraCrypt";
		break;
	}
	case VirtualDiskType::TrueCrypt:
	{
		_product_id = "TrueCrypt";
		break;
	}
	default:
	{
		_product_id = "Unknown";
	}
	}

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

VirtualDisk::~VirtualDisk()
{
}
