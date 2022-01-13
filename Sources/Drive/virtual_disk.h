#pragma once

#include "Drive/disk.h"

enum class VirtualDiskType { TrueCrypt, VeraCrypt };

class VirtualDisk : public Disk
{
private:
public:
	VirtualDisk(VirtualDiskType type, PWCHAR device_name, PWCHAR volume_name);
	~VirtualDisk();

};


namespace core
{
	namespace win
	{
		namespace virtualdisk
		{
			std::vector<std::shared_ptr<Disk>> list();
		}
	}
}
