#pragma once

#include "Drive/disk.h"

enum class VirtualDiskType { TrueCrypt, VeraCrypt, Dummy };

class VirtualDisk : public Disk
{
private:
public:
	VirtualDisk(VirtualDiskType type, PWCHAR device_name, PWCHAR volume_name);

	void add_volume_image(std::string filename);

	virtual bool is_virtual() const { return true; }

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
