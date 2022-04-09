#include "ntfs_explorer.h"

#include "ntfs_mft_record.h"
#include "ntfs_mft.h"
#include <Drive\volume.h>
#include <Drive\disk.h>

NTFSExplorer::NTFSExplorer(std::shared_ptr<Volume> volume)
{
	if (volume->disk_index() != DISK_INDEX_IMAGE)
	{
		_reader = std::make_shared<NTFSReader>(utils::strings::from_string(volume->name()));
	}
	else
	{
		auto pdisk = reinterpret_cast<Disk*>(volume->parent());
		if (pdisk->is_virtual())
		{
			_reader = std::make_shared<NTFSReader>(utils::strings::from_string(volume->name()), volume->offset());
		}
		else
		{
			_reader = std::make_shared<NTFSReader>(utils::strings::from_string(reinterpret_cast<Disk*>(volume->parent())->name()), volume->offset());
		}
	}
	_MFT = std::make_shared<MFT>(_reader);
}

NTFSExplorer::~NTFSExplorer()
{
}