#pragma once


#include <Windows.h>

#include "ntfs_explorer.h"
#include "ntfs_index_entry.h"
#include "ntfs_mft.h"
#include "ntfs_mft_record.h"
#include "ntfs.h"
#include "ntfs_reader.h"

#include "Drive/volume.h"

#include <memory>
#include <vector>

class NTFSExplorer
{
private:
	std::wstring _volume_name;

	std::shared_ptr<MFT> _MFT;

	std::shared_ptr<NTFSReader> _reader;

public:
	explicit NTFSExplorer(std::shared_ptr<Volume> volume);
	~NTFSExplorer();

	std::wstring volume_name() const { return _volume_name; }

	std::shared_ptr<NTFSReader> reader() { return _reader; }

	HANDLE handle() { return _reader->handle(); }

	std::shared_ptr<MFT> mft() { return _MFT; }
};