#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include <Drive/volume.h>
#include <NTFS/ntfs.h>
#include <NTFS/ntfs_reader.h>
#include <NTFS/ntfs_mft_record.h>
#include <NTFS/ntfs_explorer.h>

class PathFinder {

private:
	std::unordered_map<DWORD64, DWORD64> _map_parent;
	std::unordered_map<DWORD64, std::string> _map_name;

public:
	PathFinder(std::shared_ptr<Volume> volume);

	std::string get_file_path(std::string filename, DWORD64 parent_inode);

	size_t count() { return _map_name.size(); }
};
