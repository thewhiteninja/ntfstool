#pragma once

#include <vector>
#include <memory>
#include <NTFS/ntfs_index_entry.h>

class node
{
private:
	uint64_t _vcn;
	std::vector<std::tuple<std::shared_ptr<IndexEntry>, std::shared_ptr<node>>> _items;



public:
	node(uint64_t vcn)
	{
		_vcn = vcn;
	}

	void add_item(std::shared_ptr<IndexEntry> inode, std::shared_ptr<node> subnodes = nullptr)
	{
		_items.push_back(std::tuple<std::shared_ptr<IndexEntry>, std::shared_ptr<node>>(inode, subnodes));
	}

	void print(int level);

	void print();

	uint64_t vcn() { return _vcn; }

	std::vector<std::tuple<std::shared_ptr<IndexEntry>, std::shared_ptr<node>>>& items() { return _items; }

};
