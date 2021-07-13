#include "Utils/btree.h"
#include <iostream>
#include <Utils/utils.h>

void space(int level = 0, bool leaf = true)
{
	if (leaf)
	{
		for (int i = 0; i < level; i++) std::cout << "     ";
	}
	else
	{
		for (int i = 0; i < level - 1; i++) std::cout << "     ";
		std::cout << "|    ";
	}
}

void node::print(int level)
{
	space(level, true);
	std::cout << " \\___ " << "VCN: " << _vcn << std::endl;
	for (auto& item : _items)
	{
		auto subnode = std::get<1>(item);
		auto inode = std::get<0>(item)->record_number();

		if (subnode != nullptr)
		{
			space(level + 1, true);
			std::cout << "|- " << utils::format::hex6(inode) << (inode == 0 ? " (*)" : (": " + utils::strings::to_utf8(std::get<0>(item)->name()))) << std::endl;
			subnode->print(level + 1);
		}
		else
		{
			if (std::get<0>(item)->record_number() != 0 || std::get<0>(item)->name() == L"$MFT")
			{
				space(level + 1, true);
				std::cout << "|- " << utils::format::hex6(inode) << ": " + utils::strings::to_utf8(std::get<0>(item)->name()) << std::endl;
			}
		}
	}
}

void node::print()
{
	std::cout << "Root" << std::endl;
	for (auto& item : _items)
	{
		auto subnode = std::get<1>(item);

		std::cout << "|- " << utils::format::hex6(std::get<0>(item)->record_number()) << ": " << utils::strings::to_utf8(std::get<0>(item)->name()) << std::endl;

		if (subnode != nullptr)
		{
			subnode->print(0);
		}
	}
}

