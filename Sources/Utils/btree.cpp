#include "Utils/btree.h"
#include <iostream>
#include <Utils/utils.h>

void space(int level = 0)
{
	for (int i = 0; i < level; i++) std::cout << "|     ";
}

void node::print(int level)
{
	space(level - 1);
	std::cout << (level == 0 ? "" : "|---- ") << "VCN: " << _vcn << std::endl;
	for (auto& item : _items)
	{
		auto subnode = std::get<1>(item);
		if (!(std::get<0>(item)->flags() & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_LAST) || level == 0)
		{
			space(level);
			std::cout << "+ " << utils::format::hex6(std::get<0>(item)->record_number()) << ": " << utils::strings::to_utf8(std::get<0>(item)->name()) << std::endl;
		}
		if (subnode != nullptr)
		{
			subnode->print(level + 1);
		}
	}
}

