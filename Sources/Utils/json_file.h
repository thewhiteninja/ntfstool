#pragma once

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <map>

#include <nlohmann/json.hpp>

#include "Utils/buffer.h"
#include "Utils/utils.h"
#include "Utils/formatted_file.h"

class JSONFile : public FormatteddFile
{
protected:
	std::ofstream _file;
	nlohmann::json _current_item;
	bool _first = true;

public:
	explicit JSONFile(std::string filename);

	~JSONFile();

	void set_columns(std::initializer_list<std::string> columns);

	void add_item(std::string item = "");

	void add_item(unsigned long long item);

	void new_line();
};
