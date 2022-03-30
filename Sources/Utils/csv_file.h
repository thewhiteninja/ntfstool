#pragma once

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <map>

#include "Utils/buffer.h"
#include "Utils/utils.h"
#include "Utils/formatted_file.h"


class CSVFile : public FormatteddFile
{
private:
	std::ofstream _file;
	std::string _separator = ",";
	std::vector<std::string> _current_line;

	std::string _escape(std::string s);

public:
	explicit CSVFile(std::string filename, std::string separator = ",");

	~CSVFile();

	void set_columns(std::initializer_list<std::string> columns);

	void add_item(std::string item = "");

	void add_item(unsigned long long item);

	void new_line();
};
