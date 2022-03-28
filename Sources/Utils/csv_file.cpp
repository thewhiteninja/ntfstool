#include "csv_file.h"
#include <regex>


std::string CSVFile::_escape(std::string s)
{
	std::stringstream ss;
	for (auto& c : s)
	{
		if (c == '\\') ss << c;
		ss << c;
	}
	return ss.str();
}

CSVFile::CSVFile(std::string filename, std::string separator)
{
	_file.open(filename, std::ios::out | std::ios::binary);
	_separator = separator;
}

CSVFile::~CSVFile()
{
	if (_file.is_open())
	{
		_file.close();
	}
}

void CSVFile::set_columns(std::initializer_list<std::string> columns)
{
	_columns = columns;

	bool first = true;
	for (auto& column : _columns)
	{
		if (!first) _file << _separator;
		else first = false;
		_file << column;
	}
	_file << std::endl;
}

void CSVFile::add_item(std::string item)
{
	if (_current_line.size() < _columns.size())
	{
		_current_line.push_back('"' + _escape(item) + '"');
	}
}

void CSVFile::add_item(unsigned long long item)
{
	if (_current_line.size() < _columns.size())
	{
		_current_line.push_back(std::to_string(item));
	}
}

void CSVFile::new_line()
{
	_file << utils::strings::join_vec<std::string>(_current_line, _separator);
	_file << std::endl;
	_current_line.clear();
}
