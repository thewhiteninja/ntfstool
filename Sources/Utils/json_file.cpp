#include "json_file.h"
#include <regex>

JSONFile::JSONFile(std::string filename)
{
	_file.open(filename, std::ios::out | std::ios::binary);
	if (_file.is_open())
	{
		_file << "[";
	}
}

JSONFile::~JSONFile()
{
	if (_file.is_open())
	{
		_file << std::endl << "]";
		_file.close();
	}
}

void JSONFile::set_columns(std::initializer_list<std::string> columns)
{
	_columns = columns;
}

void JSONFile::add_item(std::string item)
{
	if (_current_item.size() < _columns.size())
	{
		_current_item[_columns[_current_item.size()]] = utils::strings::str_to_utf8(item);
	}
}

void JSONFile::add_item(unsigned long long item)
{
	if (_current_item.size() < _columns.size())
	{
		_current_item[_columns[_current_item.size()]] = std::to_string(item);
	}
}

void JSONFile::new_line()
{
	if (!_first)
	{
		_file << ",";
	}
	else
	{
		_first = false;
	}
	_file << std::endl << _current_item.dump(4);
	_current_item.clear();
}
