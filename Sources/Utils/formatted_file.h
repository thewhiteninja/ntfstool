#pragma once

#include <initializer_list>
#include <string>
#include <vector>


class FormatteddFile
{
protected:
	std::vector<std::string> _columns;

public:

	virtual void set_columns(std::initializer_list<std::string> columns) = 0;

	virtual void add_item(std::string item = "") = 0;

	virtual void add_item(unsigned long long item) = 0;

	virtual void new_line() = 0;
};
