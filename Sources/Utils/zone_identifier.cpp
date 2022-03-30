#include "zone_identifier.h"

utils::dfir::ZoneIdentifier::ZoneIdentifier(std::shared_ptr<Buffer<PBYTE>> data)
{
	auto lines = utils::strings::split(reinterpret_cast<PCHAR>(data->data()), '\n');
	for (auto& line : lines)
	{
		size_t pos = line.find("=");
		if (pos != std::string::npos)
		{
			if (line.back() == '\r')
			{
				line.pop_back();
			}
			_values.insert(std::pair<std::string, std::string>(line.substr(0, pos), line.substr(pos + 1)));
		}
	}
}

std::string utils::dfir::ZoneIdentifier::get_value(std::string key)
{
	if (_values.find(key) != _values.end())
	{
		return _values[key];
	}
	else
	{
		return "";
	}
}
