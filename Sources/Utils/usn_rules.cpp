#include "usn_rules.h"

#include <regex>

USNRules::USNRules(std::string filename)
{
	try
	{
		std::ifstream ifs(filename);
		if (ifs.fail())
		{
			std::cout << "[!] Error reading JSON!" << std::endl;
		}
		else
		{

			_file = nlohmann::json::parse(ifs);

			for (auto& rule : _file)
			{
				try
				{
					auto r = std::make_shared<USNRule>(rule);
					_rules.push_back(r);
				}
				catch (std::invalid_argument& ex)
				{
					std::cout << "[!] Error parsing rule near: " << ex.what() << std::endl;
				}
			}
		}
	}
	catch (nlohmann::json::exception& ex)
	{
		std::cout << "[!] Error parsing JSON!" << std::endl;
		std::cout << "    " << ex.what() << std::endl;
	}
}

USNRules::~USNRules()
{

}

bool in_array(const std::string& value, const std::vector<std::string>& array)
{
	return std::find(array.begin(), array.end(), value) != array.end();
}

USNRule::USNRule(nlohmann::json j)
{
	_id = j["id"];
	_author = j["author"];
	_description = j["description"];
	_status = j["status"];
	_type = j["type"];
	_severity = j["severity"];

	for (auto& it : j["rule"].items())
	{
		if (it.key() == "filename")
		{
			try
			{
				_a_rules[it.key()] = std::regex(it.value().get<std::string>());
			}
			catch (std::regex_error)
			{
				throw std::invalid_argument(it.value());
			}
		}
		else
		{
			throw std::invalid_argument(it.key());
		}
	}

}

bool USNRule::match(std::string filename, PUSN_RECORD_V2 usn)
{
	std::map<std::string, std::any>::iterator it;
	for (it = _a_rules.begin(); it != _a_rules.end(); ++it)
	{
		if (it->first == "filename")
		{
			if (!std::regex_match(filename, std::any_cast<std::regex>(it->second)))
			{
				return false;
			}
		}
	}
	return true;
}

USNRule::~USNRule()
{
	_a_rules.clear();
}
