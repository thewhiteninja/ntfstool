#include "usn_rules.h"

#include <regex>
#include <Utils/constant_names.h>

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

			int hy_rule = 0;
			for (auto& rule : _file)
			{
				try
				{
					hy_rule++;
					auto r = std::make_shared<USNRule>(rule);
					_rules.push_back(r);
				}
				catch (std::invalid_argument& ex)
				{
					std::cout << "[!] Error parsing rule " << hy_rule << ": " << ex.what() << std::endl;
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
	if (j.contains("id"))
	{
		_id = j["id"];
	}
	else
	{
		throw std::invalid_argument("missing id");
	}
	if (j.contains("description"))
	{
		_description = j["description"];
	}
	else
	{
		throw std::invalid_argument("missing description");
	}
	if (j.contains("severity"))
	{
		_severity = j["severity"];
	}
	else
	{
		throw std::invalid_argument("missing severity");
	}

	if (j["rule"].is_object())
	{
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
					throw std::invalid_argument("filename rule \"" + it.value().get<std::string>() + "\" is not a valid regex");
				}
			}
			else if (it.key() == "reason")
			{
				if (it.value().is_array())
				{
					DWORD64 mask = 0;
					DWORD64 value = 0;

					for (auto& reason : it.value())
					{
						std::string& r = reason.get<std::string>();
						if (r.length() > 1)
						{
							if (r[0] == '+' || r[0] == '-')
							{
								DWORD64 r_flag = constants::disk::usn::reasons_inv(r.substr(1));
								if (r_flag)
								{
									mask |= r_flag;
									if (r[0] == '+')
									{
										value |= r_flag;
									}
									else
									{
										value &= ~r_flag;
									}
								}
								else
								{
									throw std::invalid_argument("invalid usn reason value \"" + r.substr(1) + "\"");
								}
							}
							else
							{
								throw std::invalid_argument("reason must start with \"+\" or \"-\"");
							}
						}
						else
						{
							throw std::invalid_argument("invalid reason value \"" + r + "\"");
						}
					}
					_a_rules[it.key()] = value << 32 | mask;;
				}
				else
				{
					throw std::invalid_argument("\"reason\" is not an array");
				}
			}
			else if (it.key() == "attributes")
			{
				if (it.value().is_array())
				{
					DWORD64 mask = 0;
					DWORD64 value = 0;

					for (auto& reason : it.value())
					{
						std::string& r = reason.get<std::string>();
						if (r.length() > 1)
						{
							if (r[0] == '+' || r[0] == '-')
							{
								DWORD64 r_flag = constants::disk::usn::fileattributes_inv(r.substr(1));
								if (r_flag)
								{
									mask |= r_flag;
									if (r[0] == '+')
									{
										value |= r_flag;
									}
									else
									{
										value &= ~r_flag;
									}
								}
								else
								{
									throw std::invalid_argument("invalid usn file attribute value \"" + r.substr(1) + "\"");
								}
							}
							else
							{
								throw std::invalid_argument("file attribute must start with \"+\" or \"-\"");
							}
						}
						else
						{
							throw std::invalid_argument("invalid file attribute value \"" + r + "\"");
						}
					}
					_a_rules[it.key()] = value << 32 | mask;;
				}
				else
				{
					throw std::invalid_argument("\"attributes\" is not an array");
				}
			}
			else
			{
				throw std::invalid_argument("unknown rule type \"" + it.key() + "\"");
			}
		}
		if (_a_rules.empty())
		{
			throw std::invalid_argument("\"rule\" is empty");
		}
	}
	else
	{
		throw std::invalid_argument("\"rule\" is not an object");
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
		else if (it->first == "reason")
		{
			DWORD mask = std::any_cast<DWORD64>(it->second) & 0xffffffff;
			DWORD value = std::any_cast<DWORD64>(it->second) >> 32;

			if ((usn->Reason & mask) != value)
			{
				return false;
			}
		}
		else if (it->first == "attributes")
		{
			DWORD mask = std::any_cast<DWORD64>(it->second) & 0xffffffff;
			DWORD value = std::any_cast<DWORD64>(it->second) >> 32;

			if ((usn->FileAttributes & mask) != value)
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
