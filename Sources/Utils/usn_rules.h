#pragma once

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <map>
#include <any>

#include "Utils/buffer.h"
#include "Utils/utils.h"

#include <nlohmann/json.hpp>


class USNRule
{
private:
	std::string _id;
	std::string _description;
	std::string _status;
	std::string _severity;

	std::map<std::string, std::any> _a_rules;

public:
	explicit USNRule(nlohmann::json j);

	std::string id() { return _id; };
	std::string description() { return _description; };
	std::string status() { return _status; };
	std::string severity() { return _severity; };

	bool match(std::string filename, PUSN_RECORD_V2 usn);

	~USNRule();
};


class USNRules
{
private:
	nlohmann::json _file;

	std::vector<std::shared_ptr<USNRule>> _rules;

public:
	explicit USNRules(std::string filename);

	std::vector<std::shared_ptr<USNRule>> rules() { return _rules; };

	unsigned int size() { return static_cast<unsigned int>(_rules.size()); }

	~USNRules();

};
