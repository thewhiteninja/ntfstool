#pragma once

#include <string>
#include <cstdint>
#include <memory>

#include "Drive/disk.h"

class Options {
private:
public:
	std::string command;
	std::string subcommand;
	std::string from;
	std::string output;
	std::string format;
	std::string rules;

	std::string password;
	std::string sid;
	std::string recovery;
	std::string bek;
	std::string fvek;
	std::string image;
	std::string pfx;
	std::string mode;

	std::shared_ptr<Buffer<PBYTE>> masterkey = nullptr;

	int64_t inode = -1;
	int32_t fve_block = -1;
	int32_t disk = -1;
	int32_t volume = -1;

	bool show_usage = false;
	bool sam = false;
	bool system = false;

	explicit Options();
};

std::shared_ptr<Options> parse_options(int argc, char** argv);

std::shared_ptr<Disk> get_disk(std::shared_ptr<Options> opts);


void invalid_option(std::shared_ptr<Options> opts, std::string name, int64_t invalid_value, std::string error_msg = "");

void invalid_option(std::shared_ptr<Options> opts, std::string name, std::string invalid_value, std::string error_msg = "");