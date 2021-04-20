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
	std::string out;
	std::string format = "raw";

	std::string password;
	std::string recovery;
	std::string bek;
	std::string fvek;
	std::string image;

	unsigned long inode = 0;
	unsigned long fve_block = 0;
	unsigned long disk = 0xffffffff;
	unsigned long volume = 0xffffffff;

	bool show_usage = false;
	bool sam = false;
	bool system = false;

	explicit Options();
};

std::shared_ptr<Options> parse_options(int argc, char** argv);

std::shared_ptr<Disk> get_disk(std::shared_ptr<Options> opts);