#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>

#include "Utils/buffer.h"
#include "Utils/utils.h"

namespace utils
{
	namespace dfir {

		class ZoneIdentifier
		{
		private:
			std::map<std::string, std::string> _values;

		public:
			explicit ZoneIdentifier(std::shared_ptr<Buffer<PBYTE>> data);

			std::string get_value(std::string);
		};
	}
}