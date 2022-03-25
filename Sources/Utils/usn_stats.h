#pragma once

#include <map>
#include <string>
#include <winioctl.h>

class USNStats
{
private:
	std::map<std::string, unsigned long> _stats;

public:
	USNStats()
	{
		_stats["file creation"] = 0;
		_stats["file deletion"] = 0;
		_stats["file rename"] = 0;
		_stats["records count"] = 0;
	}

	void add_record(std::string& filename, PUSN_RECORD_V2 record)
	{
		if (record->Reason & USN_REASON_FILE_CREATE) _stats["file creation"] += 1;
		if (record->Reason & USN_REASON_FILE_DELETE) _stats["file deletion"] += 1;
		if (record->Reason & USN_REASON_RENAME_NEW_NAME) _stats["file rename"] += 1;
		_stats["records count"] += 1;
	}

	unsigned long get_stat(std::string cat)
	{
		if (_stats.find(cat) != _stats.end())
		{
			return _stats[cat];
		}
		return 0;
	}

	std::map<std::string, unsigned long>& get_stats()
	{
		return _stats;
	}

};
