#pragma once

#include <map>
#include <string>
#include <winioctl.h>

class USNStats
{
private:
	std::map<std::string, int64_t> _stats;

public:
	USNStats()
	{
		_stats["oldest"] = 0ULL;
		_stats["latest"] = 0ULL;
		_stats["file creation"] = 0ULL;
		_stats["file deletion"] = 0ULL;
		_stats["file rename"] = 0ULL;
		_stats["records count"] = 0ULL;
	}

	void add_record(std::string& filename, PUSN_RECORD_V2 record)
	{
		if (_stats["latest"] == 0 || _stats["latest"] < record->TimeStamp.QuadPart)
		{
			_stats["latest"] = record->TimeStamp.QuadPart;
		}
		if (_stats["oldest"] == 0 || _stats["oldest"] > record->TimeStamp.QuadPart)
		{
			_stats["oldest"] = record->TimeStamp.QuadPart;
		}
		if (record->Reason & USN_REASON_FILE_CREATE) _stats["file creation"] += 1;
		if (record->Reason & USN_REASON_FILE_DELETE) _stats["file deletion"] += 1;
		if (record->Reason & USN_REASON_RENAME_NEW_NAME) _stats["file rename"] += 1;
		_stats["records count"] += 1;
	}

	int64_t get_stat(std::string cat)
	{
		if (_stats.find(cat) != _stats.end())
		{
			return _stats[cat];
		}
		return 0;
	}

	std::map<std::string, int64_t>& get_stats()
	{
		return _stats;
	}

	bool is_date(std::pair<std::string, int64_t> e)
	{
		return e.first == "oldest" || e.first == "latest";
	}

	bool is_count(std::pair<std::string, int64_t> e)
	{
		return !is_date(e);
	}
};
