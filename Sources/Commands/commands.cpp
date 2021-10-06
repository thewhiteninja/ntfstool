#include "Commands/commands.h"

#include "Utils/utils.h"

std::shared_ptr<MFTRecord> commands::helpers::find_record(std::shared_ptr<NTFSExplorer> ex, std::shared_ptr<Options> opts)
{
	std::shared_ptr<MFTRecord> rec = nullptr;

	auto [filepath, stream_name] = ::utils::files::split_file_and_stream(opts->from);

	if (opts->from != "")
	{
		rec = ex->mft()->record_from_path(filepath);
		if (rec == nullptr)
		{
			invalid_option(opts, "from", opts->from, "Unable to find file record");
		}
	}
	else
	{
		rec = ex->mft()->record_from_number(opts->inode);
		if (rec == nullptr)
		{
			invalid_option(opts, "inode", opts->inode, "Unable to find file record");
		}
	}

	return rec;
}