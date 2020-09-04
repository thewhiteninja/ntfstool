#pragma once

#include <chrono>
#include <iostream>
#include <iomanip>
#include <cmath>

class ProgressBar {
private:
	bool _infinite = false;
	unsigned int _ticks = 0;
	int _total_ticks;
	int _bar_width;

	std::wstring _label = L"";
	wchar_t complete_char = L'#';
	wchar_t incomplete_char = L' ';
	bool display_time = false;

	const std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();

public:
	ProgressBar(int total, int width, std::wstring label = L"") : _total_ticks(total), _bar_width(width), _label(label) {}

	void set_total(int total) noexcept { _total_ticks = total; }

	void set_display_time(bool b) noexcept { display_time = b; }

	void set_label(std::wstring l) noexcept { _label = l; }

	void set_infinite(bool b) noexcept { _infinite = b; }

	void set_bar_type(wchar_t c, wchar_t i) noexcept { complete_char = c; incomplete_char = i; }

	void increment() noexcept { _ticks++; }

	void set_progress(unsigned int p) noexcept { _ticks = p; }

	void display(std::wostream& out)
	{
		const float progress = float(_ticks) / _total_ticks;
		const int pos = static_cast<int>(_bar_width * progress);

		unsigned long long time_elapsed = 0;
		if (display_time)
		{
			const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
			time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
		}

		const std::ios_base::fmtflags f(out.flags());

		out << std::left << _label << L"[";

		if (_infinite)
		{
			const int inf_step = _ticks % _bar_width;
			int left = inf_step + 8 - _bar_width;
			if (left > 0)
			{
				for (int i = 0; i < left; ++i) {
					out << '=';
				}
			}
			else
			{
				left = 0;
			}
			for (int i = left; i < inf_step; ++i) {
				out << ' ';
			}
			for (int i = inf_step; i < min(inf_step + 8, _bar_width); ++i) {
				out << '=';
			}
			for (int i = min(inf_step + 8, _bar_width); i < _bar_width; ++i) {
				out << ' ';
			}
			_ticks = _ticks + 1;
		}
		else
		{
			for (int i = 0; i < _bar_width; ++i) {
				if (i < pos) out << complete_char;
				else if (i == pos) out << L">";
				else out << incomplete_char;
			}
		}
		out << std::fixed << std::setprecision(2) << L"] ";
		if (!_infinite)
		{
			out << static_cast<int>(min(progress * 100.0, 100.0)) << L"% ";
		}
		if (display_time)
		{
			out << static_cast<int>(time_elapsed / 1000.0) << L"s";
		}
		out << L"     \r";
		out.flush();

		out.flags(f);
	}

	void done(std::wostream& out)
	{
		_ticks = _total_ticks;
		_infinite = false;
		display(out);
		out << std::endl;
		out.flush();
	}
};
