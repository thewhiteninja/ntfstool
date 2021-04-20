#pragma once

#include <string>
#include <vector>

namespace utils
{
	namespace ui {
		enum class TableAlign
		{
			LEFT,
			RIGHT
		};

		class Table
		{
		private:
			std::vector<std::vector<std::string>> headers;
			std::vector<utils::ui::TableAlign> column_align;
			std::vector<std::vector<std::vector<std::string>>> data;
			std::vector<std::vector<std::string>> current_line;

			bool border_top = true;
			bool border_bottom = true;
			bool border_left = true;
			bool border_right = true;
			bool interline = false;
			bool header_interline = true;
			bool corner = true;
			uint32_t margin_left;
		public:
			explicit Table();

			void add_header_line(std::string header, utils::ui::TableAlign align = TableAlign::LEFT);

			void add_header_multiline(std::initializer_list<std::string> header, utils::ui::TableAlign align = TableAlign::LEFT);

			void add_item_line(std::string item);

			void add_item_multiline(std::initializer_list<std::string> list);

			void add_item_multiline(std::vector<std::string> list, unsigned int max_size = 32);

			void set_margin_left(uint32_t margin_left);

			void set_corner(bool show) { corner = show; }

			void set_interline(bool show) { interline = show; }

			void set_header_interline(bool show) { header_interline = show; }

			void set_border_left(bool show) { border_left = show; }

			void set_border_top(bool show) { border_top = show; }

			void set_border_right(bool show) { border_right = show; }

			void set_border_bottom(bool show) { border_bottom = show; }

			void set_border(bool show) { border_bottom = show; border_left = show; border_right = show; border_top = show; }

			void new_line();

			void render(std::ostream& out);
		};
	}
}