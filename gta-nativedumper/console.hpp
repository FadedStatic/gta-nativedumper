
#include <iostream>
#include <Windows.h>
#include <vector>
#include <iomanip>
#include <ctime>
#include <chrono>

namespace console
{
	enum class log_severity : int {
		info,
		warn,
		error,
		success,
	};

#define WHITE FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE
	constexpr std::tuple<int, int, std::string > resolve_severity(const log_severity sev)
	{
		switch (sev)
		{
		case log_severity::info:
			return { BACKGROUND_INTENSITY, FOREGROUND_INTENSITY, "INFO" };
		case log_severity::warn:
			return { BACKGROUND_INTENSITY | BACKGROUND_RED | BACKGROUND_GREEN, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN, "WARN" };
		case log_severity::success:
			return { BACKGROUND_GREEN | BACKGROUND_INTENSITY, FOREGROUND_GREEN | FOREGROUND_INTENSITY, "SUCCESS" };
		case log_severity::error:
			return { BACKGROUND_RED | BACKGROUND_INTENSITY, FOREGROUND_RED | FOREGROUND_INTENSITY, "ERROR" };
		}
		return { 0, WHITE, "general" };
	}

	template <log_severity Sev, typename... Va>
	void log(const std::string& fmt, Va... vargs)
	{
		static auto con_wnd = GetStdHandle(STD_OUTPUT_HANDLE);
		const auto [bg, fg, tag] = resolve_severity(Sev);
		SetConsoleTextAttribute(con_wnd, bg);
		std::cout << "  ";
		SetConsoleTextAttribute(con_wnd, fg);
		time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		struct tm buf;
		localtime_s(&buf, &now);
		std::printf((std::string(" [%02d:%02d:%02d] [%s]: ") + fmt + "\n").c_str(), buf.tm_hour, buf.tm_min, buf.tm_sec, tag, vargs...);
	}
}