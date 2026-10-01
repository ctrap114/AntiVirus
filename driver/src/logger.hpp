#pragma once

#include <iostream>
#include <mutex>
#include <string>

namespace everbloom::driver {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical
};

class Logger {
public:
    void initialize();
    void shutdown();
    void log(LogLevel level, const std::string& message);

private:
    std::mutex mutex_;
};

} // namespace everbloom::driver
