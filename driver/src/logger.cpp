#include "logger.hpp"

namespace everbloom::driver {

void Logger::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << "[logger] initialized" << std::endl;
}

void Logger::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << "[logger] shutdown" << std::endl;
}

void Logger::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    const char* prefix = "[INFO]";
    switch (level) {
        case LogLevel::Debug: prefix = "[DEBUG]"; break;
        case LogLevel::Info: prefix = "[INFO]"; break;
        case LogLevel::Warning: prefix = "[WARN]"; break;
        case LogLevel::Error: prefix = "[ERROR]"; break;
        case LogLevel::Critical: prefix = "[CRITICAL]"; break;
    }
    std::cout << prefix << " " << message << std::endl;
}

} // namespace everbloom::driver
