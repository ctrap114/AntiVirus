#pragma once

#include "event_bus.hpp"
#include "logger.hpp"
#include <string>

namespace everbloom::driver {

class FileProtectionModule {
public:
    FileProtectionModule(EventBus& bus, Logger& logger);
    void initialize();
    void shutdown();
    bool isProtectedPath(const std::string& path) const;
    bool inspectWriteOperation(const std::string& path) const;
    IoctlResult handleIoctl(const IRP& irp);

private:
    EventBus& event_bus_;
    Logger& logger_;
};

} // namespace everbloom::driver
