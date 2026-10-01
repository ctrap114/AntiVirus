#pragma once

#include "event_bus.hpp"
#include "logger.hpp"
#include <string>

namespace everbloom::driver {

class AdvancedThreatModule {
public:
    AdvancedThreatModule(EventBus& bus, Logger& logger);
    void initialize();
    void shutdown();
    bool inspectBehavior(const std::string& behavior) const;
    bool inspectExploitPattern(const std::string& pattern) const;
    IoctlResult handleIoctl(const IRP& irp);

private:
    EventBus& event_bus_;
    Logger& logger_;
};

} // namespace everbloom::driver
