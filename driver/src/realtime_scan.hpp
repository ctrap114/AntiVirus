#pragma once

#include "event_bus.hpp"
#include "logger.hpp"
#include <string>

namespace everbloom::driver {

class RealtimeScanModule {
public:
    RealtimeScanModule(EventBus& bus, Logger& logger);
    void initialize();
    void shutdown();
    bool enqueueScan(const std::string& target) const;
    bool inspectTarget(const std::string& target) const;
    IoctlResult handleIoctl(const IRP& irp);

private:
    EventBus& event_bus_;
    Logger& logger_;
};

} // namespace everbloom::driver
