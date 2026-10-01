#pragma once

#include "event_bus.hpp"
#include "logger.hpp"
#include <string>

namespace everbloom::driver {

class AmsiModule {
public:
    AmsiModule(EventBus& bus, Logger& logger);
    void initialize();
    void shutdown();
    bool inspectScriptPayload(const std::string& payload) const;
    bool inspectMemoryPayload(const std::string& payload) const;
    IoctlResult handleIoctl(const IRP& irp);

private:
    EventBus& event_bus_;
    Logger& logger_;
};

} // namespace everbloom::driver
