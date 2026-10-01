#pragma once

#include "event_bus.hpp"
#include "logger.hpp"
#include <string>

namespace everbloom::driver {

class NetworkFirewallModule {
public:
    NetworkFirewallModule(EventBus& bus, Logger& logger);
    void initialize();
    void shutdown();
    bool inspectConnection(const std::string& remote) const;
    bool inspectPayload(const std::string& payload) const;
    IoctlResult handleIoctl(const IRP& irp);

private:
    EventBus& event_bus_;
    Logger& logger_;
};

} // namespace everbloom::driver
