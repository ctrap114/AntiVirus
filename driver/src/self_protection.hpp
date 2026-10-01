#pragma once

#include "event_bus.hpp"
#include "logger.hpp"
#include <string>
#include <vector>

namespace everbloom::driver {

class SelfProtectionModule {
public:
    SelfProtectionModule(EventBus& bus, Logger& logger);
    void initialize();
    void shutdown();
    bool validateDriverIntegrity() const;
    bool validateControlPath(const std::string& ioctl_name) const;
    bool inspectControlRequest(const std::string& ioctl_name, const std::string& caller) const;
    bool inspectUnloadRequest(const std::string& requester) const;
    bool validateDeviceAccess(const std::string& device_name) const;
    IoctlResult handleIoctl(const IRP& irp);

private:
    EventBus& event_bus_;
    Logger& logger_;
    std::vector<std::string> allowed_ioctl_prefixes_;
    std::vector<std::string> protected_devices_;
    bool integrity_ok_;
    void reportSuspicious(const std::string& detail, ThreatLevel threat) const;
};

} // namespace everbloom::driver
