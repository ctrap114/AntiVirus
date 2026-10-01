#include "self_protection.hpp"

namespace everbloom::driver {

SelfProtectionModule::SelfProtectionModule(EventBus& bus, Logger& logger)
    : event_bus_(bus), logger_(logger), integrity_ok_(true) {
    allowed_ioctl_prefixes_ = {"IOCTL_EVERBLOOM_", "IOCTL_STORAGE_", "IOCTL_DISK_"};
    protected_devices_ = {"\\Device\\EverbloomSecurity", "\\Device\\EverbloomSecurityControl"};
}

void SelfProtectionModule::initialize() {
    logger_.log(LogLevel::Info, "Self protection initialized");
    Event pub{EventType::Generic, "self_protection", "self_protection", "Driver self-protection enabled", std::nullopt, ThreatLevel::Low, EventSeverity::Info};
    event_bus_.publish(pub);
}

void SelfProtectionModule::shutdown() {
    logger_.log(LogLevel::Info, "Self protection shutdown");
}

bool SelfProtectionModule::validateDriverIntegrity() const {
    if (!integrity_ok_) {
        reportSuspicious("Driver image integrity mismatch detected", ThreatLevel::Critical);
    }
    return integrity_ok_;
}

bool SelfProtectionModule::validateControlPath(const std::string& ioctl_name) const {
    if (inspectControlRequest(ioctl_name, "unknown")) {
        return true;
    }
    return false;
}

bool SelfProtectionModule::inspectControlRequest(const std::string& ioctl_name, const std::string& caller) const {
    for (const auto& prefix : allowed_ioctl_prefixes_) {
        if (ioctl_name.rfind(prefix, 0) == 0) {
            return true;
        }
    }
    reportSuspicious("Suspicious IOCTL request: " + ioctl_name + " from " + caller, ThreatLevel::High);
    return false;
}

bool SelfProtectionModule::inspectUnloadRequest(const std::string& requester) const {
    if (requester != "kernel" && requester != "trusted") {
        reportSuspicious("Unauthorized unload attempt by " + requester, ThreatLevel::Critical);
        return false;
    }
    return true;
}

bool SelfProtectionModule::validateDeviceAccess(const std::string& device_name) const {
    for (const auto& protected_device : protected_devices_) {
        if (device_name == protected_device) {
            reportSuspicious("Unauthorized access to protected device: " + device_name, ThreatLevel::High);
            return false;
        }
    }
    return true;
}

IoctlResult SelfProtectionModule::handleIoctl(const IRP& irp) {
    const bool known_ioctl = irp.IoControlCode == IoctlCodes::IOCTL_AMSI_SCAN_BUFFER
        || irp.IoControlCode == IoctlCodes::IOCTL_SCAN_FILE
        || irp.IoControlCode == IoctlCodes::IOCTL_NET_INSPECT
        || irp.IoControlCode == IoctlCodes::IOCTL_BEHAVIOR_ANALYZE
        || irp.IoControlCode == IoctlCodes::IOCTL_POLICY_UPDATE
        || irp.IoControlCode == IoctlCodes::IOCTL_POLICY_CLEAR
        || irp.IoControlCode == IoctlCodes::IOCTL_PROTECTION_UPDATE
        || irp.IoControlCode == IoctlCodes::IOCTL_EVENT_READ
        || irp.IoControlCode == IoctlCodes::IOCTL_CAPABILITIES_QUERY;
    const bool trusted_caller = irp.Caller == "kernel"
        || irp.Caller == "service"
        || irp.Caller == "trusted";
    const bool control_ok = known_ioctl && trusted_caller;
    const bool device_ok = validateDeviceAccess(irp.Target);
    if (!control_ok || !device_ok) {
        const std::string reason = !control_ok
            ? "Self-protection blocked unknown or untrusted control request"
            : "Self-protection blocked protected device access";
        Event pub{EventType::Policy, "self_protection", "self_protection", reason, irp, ThreatLevel::Critical, EventSeverity::Critical};
        event_bus_.publish(pub);
        return {true, ThreatLevel::Critical, ResponseAction::Terminate, reason, true};
    }
    Event pub{EventType::Policy, "self_protection", "self_protection", "Self-protection allowed IOCTL", irp, ThreatLevel::Low, EventSeverity::Info};
    event_bus_.publish(pub);
    return {true, ThreatLevel::Low, ResponseAction::Log, "Self-protection allowed IOCTL", false};
}

void SelfProtectionModule::reportSuspicious(const std::string& detail, ThreatLevel threat) const {
    logger_.log(LogLevel::Warning, detail);
    Event pub{EventType::Policy, "self_protection", "self_protection", detail, std::nullopt, threat, EventSeverity::Critical};
    event_bus_.publish(pub);
}

} // namespace everbloom::driver
