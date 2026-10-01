#include "file_protection.hpp"

namespace everbloom::driver {

FileProtectionModule::FileProtectionModule(EventBus& bus, Logger& logger)
    : event_bus_(bus), logger_(logger) {
}

void FileProtectionModule::initialize() {
    logger_.log(LogLevel::Info, "File protection initialized");
    Event pub{EventType::Generic, "file_protection", "file_protection", "Watching protected file paths", std::nullopt, ThreatLevel::Low, EventSeverity::Info};
    event_bus_.publish(pub);
}

void FileProtectionModule::shutdown() {
    logger_.log(LogLevel::Info, "File protection shutdown");
}

bool FileProtectionModule::isProtectedPath(const std::string& path) const {
    return path.find("\\Users\\") != std::string::npos || path.find("C:\\Users\\") != std::string::npos;
}

bool FileProtectionModule::inspectWriteOperation(const std::string& path) const {
    return path.find(".exe") != std::string::npos || path.find(".dll") != std::string::npos;
}

IoctlResult FileProtectionModule::handleIoctl(const IRP& irp) {
    if (irp.IoControlCode != IoctlCodes::IOCTL_SCAN_FILE) {
        return {false, ThreatLevel::Low, ResponseAction::Log, "Not a file scan IRP", false};
    }

    const bool suspicious = isProtectedPath(irp.Target) || inspectWriteOperation(irp.Target);
    const ThreatLevel threat = suspicious ? ThreatLevel::High : ThreatLevel::Medium;
    const ResponseAction action = suspicious ? ResponseAction::Block : ResponseAction::Notify;
    logger_.log(suspicious ? LogLevel::Warning : LogLevel::Info,
                "File protection reviewed path " + irp.Target);
    Event pub{EventType::Policy, "file_protection", "file_protection", "file scan result", irp, threat, suspicious ? EventSeverity::Warning : EventSeverity::Info};
    event_bus_.publish(pub);
    return {true, threat, action, "File protection result", suspicious};
}

} // namespace everbloom::driver
