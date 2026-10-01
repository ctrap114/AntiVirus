#include "advanced_threat.hpp"
#include "irp_utils.hpp"

namespace everbloom::driver {

AdvancedThreatModule::AdvancedThreatModule(EventBus& bus, Logger& logger)
    : event_bus_(bus), logger_(logger) {
}

void AdvancedThreatModule::initialize() {
    logger_.log(LogLevel::Info, "Advanced threat module initialized");
    // Behavior requests are owned by IrpDispatcher; this module only emits
    // the result so the user-mode protection controller can correlate it.
    Event pub{EventType::Generic, "advanced_threat", "advanced_threat", "Behavior and exploit monitoring enabled", std::nullopt, ThreatLevel::Low, EventSeverity::Info};
    event_bus_.publish(pub);
}

void AdvancedThreatModule::shutdown() {
    logger_.log(LogLevel::Info, "Advanced threat module shutdown");
}

IoctlResult AdvancedThreatModule::handleIoctl(const IRP& irp) {
    const bool suspicious = inspectBehavior(irp.Payload) || inspectExploitPattern(irp.Payload);
    const ThreatLevel threat = suspicious ? ThreatLevel::High : ThreatLevel::Medium;
    const ResponseAction action = suspicious ? ResponseAction::Terminate : ResponseAction::Notify;
    logger_.log(suspicious ? LogLevel::Warning : LogLevel::Info,
                "Advanced threat processed IOCTL for " + irp.Target);
    Event pub{EventType::Policy, "advanced_threat", "advanced_threat", "followup:" + irp.Target, irp, threat, suspicious ? EventSeverity::Warning : EventSeverity::Info};
    event_bus_.publish(pub);
    return {true, threat, action, "Advanced threat analysis result", suspicious};
}

bool AdvancedThreatModule::inspectBehavior(const std::string& behavior) const {
    return behavior.find("suspicious") != std::string::npos;
}

bool AdvancedThreatModule::inspectExploitPattern(const std::string& pattern) const {
    return pattern.find("ROP") != std::string::npos || pattern.find("shellcode") != std::string::npos;
}

} // namespace everbloom::driver
