#include "amsi.hpp"
#include "irp_utils.hpp"

namespace everbloom::driver {

AmsiModule::AmsiModule(EventBus& bus, Logger& logger)
    : event_bus_(bus), logger_(logger) {
}

void AmsiModule::initialize() {
    logger_.log(LogLevel::Info, "AMSI module initialized");
    // AMSI requests are dispatched once by IrpDispatcher and are reported
    // back through the event bus as telemetry.
    Event pub{EventType::Generic, "amsi", "amsi", "AMSI scanning enabled", std::nullopt, ThreatLevel::Low, EventSeverity::Info};
    event_bus_.publish(pub);
}

void AmsiModule::shutdown() {
    logger_.log(LogLevel::Info, "AMSI module shutdown");
}

bool AmsiModule::inspectScriptPayload(const std::string& payload) const {
    return payload.find("powershell") != std::string::npos || payload.find("rundll32") != std::string::npos;
}

bool AmsiModule::inspectMemoryPayload(const std::string& payload) const {
    return payload.find("shellcode") != std::string::npos;
}

IoctlResult AmsiModule::handleIoctl(const IRP& irp) {
    const bool suspicious = inspectScriptPayload(irp.Payload) || inspectMemoryPayload(irp.Payload);
    const ThreatLevel threat = suspicious ? ThreatLevel::High : ThreatLevel::Medium;
    const ResponseAction action = suspicious ? ResponseAction::Block : ResponseAction::Notify;
    logger_.log(suspicious ? LogLevel::Warning : LogLevel::Info,
                "AMSI handled IOCTL " + std::to_string(irp.IoControlCode) + " for " + irp.Target);
    Event pub{EventType::Policy, "amsi", "amsi", "followup:" + irp.Target, irp, threat, suspicious ? EventSeverity::Warning : EventSeverity::Info};
    event_bus_.publish(pub);
    return {true, threat, action, "AMSI IOCTL handled", suspicious};
}

} // namespace everbloom::driver
