#include "realtime_scan.hpp"
#include "irp_utils.hpp"

namespace everbloom::driver {

RealtimeScanModule::RealtimeScanModule(EventBus& bus, Logger& logger)
    : event_bus_(bus), logger_(logger) {
}

void RealtimeScanModule::initialize() {
    logger_.log(LogLevel::Info, "Realtime scan module initialized");
    // IOCTL ownership is centralized in IrpDispatcher. Subscribing here would
    // process the same request twice and make the event bus a control path.
    Event pub{EventType::Generic, "realtime_scan", "realtime_scan", "Realtime scanning configured", std::nullopt, ThreatLevel::Low, EventSeverity::Info};
    event_bus_.publish(pub);
}

void RealtimeScanModule::shutdown() {
    logger_.log(LogLevel::Info, "Realtime scan module shutdown");
}

IoctlResult RealtimeScanModule::handleIoctl(const IRP& irp) {
    const bool queued = enqueueScan(irp.Target);
    const ThreatLevel threat = queued ? ThreatLevel::Medium : ThreatLevel::Low;
    const ResponseAction action = queued ? ResponseAction::Notify : ResponseAction::Log;
    logger_.log(queued ? LogLevel::Info : LogLevel::Debug,
                "Realtime scan processed IOCTL for " + irp.Target);
    Event pub{EventType::Policy, "realtime_scan", "realtime_scan", "followup:" + irp.Target, irp, threat, queued ? EventSeverity::Info : EventSeverity::Warning};
    event_bus_.publish(pub);
    return {true, threat, action, "Realtime scan queued", false};
}

bool RealtimeScanModule::enqueueScan(const std::string& target) const {
    logger_.log(LogLevel::Debug, "Enqueuing target for scan: " + target);
    return !target.empty();
}

bool RealtimeScanModule::inspectTarget(const std::string& target) const {
    return target.find("evil") == std::string::npos;
}

} // namespace everbloom::driver
