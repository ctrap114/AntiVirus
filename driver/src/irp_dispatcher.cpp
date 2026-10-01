#include "irp_dispatcher.hpp"

#include <algorithm>

namespace everbloom::driver {

IrpDispatcher::IrpDispatcher(EventBus& bus, Logger& logger, CoreProtectionEngine& engine)
    : event_bus_(bus), logger_(logger), engine_(engine) {
}

void IrpDispatcher::registerHandler(const std::string& module, int priority, std::function<IoctlResult(const IRP&)> handler) {
    registerHandler(module, {}, priority, std::move(handler));
}

void IrpDispatcher::registerHandler(const std::string& module,
                                    const std::vector<uint32_t>& ioctl_codes,
                                    int priority,
                                    std::function<IoctlResult(const IRP&)> handler) {
    handlers_.push_back({module, ioctl_codes, priority, std::move(handler)});
    std::sort(handlers_.begin(), handlers_.end(), [](const IrpHandlerEntry& a, const IrpHandlerEntry& b) {
        return a.priority > b.priority;
    });
    logger_.log(
        LogLevel::Debug,
        "Registered IOCTL handler: " + module
            + " priority=" + std::to_string(priority)
            + " codes=" + std::to_string(ioctl_codes.size()));
}

IoctlResult IrpDispatcher::dispatch(const IRP& irp) {
    IRP request = irp;
    if (request.request_id == 0) {
        request.request_id = next_request_id_.fetch_add(1, std::memory_order_relaxed);
    }
    logger_.log(
        LogLevel::Info,
        "Dispatching IRP request=" + std::to_string(request.request_id)
            + " IoControlCode=" + std::to_string(request.IoControlCode)
            + " target=" + request.Target);

    Event publish_event;
    publish_event.type = EventType::Ioctl;
    publish_event.request_id = request.request_id;
    publish_event.source = "dispatcher";
    publish_event.module = "ioctl";
    publish_event.message = "IRP dispatch";
    publish_event.irp = request;
    publish_event.threat = ThreatLevel::Low;
    publish_event.severity = EventSeverity::Info;
    event_bus_.publish(publish_event);

    IoctlResult result;
    result.request_id = request.request_id;
    for (const auto& entry : handlers_) {
        if (!entry.ioctl_codes.empty()
            && std::find(entry.ioctl_codes.begin(), entry.ioctl_codes.end(), request.IoControlCode)
                == entry.ioctl_codes.end()) {
            continue;
        }

        logger_.log(
            LogLevel::Debug,
            "Invoking handler " + entry.module
                + " request=" + std::to_string(request.request_id));
        IoctlResult handler_result = entry.handler(request);
        if (!handler_result.handled) {
            continue;
        }
        handler_result.request_id = request.request_id;
        result.handled = true;
        if (handler_result.threat > result.threat) {
            result.threat = handler_result.threat;
        }
        if (handler_result.action > result.action) {
            result.action = handler_result.action;
        }
        if (!handler_result.reason.empty()) {
            result.reason = handler_result.reason;
        }

        Event module_event;
        module_event.type = EventType::Policy;
        module_event.request_id = request.request_id;
        module_event.source = entry.module;
        module_event.module = entry.module;
        module_event.message = handler_result.reason.empty() ? "IOCTL handler result" : handler_result.reason;
        module_event.irp = request;
        module_event.threat = handler_result.threat;
        module_event.severity = handler_result.action == ResponseAction::Terminate
            ? EventSeverity::Critical
            : handler_result.action == ResponseAction::Block
                ? EventSeverity::Error
                : handler_result.action == ResponseAction::Notify
                    ? EventSeverity::Warning
                    : EventSeverity::Info;
        event_bus_.publish(module_event);

        const EventContext context{
            entry.module,
            entry.module,
            request.Target,
            module_event.message,
            handler_result.threat,
            request.request_id};
        const PolicyDecision policy = engine_.evaluate(context);
        if (policy.level > result.threat) {
            result.threat = policy.level;
        }
        if (policy.action > result.action) {
            result.action = policy.action;
        }
        const bool policy_rule_applied = !policy.matched_source.empty()
            || !policy.matched_module.empty()
            || policy.action != ResponseAction::Log;
        if (policy_rule_applied && !policy.reason.empty()) {
            if (result.reason.empty()) {
                result.reason = policy.reason;
            } else if (result.reason != policy.reason) {
                // Preserve the module's concrete finding while retaining the
                // higher-level policy explanation. A weaker Notify rule must
                // not hide a handler's Block/Terminate reason.
                result.reason += "; policy=" + policy.reason;
            }
        }

        if (handler_result.stopProcessing
            || handler_result.action == ResponseAction::Block
            || handler_result.action == ResponseAction::Terminate
            || policy.action == ResponseAction::Block
            || policy.action == ResponseAction::Terminate) {
            logger_.log(
                LogLevel::Info,
                "Stopping dispatch after handler " + entry.module
                    + " request=" + std::to_string(request.request_id));
            break;
        }
    }

    Event response;
    response.type = EventType::DriverResponse;
    response.request_id = request.request_id;
    response.source = "dispatcher";
    response.module = "driver";
    response.message = result.handled ? result.reason : "no matching handler";
    response.irp = request;
    response.threat = result.threat;
    response.severity = result.action == ResponseAction::Terminate
        ? EventSeverity::Critical
        : result.action == ResponseAction::Block
            ? EventSeverity::Error
            : result.action == ResponseAction::Notify
                ? EventSeverity::Warning
                : EventSeverity::Info;
    event_bus_.publish(response);
    return result;
}

} // namespace everbloom::driver
