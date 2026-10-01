#include "core_protection.hpp"

#include <iostream>

namespace everbloom::driver {

CoreProtectionEngine::CoreProtectionEngine(EventBus& bus, Logger& logger)
    : event_bus_(bus), logger_(logger) {
}

void CoreProtectionEngine::initialize() {
    shutdown();
    modules_.clear();
    modules_.push_back("self_protection");
    modules_.push_back("file_protection");
    modules_.push_back("amsi");
    modules_.push_back("realtime_scan");
    modules_.push_back("network_firewall");
    modules_.push_back("advanced_threat");

    for (const auto& name : modules_) {
        module_weights_[name] = ThreatLevel::Low;
    }

    // EventContext::target carries the concrete path/process/endpoint. These
    // built-in rules are module policies, so they intentionally leave target
    // empty instead of comparing it with a category label such as "file".
    policy_rules_.push_back({"file_protection", "file_protection", "", 10, ThreatLevel::High, ResponseAction::Block, "Block high-risk file operations"});
    policy_rules_.push_back({"amsi", "amsi", "", 5, ThreatLevel::Medium, ResponseAction::Notify, "Notify on AMSI detections"});
    policy_rules_.push_back({"self_protection", "self_protection", "", 20, ThreatLevel::Critical, ResponseAction::Terminate, "Terminate on self-protection bypass attempts"});
}

void CoreProtectionEngine::shutdown() {
    modules_.clear();
    module_weights_.clear();
    policy_rules_.clear();
}

PolicyDecision CoreProtectionEngine::applyPolicyRules(const EventContext& ctx) const {
    PolicyDecision decision;
    decision.request_id = ctx.request_id;
    decision.level = ctx.level;
    decision.action = ResponseAction::Log;
    decision.reason = "default policy";

    const PolicyRule* best_rule = nullptr;
    for (const auto& rule : policy_rules_) {
        if (rule.matches(ctx)) {
            if (!best_rule || rule.priority > best_rule->priority) {
                best_rule = &rule;
            }
        }
    }

    if (best_rule) {
        decision.level = ctx.level;
        decision.action = best_rule->response;
        decision.reason = best_rule->reason;
        decision.matched_source = best_rule->source;
        decision.matched_module = best_rule->module;
    }

    return decision;
}

PolicyDecision CoreProtectionEngine::evaluate(const EventContext& ctx) const {
    logger_.log(LogLevel::Debug, "Evaluating event: " + ctx.source + " -> " + ctx.detail);

    PolicyDecision decision = applyPolicyRules(ctx);
    const auto module_name = ctx.module.empty() ? ctx.source : ctx.module;
    if (const auto it = module_weights_.find(module_name);
        it != module_weights_.end()
        && ctx.level >= it->second
        && it->second > decision.level) {
        decision.level = it->second;
        switch (it->second) {
            case ThreatLevel::Critical:
                decision.action = ResponseAction::Terminate;
                break;
            case ThreatLevel::High:
                decision.action = ResponseAction::Block;
                break;
            case ThreatLevel::Medium:
                decision.action = ResponseAction::Notify;
                break;
            case ThreatLevel::Low:
                break;
        }
        decision.reason = "escalated by module risk: " + module_name;
        decision.matched_module = module_name;
    }

    Event event;
    event.request_id = ctx.request_id;
    event.source = ctx.source;
    event.module = module_name;
    event.message = ctx.detail;
    event.threat = decision.level;
    event.severity = decision.action == ResponseAction::Terminate
        ? EventSeverity::Critical
        : decision.action == ResponseAction::Block
            ? EventSeverity::Error
            : decision.action == ResponseAction::Notify
                ? EventSeverity::Warning
                : EventSeverity::Info;
    event_bus_.publish(event);

    logger_.log(
        LogLevel::Info,
        "Policy decision request=" + std::to_string(ctx.request_id)
            + " reason=" + decision.reason
            + " module=" + decision.matched_module
            + " action=" + toString(decision.action));
    return decision;
}

void CoreProtectionEngine::registerModule(const std::string& name) {
    if (!isModuleRegistered(name)) {
        modules_.push_back(name);
        module_weights_[name] = ThreatLevel::Medium;
        logger_.log(LogLevel::Info, "Registered module: " + name);
    }
}

void CoreProtectionEngine::addPolicyRule(const PolicyRule& rule) {
    policy_rules_.push_back(rule);
    std::sort(policy_rules_.begin(), policy_rules_.end(), [](const PolicyRule& a, const PolicyRule& b) {
        return a.priority > b.priority;
    });
    logger_.log(LogLevel::Debug, "Added policy rule for source: " + rule.source + " module: " + rule.module + " priority=" + std::to_string(rule.priority));
}

void CoreProtectionEngine::setModuleRisk(const std::string& module, ThreatLevel level) {
    if (isModuleRegistered(module)) {
        module_weights_[module] = level;
        logger_.log(LogLevel::Debug, "Module " + module + " risk set to " + std::to_string(static_cast<int>(level)));
    }
}

bool CoreProtectionEngine::isModuleRegistered(const std::string& module) const {
    return std::find(modules_.begin(), modules_.end(), module) != modules_.end();
}

} // namespace everbloom::driver
