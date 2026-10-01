#pragma once

#include "driver_types.hpp"
#include "event_bus.hpp"
#include "logger.hpp"

#include <algorithm>
#include <string>
#include <vector>
#include <unordered_map>

namespace everbloom::driver {

struct PolicyRule {
    std::string module;
    std::string source;
    std::string target;
    int priority{0};
    ThreatLevel minimum_level{ThreatLevel::Low};
    ResponseAction response{ResponseAction::Notify};
    std::string reason;

    bool matches(const EventContext& ctx) const {
        if (!source.empty() && source != ctx.source) {
            return false;
        }
        if (!module.empty() && module != ctx.module) {
            return false;
        }
        if (!target.empty() && target != ctx.target) {
            return false;
        }
        return ctx.level >= minimum_level;
    }
};

class CoreProtectionEngine {
public:
    CoreProtectionEngine(EventBus& bus, Logger& logger);
    void initialize();
    void shutdown();
    PolicyDecision evaluate(const EventContext& ctx) const;
    void registerModule(const std::string& name);
    void addPolicyRule(const PolicyRule& rule);
    void setModuleRisk(const std::string& module, ThreatLevel level);
    bool isModuleRegistered(const std::string& module) const;

private:
    PolicyDecision applyPolicyRules(const EventContext& ctx) const;
    EventBus& event_bus_;
    Logger& logger_;
    std::vector<std::string> modules_;
    std::vector<PolicyRule> policy_rules_;
    std::unordered_map<std::string, ThreatLevel> module_weights_;
};

} // namespace everbloom::driver
