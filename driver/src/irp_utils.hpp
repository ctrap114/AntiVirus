#pragma once

#include "driver_types.hpp"
#include <string>
#include <sstream>

namespace everbloom::driver {

inline IRP parseIprFromPayload(const std::string& payload) {
    IRP irp{};
    // simple key=value;key2=value2 parser
    std::istringstream ss(payload);
    std::string token;
    while (std::getline(ss, token, ';')) {
        auto pos = token.find('=');
        if (pos == std::string::npos) continue;
        std::string k = token.substr(0, pos);
        std::string v = token.substr(pos + 1);
        if (k == "IOCTL") irp.IoControlCode = static_cast<uint32_t>(std::stoul(v, nullptr, 0));
        else if (k == "Caller") irp.Caller = v;
        else if (k == "Target") irp.Target = v;
        else if (k == "Data") irp.Payload = v;
    }
    return irp;
}

inline std::string makeIprPayload(uint32_t code, const std::string& caller, const std::string& target, const std::string& data) {
    std::ostringstream ss;
    ss << "IOCTL=" << code << ";Caller=" << caller << ";Target=" << target << ";Data=" << data;
    return ss.str();
}

} // namespace everbloom::driver
