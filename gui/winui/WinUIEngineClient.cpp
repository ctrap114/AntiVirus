#include "WinUIEngineClient.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>

#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>

namespace everbloom::gui {

void NotifyWinUiStage(const std::wstring& stage);

namespace {

constexpr size_t kMaximumQueuedRequests = 256;
constexpr size_t kMaximumLineSize = 16U * 1024U * 1024U;
constexpr uint32_t kMaximumR3EventsPerSecond = 8;
// AI inference plus a disposable VM/AppContainer can legitimately take
// longer than a normal static scan. Keep this timeout independent from the
// normal GUI scan timeout so the protocol deadline does not kill a healthy
// sandbox session while it is still collecting evidence.
constexpr uint32_t kAiSandboxScanTimeoutMs = 5U * 60U * 1000U;

using winrt::Windows::Data::Json::JsonArray;
using winrt::Windows::Data::Json::JsonObject;

std::string ToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        size,
        nullptr,
        nullptr);
    return result;
}

std::wstring FromUtf8(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    if (size <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        size);
    return result;
}

std::string JsonString(const std::wstring& value) {
    const std::string utf8 = ToUtf8(value);
    std::string result;
    result.reserve(utf8.size() + 2);
    result.push_back('"');
    for (const unsigned char character : utf8) {
        switch (character) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (character < 0x20) {
                std::ostringstream escaped;
                escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<unsigned int>(character);
                result += escaped.str();
            } else {
                result.push_back(static_cast<char>(character));
            }
            break;
        }
    }
    result.push_back('"');
    return result;
}

std::wstring NormalizePath(const std::wstring& path) {
    std::wstring normalized = path;
    std::replace(normalized.begin(), normalized.end(), L'\\', L'/');
    return normalized;
}

uint32_t EffectiveScanTimeout(
    uint32_t requested_timeout_ms,
    bool sandbox_enabled,
    bool ai_enabled) {
    if (sandbox_enabled && ai_enabled) {
        return std::max(requested_timeout_ms, kAiSandboxScanTimeoutMs);
    }
    return requested_timeout_ms;
}

std::wstring NamedString(const JsonObject& object, const wchar_t* name) {
    if (!object) {
        return {};
    }
    try {
        return std::wstring(object.GetNamedString(name, L"").c_str());
    } catch (...) {
        return {};
    }
}

double NamedNumber(const JsonObject& object, const wchar_t* name, double fallback = 0.0) {
    if (!object) {
        return fallback;
    }
    try {
        return object.GetNamedNumber(name, fallback);
    } catch (...) {
        return fallback;
    }
}

bool NamedBool(const JsonObject& object, const wchar_t* name, bool fallback = false) {
    if (!object) {
        return fallback;
    }
    try {
        return object.GetNamedBoolean(name, fallback);
    } catch (...) {
        return fallback;
    }
}

uint64_t NamedUInt64(const JsonObject& object, const wchar_t* name) {
    const double value = NamedNumber(object, name, 0.0);
    return value > 0.0 ? static_cast<uint64_t>(value) : 0;
}

JsonObject NamedObject(const JsonObject& object, const wchar_t* name) {
    if (!object) {
        return nullptr;
    }
    try {
        return object.GetNamedObject(name, nullptr);
    } catch (...) {
        return nullptr;
    }
}

JsonArray NamedArray(const JsonObject& object, const wchar_t* name) {
    if (!object) {
        return nullptr;
    }
    try {
        return object.GetNamedArray(name, nullptr);
    } catch (...) {
        return nullptr;
    }
}

std::vector<std::wstring> NamedStringArray(const JsonObject& object, const wchar_t* name) {
    std::vector<std::wstring> values;
    const JsonArray array = NamedArray(object, name);
    if (!array) {
        return values;
    }
    for (uint32_t index = 0; index < array.Size(); ++index) {
        try {
            values.push_back(std::wstring(array.GetStringAt(index).c_str()));
        } catch (...) {
            // Ignore one malformed optional diagnostic item.
        }
    }
    return values;
}

std::wstring FileNameOf(const std::wstring& path) {
    const std::filesystem::path filesystem_path(path);
    if (const auto name = filesystem_path.filename().wstring(); !name.empty()) {
        return name;
    }
    return path;
}

std::string BoolJson(bool value) {
    return value ? "true" : "false";
}

std::string BuildScanLine(
    const std::wstring& path,
    uint64_t sequence,
    uint32_t timeout_ms,
    bool sandbox_enabled,
    bool yara_enabled,
    bool ai_enabled,
    bool heuristic_enabled,
    float ai_threshold,
    uint64_t maximum_file_size,
    bool cloud_enabled) {
    const uint64_t maximum_file_size_mb = maximum_file_size == 0
        ? 0
        : std::max<uint64_t>(1, (maximum_file_size + (1024 * 1024 - 1)) / (1024 * 1024));
    std::ostringstream json;
    const std::wstring normalized_path = NormalizePath(path);
    const std::wstring task_id = L"gui-" + std::to_wstring(GetCurrentProcessId()) + L"-"
        + std::to_wstring(sequence);
    json << "{\"task_info\":{\"task_id\":" << JsonString(task_id)
         << ",\"priority\":\"NORMAL\",\"timeout_ms\":" << timeout_ms
         << "},\"target\":{\"type\":\"LOCAL_PATH\",\"file_path\":"
         << JsonString(normalized_path) << ",\"file_name\":"
         << JsonString(FileNameOf(path)) << "},\"scan_options\":{"
         << "\"enable_heuristics\":" << BoolJson(heuristic_enabled)
         << ",\"max_archive_depth\":3";
    if (maximum_file_size_mb > 0) {
        json << ",\"max_file_size_mb\":" << maximum_file_size_mb;
    }
    json << ",\"enable_yara\":" << BoolJson(yara_enabled)
         << ",\"enable_ai\":" << BoolJson(ai_enabled)
         << ",\"enable_sandbox\":" << BoolJson(sandbox_enabled)
         << ",\"ai_threshold\":" << std::fixed << std::setprecision(5)
         << std::clamp(ai_threshold, 0.0f, 1.0f)
         << ",\"cloud_enabled\":" << BoolJson(cloud_enabled) << "}}\n";
    return json.str();
}

std::string BuildCommandLine(
    const char* command,
    const std::wstring* path = nullptr,
    const std::wstring* strategy = nullptr,
    bool r3_enabled = false,
    bool driver_enabled = false) {
    std::ostringstream json;
    json << "{\"command\":\"" << command << "\"";
    if (path != nullptr) {
        json << ",\"path\":" << JsonString(NormalizePath(*path));
    }
    if (strategy != nullptr) {
        json << ",\"strategy\":" << JsonString(*strategy);
    }
    if (std::string_view(command) == "SET_PROTECTION_MODES") {
        json << ",\"r3_enabled\":" << BoolJson(r3_enabled)
             << ",\"driver_enabled\":" << BoolJson(driver_enabled);
    }
    json << "}\n";
    return json.str();
}

std::string BuildQuarantineFileLine(const std::wstring& path, const std::wstring& reason) {
    std::ostringstream json;
    json << "{\"command\":\"QUARANTINE_FILE\",\"path\":"
         << JsonString(NormalizePath(path));
    if (!reason.empty()) {
        json << ",\"reason\":" << JsonString(reason);
    }
    json << "}\n";
    return json.str();
}

std::string BuildQuarantineRestoreLine(
    const std::wstring& id,
    const std::wstring& restore_path,
    bool overwrite) {
    std::ostringstream json;
    json << "{\"command\":\"RESTORE_QUARANTINE\",\"id\":" << JsonString(id);
    if (!restore_path.empty()) {
        json << ",\"restore_path\":" << JsonString(NormalizePath(restore_path));
    }
    json << ",\"overwrite\":" << BoolJson(overwrite) << "}\n";
    return json.str();
}

std::string BuildQuarantineDeleteLine(const std::wstring& id) {
    std::ostringstream json;
    json << "{\"command\":\"DELETE_QUARANTINE\",\"id\":" << JsonString(id) << "}\n";
    return json.str();
}

std::string BuildQuarantineListLine(bool include_inactive) {
    std::ostringstream json;
    json << "{\"command\":\"LIST_QUARANTINE\",\"include_inactive\":"
         << BoolJson(include_inactive) << "}\n";
    return json.str();
}

EngineQuarantineItem ParseQuarantineItem(const JsonObject& object) {
    EngineQuarantineItem item;
    if (!object) {
        return item;
    }
    item.id = NamedString(object, L"id");
    item.original_path = NormalizePath(NamedString(object, L"original_path"));
    item.quarantine_path = NormalizePath(NamedString(object, L"quarantine_path"));
    item.restore_path = NormalizePath(NamedString(object, L"restore_path"));
    item.status = NamedString(object, L"status");
    item.message = NamedString(object, L"message");
    return item;
}

void LogClientStage(const std::wstring& stage) {
    NotifyWinUiStage(L"EngineClient: " + stage);
}

} // namespace

EngineClient::EngineClient(
    std::wstring endpoint,
    winrt::Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
    HANDLE stdin_write,
    HANDLE stdout_read)
    : m_endpoint(std::move(endpoint)),
      m_dispatcher(std::move(dispatcher)),
      m_stdin_write(stdin_write),
      m_stdout_read(stdout_read) {}

EngineClient::~EngineClient() {
    Stop();
}

void EngineClient::Start() {
    bool expected = false;
    if (!m_started.compare_exchange_strong(expected, true)) {
        return;
    }
    m_stop.store(false);
    m_cancel_scan_requested.store(false);
    m_exit_sent.store(false);
    m_timeout_reported.store(false);
    m_worker = std::thread([this] { WorkerLoop(); });
    m_writer = std::thread([this] { WriteLoop(); });
    m_watchdog = std::thread([this] { WatchdogLoop(); });
    LogClientStage(L"NDJSON worker and writer started");
}

void EngineClient::Stop() {
    if (!m_started.exchange(false)) {
        return;
    }

    // EXIT is best-effort. If a scan is in progress, closing stdin/stdout is
    // safer than blocking the GUI while the engine is already past its read
    // boundary; EngineProcess supplies a termination fallback afterwards.
    bool request_in_flight = false;
    {
        std::lock_guard lock(m_write_queue_mutex);
        request_in_flight = m_waiting_response;
    }
    if (m_ready.load() && !m_scan_active.load() && !request_in_flight
        && !m_exit_sent.exchange(true)) {
        const std::string exit_line = "{\"command\":\"EXIT\"}\n";
        WriteLine(exit_line);
    }
    m_stop.store(true);
    m_cancel_scan_requested.store(true);
    m_ready.store(false);
    m_connected.store(false);
    CloseTransport();
    m_write_queue_cv.notify_all();
    if (m_worker.joinable()) {
        m_worker.join();
    }
    if (m_writer.joinable()) {
        m_writer.join();
    }
    if (m_watchdog.joinable()) {
        m_watchdog.join();
    }
    {
        std::lock_guard lock(m_write_queue_mutex);
        m_write_queue.clear();
        m_inflight_line.clear();
        m_inflight_scan = false;
        m_waiting_response = false;
    }
    m_scan_active.store(false);
    m_scan_deadline_ms.store(0);
    m_timeout_reported.store(false);
    m_r3_event_window_started_ms = 0;
    m_r3_event_window_count = 0;
    m_r3_event_window_suppressed = 0;
    {
        std::lock_guard lock(m_realtime_mutex);
        m_realtime_paths.clear();
    }
}

void EngineClient::CancelScan() {
    m_cancel_scan_requested.store(true);
    bool request_in_flight = false;
    {
        std::lock_guard lock(m_write_queue_mutex);
        for (auto it = m_write_queue.begin(); it != m_write_queue.end();) {
            if (it->scan_request && !it->realtime) {
                it = m_write_queue.erase(it);
            } else {
                ++it;
            }
        }
        request_in_flight = m_inflight_scan;
        m_scan_total = m_scan_processed + (request_in_flight ? 1 : 0);
        if (!request_in_flight) {
            m_scan_active.store(false);
            m_scan_deadline_ms.store(0);
        }
    }
    // The protocol is deliberately one-question/one-answer. A second control
    // frame cannot be consumed while Rust is scanning, so cancellation is
    // cooperative: queued work is removed immediately and the in-flight
    // request is allowed to return its timeout/cancelled response.
    LogClientStage(L"manual scan cancellation requested");
    m_write_queue_cv.notify_one();
}

std::wstring EngineClient::Endpoint() const {
    return m_endpoint.empty() ? L"stdin/stdout NDJSON" : m_endpoint;
}

void EngineClient::SetProgressHandler(ProgressHandler handler) {
    std::lock_guard lock(m_handler_mutex);
    m_progress_handler = std::move(handler);
}

void EngineClient::SetResponseHandler(ResponseHandler handler) {
    std::lock_guard lock(m_handler_mutex);
    m_response_handler = std::move(handler);
}

void EngineClient::SetConnectionHandler(ConnectionHandler handler) {
    const bool should_report_current_state = m_started.load() || m_connected.load();
    const bool connected = m_connected.load();
    std::lock_guard lock(m_handler_mutex);
    m_connection_handler = std::move(handler);
    if (should_report_current_state && m_connection_handler) {
        Dispatch([handler = m_connection_handler, connected] { handler(connected); });
    }
}

void EngineClient::SetErrorHandler(ErrorHandler handler) {
    std::lock_guard lock(m_handler_mutex);
    m_error_handler = std::move(handler);
}

void EngineClient::SetConfigHandler(ConfigHandler handler) {
    std::lock_guard lock(m_handler_mutex);
    m_config_handler = std::move(handler);
}

void EngineClient::SetDriverAvailabilityHandler(DriverAvailabilityHandler handler) {
    std::lock_guard lock(m_handler_mutex);
    m_driver_availability_handler = std::move(handler);
}

void EngineClient::SetRealtimeThreatHandler(RealtimeThreatHandler handler) {
    std::lock_guard lock(m_handler_mutex);
    m_realtime_threat_handler = std::move(handler);
}

void EngineClient::SetQuarantineHandler(QuarantineHandler handler) {
    std::lock_guard lock(m_handler_mutex);
    m_quarantine_handler = std::move(handler);
}

void EngineClient::SetModelValidationHandler(ModelValidationHandler handler) {
    std::lock_guard lock(m_handler_mutex);
    m_model_validation_handler = std::move(handler);
}

void EngineClient::RequestScan(
    std::vector<std::wstring> paths,
    uint32_t timeout_ms,
    bool sandbox_enabled,
    bool yara_enabled,
    bool ai_enabled,
    bool heuristic_enabled,
    float ai_threshold,
    uint64_t maximum_file_size,
    bool realtime,
    bool cloud_enabled) {
    paths.erase(
        std::remove_if(paths.begin(), paths.end(), [](const auto& path) { return path.empty(); }),
        paths.end());
    if (paths.empty()) {
        ReportError(L"No scan path was supplied.");
        return;
    }
    const uint32_t effective_timeout_ms =
        EffectiveScanTimeout(timeout_ms, sandbox_enabled, ai_enabled);
    if (effective_timeout_ms != timeout_ms) {
        LogClientStage(
            L"AI_SANDBOX_TIMEOUT timeout_ms=" + std::to_wstring(effective_timeout_ms)
            + L" requested_ms=" + std::to_wstring(timeout_ms));
    }
    if (!realtime) {
        std::lock_guard lock(m_write_queue_mutex);
        const bool manual_already_present = m_scan_active.load()
            || m_inflight_scan
            || std::any_of(m_write_queue.begin(), m_write_queue.end(), [](const auto& item) {
                   return item.scan_request && !item.realtime;
               });
        if (manual_already_present) {
            ReportError(L"A manual scan is already queued or running.");
            return;
        }
        m_scan_total = 0;
        m_scan_processed = 0;
        m_scan_threats = 0;
        m_scan_errors = 0;
        m_cancel_scan_requested.store(false);
        m_timeout_reported.store(false);
        m_scan_active.store(true);
        m_scan_deadline_ms.store(0);
    }

    size_t accepted = 0;
    for (const auto& path : paths) {
        const std::string line = BuildScanLine(
            path,
            ++m_task_sequence,
            effective_timeout_ms,
            sandbox_enabled,
            yara_enabled,
            ai_enabled,
            heuristic_enabled,
            ai_threshold,
            maximum_file_size,
            cloud_enabled);
        if (QueueLine(line, realtime, !realtime, path, effective_timeout_ms)) {
            ++accepted;
            if (!realtime) {
                ++m_scan_total;
            }
        }
    }
    if (accepted == 0 && !realtime) {
        m_scan_active.store(false);
        m_scan_deadline_ms.store(0);
        ReportError(L"The scan request could not be queued.");
    }
    if (accepted > 0 && realtime) {
        std::lock_guard lock(m_realtime_mutex);
        for (const auto& path : paths) {
            m_realtime_paths.insert(NormalizePath(path));
        }
        while (m_realtime_paths.size() > 512) {
            m_realtime_paths.erase(m_realtime_paths.begin());
        }
    }
}

void EngineClient::RequestConfigReload() {
    QueueLine(BuildCommandLine("RELOAD_HASH_DATABASE"), false, false);
}

void EngineClient::RequestHashDatabaseImport(const std::wstring& path) {
    if (path.empty()) {
        ReportError(L"The hash database import request had no file path.");
        return;
    }
    QueueLine(BuildCommandLine("IMPORT_HASH_DATABASE", &path), false, false);
}

void EngineClient::RequestModelImport(const std::wstring& path) {
    if (path.empty()) {
        ReportError(L"The model import request had no file path.");
        return;
    }
    QueueLine(BuildCommandLine("IMPORT_MODEL", &path), false, false);
}

void EngineClient::RequestModelValidate(const std::wstring& path) {
    if (path.empty()) {
        ReportError(L"The model validation request had no file path.");
        return;
    }
    QueueLine(BuildCommandLine("VALIDATE_MODEL", &path), false, false);
}

void EngineClient::RequestModelStrategy(const std::wstring& strategy) {
    if (strategy.empty()) {
        ReportError(L"The model strategy request was empty.");
        return;
    }
    QueueLine(BuildCommandLine("SET_AI_STRATEGY", nullptr, &strategy), false, false);
}

void EngineClient::RequestProtectionModes(bool r3_enabled, bool driver_enabled) {
    m_driver_protection_enabled.store(driver_enabled);
    QueueLine(
        BuildCommandLine("SET_PROTECTION_MODES", nullptr, nullptr, r3_enabled, driver_enabled),
        false,
        false);
}

void EngineClient::RequestFileBlock(const std::wstring& path) {
    if (path.empty()) {
        ReportError(L"The real-time block request had no file path.");
        return;
    }
    QueueLine(BuildCommandLine("BLOCK_FILE", &path), false, false);
}

void EngineClient::RequestFileAllow(const std::wstring& path) {
    if (path.empty()) {
        ReportError(L"The real-time allow request had no file path.");
        return;
    }
    QueueLine(BuildCommandLine("ALLOW_FILE", &path), false, false);
}

void EngineClient::RequestAllowlistAdd(const std::wstring& path) {
    if (path.empty()) {
        ReportError(L"The allowlist add request had no file path.");
        return;
    }
    QueueLine(BuildCommandLine("ALLOWLIST_ADD", &path), false, false);
}

void EngineClient::RequestFileQuarantine(const std::wstring& path, const std::wstring& reason) {
    if (path.empty()) {
        ReportError(L"The quarantine request had no file path.");
        return;
    }
    QueueLine(BuildQuarantineFileLine(path, reason), false, false);
}

void EngineClient::RequestQuarantineRestore(
    const std::wstring& id,
    const std::wstring& restore_path,
    bool overwrite) {
    if (id.empty()) {
        ReportError(L"The quarantine restore request had no item id.");
        return;
    }
    QueueLine(BuildQuarantineRestoreLine(id, restore_path, overwrite), false, false);
}

void EngineClient::RequestQuarantineDelete(const std::wstring& id) {
    if (id.empty()) {
        ReportError(L"The quarantine delete request had no item id.");
        return;
    }
    QueueLine(BuildQuarantineDeleteLine(id), false, false);
}

void EngineClient::RequestQuarantineList(bool include_inactive) {
    QueueLine(BuildQuarantineListLine(include_inactive), false, false);
}

bool EngineClient::QueueLine(
    std::string line,
    bool realtime,
    bool scan_request,
    std::wstring path,
    uint32_t timeout_ms) {
    if (!m_started.load()) {
        if (!realtime) {
            ReportError(L"The engine is still starting; request was not sent.");
        }
        return false;
    }
    if (line.empty() || line.size() > kMaximumLineSize) {
        ReportError(L"The engine NDJSON request was empty or oversized.");
        return false;
    }
    bool rejected = false;
    {
        std::lock_guard lock(m_write_queue_mutex);
        while (m_write_queue.size() >= kMaximumQueuedRequests) {
            const auto realtime_to_drop = std::find_if(
                m_write_queue.begin(),
                m_write_queue.end(),
                [](const auto& item) { return item.realtime; });
            if (realtime_to_drop == m_write_queue.end()) {
                rejected = true;
                break;
            }
            m_write_queue.erase(realtime_to_drop);
        }
        if (!rejected) {
            m_write_queue.push_back(QueuedLine{
                std::move(line), realtime, scan_request, std::move(path), timeout_ms});
        }
    }
    if (rejected) {
        if (!realtime) {
            ReportError(L"The engine request queue is full; request was not sent.");
        }
        return false;
    }
    m_write_queue_cv.notify_one();
    return true;
}

void EngineClient::CloseTransport() {
    std::lock_guard lock(m_write_mutex);
    if (m_stdin_write != INVALID_HANDLE_VALUE) {
        CloseHandle(m_stdin_write);
        m_stdin_write = INVALID_HANDLE_VALUE;
    }
    if (m_stdout_read != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_stdout_read, nullptr);
        CloseHandle(m_stdout_read);
        m_stdout_read = INVALID_HANDLE_VALUE;
    }
}

bool EngineClient::WriteLine(const std::string& line) {
    std::lock_guard lock(m_write_mutex);
    if (m_stdin_write == INVALID_HANDLE_VALUE || line.empty()) {
        return false;
    }
    size_t offset = 0;
    while (offset < line.size()) {
        DWORD written = 0;
        const DWORD requested = static_cast<DWORD>(std::min<size_t>(
            line.size() - offset,
            std::numeric_limits<DWORD>::max()));
        if (!WriteFile(m_stdin_write, line.data() + offset, requested, &written, nullptr)
            || written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

void EngineClient::WorkerLoop() {
    // Windows.Data.Json is a WinRT API.  This reader runs on a std::thread,
    // not on the XAML thread, so it must explicitly enter an apartment before
    // parsing frames.  Without this, a WinRT virtual call can dereference an
    // uninitialized apartment state and terminate the GUI with 0xc0000005.
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
    } catch (...) {
        LogClientStage(L"NDJSON worker could not initialize the WinRT apartment");
        ReportError(L"The engine reader could not initialize its WinRT apartment.");
        return;
    }

    std::string buffer;
    std::array<char, 8192> chunk{};
    bool ready_reported = false;
    while (!m_stop.load()) {
        DWORD read = 0;
        if (m_stdout_read == INVALID_HANDLE_VALUE) {
            LogClientStage(L"RUST_ENGINE_STDOUT_CLOSED reason=invalid_handle");
            break;
        }
        if (!ReadFile(
                m_stdout_read,
                chunk.data(),
                static_cast<DWORD>(chunk.size()),
                &read,
                nullptr)) {
            LogClientStage(
                L"RUST_ENGINE_STDOUT_CLOSED reason=read_error win32="
                + std::to_wstring(GetLastError()));
            break;
        }
        if (read == 0) {
            LogClientStage(L"RUST_ENGINE_STDOUT_CLOSED reason=eof");
            break;
        }
        m_last_engine_activity_ms.store(GetTickCount64());
        buffer.append(chunk.data(), read);
        if (buffer.size() > kMaximumLineSize) {
            ReportError(L"The engine returned an oversized NDJSON line.");
            break;
        }
        size_t newline = 0;
        while ((newline = buffer.find('\n')) != std::string::npos) {
            std::string line = buffer.substr(0, newline);
            buffer.erase(0, newline + 1);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (!line.empty()) {
                DecodeJsonLine(line);
            }
            if (!ready_reported && m_ready.load()) {
                ready_reported = true;
            }
        }
    }
    m_ready.store(false);
    const bool was_connected = m_connected.exchange(false);
    if (was_connected) {
        LogClientStage(L"NDJSON stdout closed; engine disconnected");
        ReportConnection(false);
    }
    if (!m_stop.load() && !m_exit_sent.load()) {
        ReportError(L"The engine NDJSON stream closed before the expected response.");
    }
    winrt::uninit_apartment();
}

void EngineClient::WriteLoop() {
    while (!m_stop.load()) {
        QueuedLine queued;
        {
            std::unique_lock lock(m_write_queue_mutex);
            m_write_queue_cv.wait(lock, [this] {
                return m_stop.load()
                    || (m_ready.load() && !m_waiting_response && !m_write_queue.empty());
            });
            if (m_stop.load()) {
                return;
            }
            if (m_write_queue.empty()) {
                continue;
            }
            queued = std::move(m_write_queue.front());
            m_write_queue.pop_front();
        }

        if (queued.scan_request && !queued.realtime && m_cancel_scan_requested.load()) {
            std::lock_guard lock(m_write_queue_mutex);
            m_inflight_line.clear();
            m_inflight_scan = false;
            continue;
        }

        {
            std::lock_guard lock(m_write_queue_mutex);
            m_inflight_line = queued.line;
            m_inflight_scan = queued.scan_request && !queued.realtime;
            m_waiting_response = true;
            if (queued.scan_request && queued.timeout_ms > 0) {
                m_scan_deadline_ms.store(GetTickCount64() + queued.timeout_ms);
            } else {
                m_scan_deadline_ms.store(0);
            }
        }
        if (!WriteLine(queued.line)) {
            ReportError(L"The engine stdin pipe could not accept the NDJSON request.");
            std::lock_guard lock(m_write_queue_mutex);
            m_inflight_line.clear();
            m_inflight_scan = false;
            m_waiting_response = false;
            m_scan_deadline_ms.store(0);
            CloseTransport();
        } else {
            std::lock_guard lock(m_write_queue_mutex);
            m_inflight_line.clear();
        }
    }
}

void EngineClient::WatchdogLoop() {
    while (!m_stop.load()) {
        const ULONGLONG deadline = m_scan_deadline_ms.load();
        if (m_scan_active.load() && deadline != 0 && GetTickCount64() >= deadline
            && !m_timeout_reported.exchange(true)) {
            LogClientStage(L"scan request timeout reached; requesting cooperative cancellation");
            CancelScan();
            ReportError(L"The scan request reached its timeout; waiting for the engine response.");
        }
        Sleep(25);
    }
}

void EngineClient::DecodeJsonLine(const std::string& line) {
    try {
        const JsonObject root = JsonObject::Parse(winrt::to_hstring(line));
        if (!root) {
            ReportError(L"Engine returned an empty JSON object.");
            return;
        }

        // Extension frames are asynchronous and intentionally do not carry
        // engine_status. Handle them before reading the status object so a
        // valid engine_event/engine_metrics frame cannot be mistaken for a
        // malformed control or scan response.
        const JsonObject event_object = NamedObject(root, L"engine_event");
        if (event_object) {
            EngineScanResponse event_response;
            event_response.realtime_event = true;
            const std::wstring event_kind = NamedString(event_object, L"kind");
            if (event_kind == L"kernel_event_overflow") {
                event_response.kernel_event_overflow = true;
                event_response.kernel_events_dropped =
                    NamedUInt64(event_object, L"dropped");
                event_response.status = event_kind;
                event_response.reason = L"kernel event ring overflow";
                event_response.error = L"kernel event ring overflow";
            }
            event_response.path = NormalizePath(NamedString(event_object, L"target"));
            if (!event_response.kernel_event_overflow) {
                event_response.reason = NamedString(event_object, L"reason");
                event_response.status = event_kind;
                // Only a kernel block is an enforcement decision.  R3 HIPS
                // and kernel alert frames are telemetry and must not be shown
                // as malware or offered as quarantine/allow actions.
                event_response.realtime_blocked = event_kind == L"KERNEL_BLOCK";
                event_response.malicious = event_response.realtime_blocked;
                event_response.error = NamedString(event_object, L"message");
            }

            if (event_kind == L"R3_HIPS_ALERT" || event_kind == L"R3_BEHAVIOR") {
                // R3 behavior telemetry (kernel/Sysmon file, registry, process
                // and network observations) can fire many times per second
                // during a scan. Share the HIPS burst window so a bottomless
                // ETW feed cannot stall the UI thread with notifications.
                const ULONGLONG now = GetTickCount64();
                if (m_r3_event_window_started_ms == 0
                    || now - m_r3_event_window_started_ms >= 1000) {
                    if (m_r3_event_window_suppressed > 0) {
                        EngineScanResponse summary;
                        summary.realtime_event = true;
                        summary.status = L"R3_HIPS_SUMMARY";
                        summary.reason = L"R3 HIPS event burst suppressed "
                            + std::to_wstring(m_r3_event_window_suppressed)
                            + L" additional event(s) in the last second.";
                        RealtimeThreatHandler summary_handler;
                        {
                            std::lock_guard lock(m_handler_mutex);
                            summary_handler = m_realtime_threat_handler;
                        }
                        if (summary_handler) {
                            Dispatch([summary_handler, summary] {
                                summary_handler(summary);
                            });
                        }
                    }
                    m_r3_event_window_started_ms = now;
                    m_r3_event_window_count = 0;
                    m_r3_event_window_suppressed = 0;
                }
                if (m_r3_event_window_count >= kMaximumR3EventsPerSecond) {
                    ++m_r3_event_window_suppressed;
                    return;
                }
                ++m_r3_event_window_count;
            }
            RealtimeThreatHandler realtime_handler;
            {
                std::lock_guard lock(m_handler_mutex);
                realtime_handler = m_realtime_threat_handler;
            }
            if (realtime_handler) {
                Dispatch([realtime_handler, event_response] { realtime_handler(event_response); });
            }
            return;
        }

        // Metrics are an optional diagnostic extension frame. They are
        // intentionally ignored here; the activity/scan UI consumes only
        // threat and status events, while future diagnostics pages can opt in
        // without changing the scan response contract.
        if (root.HasKey(L"engine_metrics")) {
            return;
        }

        const JsonObject status_object = NamedObject(root, L"engine_status");
        if (!status_object) {
            ReportError(L"Engine returned a JSON frame without engine_status.");
            return;
        }
        const std::wstring status_code = NamedString(status_object, L"code");
        const std::wstring status_message = NamedString(status_object, L"message");
        bool manual_request_in_flight = false;
        {
            std::lock_guard lock(m_write_queue_mutex);
            manual_request_in_flight = m_inflight_scan;
        }
        const auto mark_response_received = [this] {
            {
                std::lock_guard lock(m_write_queue_mutex);
                m_waiting_response = false;
                m_inflight_scan = false;
                m_inflight_line.clear();
            }
            m_scan_deadline_ms.store(0);
            m_write_queue_cv.notify_one();
        };

        // An error response for a scan (for example SHA256 mismatch or
        // ERR_TIMEOUT) may omit scan_result. Treat it as a scan response while
        // a manual request is in flight; only bare control-plane responses
        // take the config branch below.
        if (status_object && !root.HasKey(L"scan_result") && !manual_request_in_flight) {
            if (status_message == L"Engine initialized and ready.") {
                m_ready.store(true);
                m_connected.store(true);
                m_last_engine_activity_ms.store(GetTickCount64());
                LogClientStage(L"ready handshake received");
                ReportConnection(true);
                m_write_queue_cv.notify_one();
                return;
            }
            if (status_message == L"Engine is shutting down.") {
                m_ready.store(false);
                mark_response_received();
                return;
            }
            mark_response_received();
            bool handled_special = false;
            const JsonObject quarantine_object = NamedObject(root, L"quarantine_result");
            if (quarantine_object) {
                handled_special = true;
                EngineQuarantineResponse quarantine_response;
                quarantine_response.action = NamedString(quarantine_object, L"action");
                quarantine_response.message = status_message.empty()
                    ? NamedString(quarantine_object, L"message")
                    : status_message;
                quarantine_response.success = status_code == L"SUCCESS";
                quarantine_response.item = ParseQuarantineItem(quarantine_object);
                const JsonArray records = NamedArray(quarantine_object, L"records");
                if (records) {
                    for (uint32_t index = 0; index < records.Size(); ++index) {
                        try {
                            quarantine_response.records.push_back(
                                ParseQuarantineItem(records.GetObjectAt(index)));
                        } catch (...) {
                            // Ignore one malformed optional record.
                        }
                    }
                }
                QuarantineHandler quarantine_handler;
                {
                    std::lock_guard lock(m_handler_mutex);
                    quarantine_handler = m_quarantine_handler;
                }
                if (quarantine_handler) {
                    Dispatch([quarantine_handler, quarantine_response] {
                        quarantine_handler(quarantine_response);
                    });
                }
            }
            const JsonObject model_validation_object = NamedObject(root, L"model_validation");
            if (model_validation_object) {
                handled_special = true;
                EngineModelValidationResponse validation_response;
                validation_response.path =
                    NormalizePath(NamedString(model_validation_object, L"path"));
                validation_response.usable = NamedBool(model_validation_object, L"usable");
                validation_response.size_bytes =
                    NamedUInt64(model_validation_object, L"size_bytes");
                validation_response.kind = NamedString(model_validation_object, L"kind");
                validation_response.feature_dim =
                    NamedUInt64(model_validation_object, L"feature_dim");
                validation_response.input_count =
                    NamedUInt64(model_validation_object, L"input_count");
                validation_response.output_count =
                    NamedUInt64(model_validation_object, L"output_count");
                validation_response.input0 = NamedString(model_validation_object, L"input0");
                validation_response.output0 = NamedString(model_validation_object, L"output0");
                validation_response.dry_run_score =
                    static_cast<float>(NamedNumber(model_validation_object, L"dry_run_score"));
                validation_response.warnings =
                    NamedStringArray(model_validation_object, L"warnings");
                validation_response.errors =
                    NamedStringArray(model_validation_object, L"errors");
                ModelValidationHandler validation_handler;
                {
                    std::lock_guard lock(m_handler_mutex);
                    validation_handler = m_model_validation_handler;
                }
                if (validation_handler) {
                    Dispatch([validation_handler, validation_response] {
                        validation_handler(validation_response);
                    });
                }
            }
            if (handled_special) {
                if (status_code != L"SUCCESS" && !status_message.empty()) {
                    ReportError(status_message);
                }
                return;
            }
            if (status_message.find(L"driver protection unavailable") != std::wstring::npos) {
                m_driver_protection_enabled.store(false);
                DriverAvailabilityHandler availability_handler;
                {
                    std::lock_guard lock(m_handler_mutex);
                    availability_handler = m_driver_availability_handler;
                }
                if (availability_handler) {
                    Dispatch([availability_handler, status_message] {
                        availability_handler(false, status_message);
                    });
                }
            }            ConfigHandler config_handler;
            {
                std::lock_guard lock(m_handler_mutex);
                config_handler = m_config_handler;
            }
            if (config_handler) {
                const bool success = status_code == L"SUCCESS";
                Dispatch([config_handler, success, status_message] {
                    config_handler(success, status_message);
                });
            }
            if (status_code != L"SUCCESS" && !status_message.empty()) {
                ReportError(status_message);
            }
            return;
        }

        const JsonObject target = NamedObject(root, L"target_info");
        const JsonObject result_object = NamedObject(root, L"scan_result");
        const JsonObject sandbox_object = NamedObject(root, L"sandbox_analysis");
        EngineScanResponse response;
        response.path = NormalizePath(NamedString(target, L"file_path"));
        response.status = NamedString(result_object, L"verdict");
        response.reason = NamedString(result_object, L"threat_name");
        response.malicious = response.status == L"Malware";
        response.heuristic_score = static_cast<float>(NamedNumber(result_object, L"confidence"));
        response.ai_score = response.heuristic_score;
        response.duration_ms = NamedUInt64(NamedObject(root, L"engine_metadata"), L"scan_time_ms");
        if (sandbox_object) {
            response.sandbox_backend = NamedString(sandbox_object, L"backend");
            response.sandbox_status = NamedString(sandbox_object, L"status");
            response.sandbox_snapshot_rounds = static_cast<uint32_t>(NamedUInt64(sandbox_object, L"snapshot_rounds"));
            response.sandbox_triggered_snapshots = static_cast<uint32_t>(NamedUInt64(sandbox_object, L"triggered_snapshots"));
            response.sandbox_adaptive_timeout_ms = NamedUInt64(sandbox_object, L"adaptive_timeout_ms");
            response.sandbox_candidate_images = static_cast<uint32_t>(NamedUInt64(sandbox_object, L"candidate_images"));
            response.sandbox_recovered_entry_points = static_cast<uint32_t>(NamedUInt64(sandbox_object, L"recovered_entry_points"));
            response.sandbox_observed_execution_points = static_cast<uint32_t>(NamedUInt64(sandbox_object, L"observed_execution_points"));
            response.sandbox_bytes_captured = NamedUInt64(sandbox_object, L"bytes_captured");
            response.sandbox_snapshot_truncated = NamedBool(sandbox_object, L"truncated");
            response.sandbox_timed_out = NamedBool(sandbox_object, L"timed_out");
            response.sandbox_notes = NamedStringArray(sandbox_object, L"notes");
        }
        const JsonArray matched_rules = NamedArray(result_object, L"matched_rules");
        if (matched_rules) {
            for (uint32_t index = 0; index < matched_rules.Size(); ++index) {
                try {
                    response.yara_matches.push_back(std::wstring(matched_rules.GetStringAt(index).c_str()));
                } catch (...) {
                    // Ignore one malformed optional evidence item.
                }
            }
        }
        // Multi-step attack chains ride on the scan result. Each chain carries
        // its correlation stage, whether it was gap-tolerant evidence, and the
        // ordered step labels for the visualized chain.
        const JsonArray attack_chains = NamedArray(result_object, L"attack_chains");
        if (attack_chains) {
            for (uint32_t index = 0; index < attack_chains.Size(); ++index) {
                try {
                    const JsonObject chain = attack_chains.GetObjectAt(index);
                    EngineAttackChain parsed;
                    parsed.chain = NamedString(chain, L"chain");
                    parsed.stage = NamedString(chain, L"stage");
                    parsed.tolerant = NamedBool(chain, L"tolerant");
                    parsed.matched_by = NamedString(chain, L"matched_by");
                    parsed.step_labels = NamedStringArray(chain, L"step_labels");
                    if (!parsed.chain.empty()) {
                        response.attack_chains.push_back(std::move(parsed));
                    }
                } catch (...) {
                    // Ignore one malformed optional chain entry.
                }
            }
        }
        if (response.reason.empty() && !response.yara_matches.empty()) {
            response.reason = response.yara_matches.front();
        }
        if (status_code != L"SUCCESS") {
            response.error = status_message;
            response.timed_out = status_code == L"ERR_TIMEOUT";
        }
        mark_response_received();

        bool realtime = false;
        {
            std::lock_guard lock(m_realtime_mutex);
            const auto pending = m_realtime_paths.find(response.path);
            if (pending != m_realtime_paths.end()) {
                realtime = true;
                m_realtime_paths.erase(pending);
            }
        }

        ResponseHandler response_handler;
        RealtimeThreatHandler realtime_handler;
        EngineScanProgress progress;
        bool dispatch_progress = false;
        {
            std::lock_guard lock(m_write_queue_mutex);
            if (!realtime && m_scan_total > 0) {
                ++m_scan_processed;
                if (response.malicious) {
                    ++m_scan_threats;
                }
                if (!response.error.empty()) {
                    ++m_scan_errors;
                }
                progress.path = response.path;
                progress.completed = true;
                progress.total_files = m_scan_total;
                progress.processed_files = m_scan_processed;
                progress.threat_count = m_scan_threats;
                progress.error_count = m_scan_errors;
                progress.batch_completed = m_scan_processed >= m_scan_total;
                progress.cancelled = m_cancel_scan_requested.load();
                if (progress.batch_completed) {
                    m_scan_active.store(false);
                    m_scan_deadline_ms.store(0);
                }
                dispatch_progress = true;
            }
            response_handler = m_response_handler;
            realtime_handler = m_realtime_threat_handler;
        }
        if (response_handler) {
            Dispatch([response_handler, response] { response_handler(response); });
        }
        if (dispatch_progress) {
            ProgressHandler progress_handler;
            {
                std::lock_guard lock(m_handler_mutex);
                progress_handler = m_progress_handler;
            }
            if (progress_handler) {
                Dispatch([progress_handler, progress] { progress_handler(progress); });
            }
        }
        if (realtime && response.malicious && realtime_handler) {
            Dispatch([realtime_handler, response] { realtime_handler(response); });
        }
    } catch (const winrt::hresult_error& error) {
        ReportError(
            L"The engine returned malformed NDJSON: 0x"
            + std::to_wstring(static_cast<uint32_t>(error.code().value)));
    } catch (...) {
        ReportError(L"The engine returned malformed NDJSON.");
    }
}

void EngineClient::Dispatch(std::function<void()> action) const {
    if (!action) return;
    if (!m_dispatcher) {
        NotifyWinUiStage(L"EngineClient: dispatch skipped: dispatcher missing");
        return;
    }
    try {
        if (!m_dispatcher.TryEnqueue([action = std::move(action)] { action(); })) {
            NotifyWinUiStage(L"EngineClient: WinUI dispatcher rejected an NDJSON callback");
        }
    } catch (...) {
        NotifyWinUiStage(L"EngineClient: WinUI dispatcher raised while dispatching NDJSON callback");
    }
}

void EngineClient::ReportError(std::wstring message) {
    ErrorHandler handler;
    {
        std::lock_guard lock(m_handler_mutex);
        handler = m_error_handler;
    }
    if (handler) Dispatch([handler, message = std::move(message)] { handler(message); });
}

void EngineClient::ReportConnection(bool connected) {
    ConnectionHandler handler;
    {
        std::lock_guard lock(m_handler_mutex);
        handler = m_connection_handler;
    }
    if (handler) Dispatch([handler, connected] { handler(connected); });
}

} // namespace everbloom::gui
