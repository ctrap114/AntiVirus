#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <windows.h>
#include <unknwn.h>
#include <winrt/Microsoft.UI.Dispatching.h>

namespace everbloom::gui {

struct EngineScanProgress {
    std::wstring path;
    uint32_t stage{0};
    bool completed{false};
    std::wstring error;
    uint64_t total_files{0};
    uint64_t processed_files{0};
    uint64_t threat_count{0};
    uint64_t error_count{0};
    bool batch_completed{false};
    bool cancelled{false};
};

// One matched multi-step behavior chain from the engine's scan_result frame.
// The chain element order and labels come from the engine signature table, so
// the GUI renders them without knowing the internal correlation names.
struct EngineAttackChain {
    std::wstring chain;
    std::wstring stage;
    bool tolerant{false};
    std::wstring matched_by;
    std::vector<std::wstring> step_labels;
};

struct EngineScanResponse {
    std::wstring path;
    bool malicious{false};
    std::wstring status;
    std::wstring reason;
std::vector<std::wstring> yara_matches;
    std::vector<EngineAttackChain> attack_chains;
    float heuristic_score{0.0f};
    float ai_score{0.0f};
    bool timed_out{false};
    std::vector<std::wstring> files_changed;
    std::vector<std::wstring> registry_writes;
    std::vector<std::wstring> network_connections;
    std::vector<std::wstring> processes;
    std::wstring sandbox_backend;
    std::wstring sandbox_status;
    uint32_t sandbox_snapshot_rounds{0};
    uint32_t sandbox_triggered_snapshots{0};
    uint64_t sandbox_adaptive_timeout_ms{0};
    uint32_t sandbox_candidate_images{0};
    uint32_t sandbox_recovered_entry_points{0};
    uint32_t sandbox_observed_execution_points{0};
    uint64_t sandbox_bytes_captured{0};
    bool sandbox_snapshot_truncated{false};
    bool sandbox_timed_out{false};
    std::vector<std::wstring> sandbox_notes;
    uint64_t duration_ms{0};
    // True when the frame came from the asynchronous engine_event channel,
    // rather than from a file scan response.  These events are kept separate
    // so an R3 telemetry alert cannot accidentally become a scan threat or a
    // destructive-action checkbox in the GUI.
    bool realtime_event{false};
    bool realtime_blocked{false};
    bool kernel_event_overflow{false};
    uint64_t kernel_events_dropped{0};
    std::wstring error;
};

struct EngineQuarantineItem {
    std::wstring id;
    std::wstring original_path;
    std::wstring quarantine_path;
    std::wstring restore_path;
    std::wstring status;
    std::wstring message;
};

struct EngineQuarantineResponse {
    std::wstring action;
    std::wstring message;
    EngineQuarantineItem item;
    std::vector<EngineQuarantineItem> records;
    bool success{false};
};

struct EngineModelValidationResponse {
    std::wstring path;
    bool usable{false};
    uint64_t size_bytes{0};
    std::wstring kind;
    uint64_t feature_dim{0};
    uint64_t input_count{0};
    uint64_t output_count{0};
    std::wstring input0;
    std::wstring output0;
    float dry_run_score{0.0f};
    std::vector<std::wstring> warnings;
    std::vector<std::wstring> errors;
};

class EngineClient final {
public:
    using ProgressHandler = std::function<void(const EngineScanProgress&)>;
    using ResponseHandler = std::function<void(const EngineScanResponse&)>;
    using ConnectionHandler = std::function<void(bool)>;
    using ErrorHandler = std::function<void(const std::wstring&)>;
    using ConfigHandler = std::function<void(bool, const std::wstring&)>;
    using DriverAvailabilityHandler = std::function<void(bool, const std::wstring&)>;
    using RealtimeThreatHandler = std::function<void(const EngineScanResponse&)>;
    using QuarantineHandler = std::function<void(const EngineQuarantineResponse&)>;
    using ModelValidationHandler =
        std::function<void(const EngineModelValidationResponse&)>;

    EngineClient(
        std::wstring endpoint,
        winrt::Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
        HANDLE stdin_write = INVALID_HANDLE_VALUE,
        HANDLE stdout_read = INVALID_HANDLE_VALUE);
    ~EngineClient();

    EngineClient(EngineClient const&) = delete;
    EngineClient& operator=(EngineClient const&) = delete;

    void Start();
    void Stop();
    // Cancels queued manual work immediately. The one request already in
    // flight is cancelled cooperatively by its timeout/cancellation boundary;
    // the client keeps the transport alive for the corresponding response.
    void CancelScan();
    std::wstring Endpoint() const;

    void RequestScan(
        std::vector<std::wstring> paths,
        uint32_t timeout_ms,
        bool sandbox_enabled,
        bool yara_enabled,
        bool ai_enabled,
        bool heuristic_enabled,
        float ai_threshold,
        uint64_t maximum_file_size,
        bool realtime = false,
        bool cloud_enabled = false);
    void RequestConfigReload();
    void RequestHashDatabaseImport(const std::wstring& path);
    void RequestModelImport(const std::wstring& path);
    void RequestModelValidate(const std::wstring& path);
    void RequestModelStrategy(const std::wstring& strategy);
    void RequestProtectionModes(bool r3_enabled, bool driver_enabled);
void RequestFileBlock(const std::wstring& path);
    void RequestFileAllow(const std::wstring& path);
    void RequestAllowlistAdd(const std::wstring& path);
    void RequestFileQuarantine(const std::wstring& path, const std::wstring& reason = {});
    void RequestQuarantineRestore(
        const std::wstring& id,
        const std::wstring& restore_path = {},
        bool overwrite = false);
    void RequestQuarantineDelete(const std::wstring& id);
    void RequestQuarantineList(bool include_inactive = false);
    bool DriverProtectionEnabled() const noexcept { return m_driver_protection_enabled.load(); }

    void SetProgressHandler(ProgressHandler handler);
    void SetResponseHandler(ResponseHandler handler);
    void SetConnectionHandler(ConnectionHandler handler);
    void SetErrorHandler(ErrorHandler handler);
    void SetConfigHandler(ConfigHandler handler);
    void SetDriverAvailabilityHandler(DriverAvailabilityHandler handler);
    void SetRealtimeThreatHandler(RealtimeThreatHandler handler);
    void SetQuarantineHandler(QuarantineHandler handler);
    void SetModelValidationHandler(ModelValidationHandler handler);

private:
    void WorkerLoop();
    void WriteLoop();
    void WatchdogLoop();
    void CloseTransport();
    bool WriteLine(const std::string& line);
    void DecodeJsonLine(const std::string& line);
    bool QueueLine(
        std::string line,
        bool realtime,
        bool scan_request,
        std::wstring path = {},
        uint32_t timeout_ms = 0);
    void Dispatch(std::function<void()> action) const;
    void ReportError(std::wstring message);
    void ReportConnection(bool connected);

    std::wstring m_endpoint;
    winrt::Microsoft::UI::Dispatching::DispatcherQueue m_dispatcher{nullptr};
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_started{false};
    std::atomic<bool> m_driver_protection_enabled{false};
    std::atomic<bool> m_cancel_scan_requested{false};
    std::atomic<bool> m_scan_active{false};
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_ready{false};
    std::atomic<bool> m_exit_sent{false};
    std::atomic<ULONGLONG> m_last_engine_activity_ms{0};
    std::atomic<ULONGLONG> m_scan_deadline_ms{0};
    std::atomic<bool> m_timeout_reported{false};
    std::thread m_worker;
    std::thread m_writer;
    std::thread m_watchdog;
    std::mutex m_write_mutex;
    std::mutex m_write_queue_mutex;
    std::condition_variable m_write_queue_cv;
    struct QueuedLine {
        std::string line;
        bool realtime{false};
        bool scan_request{false};
        std::wstring path;
        uint32_t timeout_ms{0};
    };
    std::deque<QueuedLine> m_write_queue;
    std::string m_inflight_line;
    bool m_inflight_scan{false};
    bool m_waiting_response{false};
    HANDLE m_stdin_write{INVALID_HANDLE_VALUE};
    HANDLE m_stdout_read{INVALID_HANDLE_VALUE};

    uint64_t m_scan_total{0};
    uint64_t m_scan_processed{0};
    uint64_t m_scan_threats{0};
    uint64_t m_scan_errors{0};
    uint64_t m_task_sequence{0};

    std::mutex m_realtime_mutex;
    std::unordered_set<std::wstring> m_realtime_paths;

    // Progress is sampled on the IPC worker and delivered to WinUI at a
    // bounded rate so a large directory scan cannot enqueue thousands of UI
    // callbacks at once.
    std::mutex m_progress_throttle_mutex;
    ULONGLONG m_last_progress_dispatch_ms{0};
    std::atomic<ULONGLONG> m_last_progress_log_ms{0};
    std::atomic<uint64_t> m_last_logged_processed_files{0};
    std::atomic<uint64_t> m_last_logged_total_files{0};

    // DecodeJsonLine is called only by the worker thread.  Keep a small
    // per-second budget for noisy R3 telemetry (for example, a process with
    // many legitimate executable regions) so an event burst cannot enqueue
    // thousands of WinUI callbacks during startup.
    ULONGLONG m_r3_event_window_started_ms{0};
    uint32_t m_r3_event_window_count{0};
    uint64_t m_r3_event_window_suppressed{0};

    mutable std::mutex m_handler_mutex;
    ProgressHandler m_progress_handler;
    ResponseHandler m_response_handler;
    ConnectionHandler m_connection_handler;
    ErrorHandler m_error_handler;
    ConfigHandler m_config_handler;
    DriverAvailabilityHandler m_driver_availability_handler;
    RealtimeThreatHandler m_realtime_threat_handler;
    QuarantineHandler m_quarantine_handler;
    ModelValidationHandler m_model_validation_handler;
};

} // namespace everbloom::gui
