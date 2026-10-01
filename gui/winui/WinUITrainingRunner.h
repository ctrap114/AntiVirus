#pragma once

#include <string>
#include <vector>
#include <functional>

#include <windows.h>
#include <winrt/Microsoft.UI.Dispatching.h>

namespace everbloom::gui {

// One NDJSON line emitted by `everbloom_engine.exe --train-synthetic`.
struct TrainingRunnerEvent {
    std::wstring type;       // "stage" | "progress" | "epoch" | "comparison"
    std::wstring name;       // stage name ("generation"/"loading"/"export")
    double percent{0.0};     // 0-100 when available
    std::wstring message;    // human-readable detail
    // Epoch-specific fields (populated when type=="epoch").
    uint32_t epoch{0};
    uint32_t total_epochs{0};
    double loss{0.0};
    double accuracy{0.0};
    double best_accuracy{0.0};
    std::wstring model;      // "baseline" or "augmented"
    // Comparison fields (populated when type=="comparison").
    double baseline_accuracy{0.0};
    double augmented_accuracy{0.0};
    double accuracy_gain{0.0};
    double recall_gain{0.0};
    std::wstring selected_model;
    uint32_t train_samples{0};
    uint32_t valid_samples{0};
    uint32_t test_samples{0};
    std::vector<std::wstring> families;
};

// Drives an out-of-band AI training child process. The engine keeps serving
// scan IPC normally while this separate process generates the synthetic
// corpus, trains the models, and exports the winning ONNX artifact.
class TrainingRunner final {
public:
    // All callbacks are marshalled onto the provided UI DispatcherQueue.
    using EventHandler = std::function<void(const TrainingRunnerEvent&)>;
    // success=true -> detail holds the absolute path of the exported model.
    using FinishedHandler = std::function<void(bool success, const std::wstring& detail)>;

    TrainingRunner() = default;
    ~TrainingRunner();

    TrainingRunner(TrainingRunner const&) = delete;
    TrainingRunner& operator=(TrainingRunner const&) = delete;

    bool Start(
        winrt::Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
        EventHandler on_event,
        FinishedHandler on_finished,
        std::wstring* error = nullptr);
    void Stop();
    bool IsRunning() const;
    std::wstring LastError() const;

private:
    void ResetHandles();

    PROCESS_INFORMATION m_process{};
    HANDLE m_stdout_read{INVALID_HANDLE_VALUE};
    HANDLE m_stdin_write{INVALID_HANDLE_VALUE};
    winrt::Microsoft::UI::Dispatching::DispatcherQueue m_dispatcher{nullptr};
    EventHandler m_on_event;
    FinishedHandler m_on_finished;
    std::wstring m_last_error;
};

} // namespace everbloom::gui
