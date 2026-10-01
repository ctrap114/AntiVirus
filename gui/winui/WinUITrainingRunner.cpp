#include "WinUITrainingRunner.h"

#include <array>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <system_error>
#include <thread>
#include <vector>

#include <winrt/Windows.Data.Json.h>

#include "WinUIEngineProcess.h"

namespace everbloom::gui {

void NotifyWinUiStage(const std::wstring& stage);

namespace {

std::wstring QuoteCommandLineArgument(const std::wstring& value) {
    std::wstring quoted = L"\"";
    for (const wchar_t character : value) {
        if (character == L'\"') {
            quoted += L"\\\"";
        } else {
            quoted.push_back(character);
        }
    }
    quoted += L"\"";
    return quoted;
}

std::wstring FromNarrow(const char* value) {
    if (value == nullptr || value[0] == '\0') {
        return {};
    }
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, nullptr, 0);
    UINT codepage = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (size <= 0) {
        codepage = CP_ACP;
        flags = 0;
        size = MultiByteToWideChar(codepage, flags, value, -1, nullptr, 0);
    }
    if (size <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(codepage, flags, value, -1, result.data(), size);
    if (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }
    return result;
}

std::wstring FormatWin32Error(DWORD error) {
    return EngineProcess::Win32ErrorMessage(error);
}

bool ParseTrainingLine(
    const std::string& line,
    TrainingRunnerEvent& event,
    std::wstring& result_model_path,
    std::wstring& error_text,
    bool& is_result_line) {
    is_result_line = false;
    const int wide_length = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, nullptr, 0);
    if (wide_length <= 0) {
        return false;
    }
    std::wstring wide(static_cast<size_t>(wide_length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, wide.data(), wide_length);
    if (!wide.empty() && wide.back() == L'\0') {
        wide.pop_back();
    }

    try {
        const auto value = winrt::Windows::Data::Json::JsonValue::Parse(wide);
        if (value.ValueType() != winrt::Windows::Data::Json::JsonValueType::Object) {
            return false;
        }
        const auto object = value.GetObject();
        event.type = std::wstring(object.GetNamedString(L"type", L"").c_str());
        event.name = std::wstring(object.GetNamedString(L"name", L"").c_str());
        event.percent = object.GetNamedNumber(L"percent", 0.0);
        event.message = std::wstring(object.GetNamedString(L"message", L"").c_str());
        if (event.type == L"epoch") {
            event.epoch = static_cast<uint32_t>(object.GetNamedNumber(L"epoch", 0));
            event.total_epochs = static_cast<uint32_t>(object.GetNamedNumber(L"total_epochs", 0));
            event.loss = object.GetNamedNumber(L"loss", 0.0);
            event.accuracy = object.GetNamedNumber(L"accuracy", 0.0);
            event.best_accuracy = object.GetNamedNumber(L"best_accuracy", 0.0);
            event.model = std::wstring(object.GetNamedString(L"model", L"").c_str());
            return true;
        }
        if (event.type == L"comparison") {
            event.baseline_accuracy = object.GetNamedNumber(L"baseline_accuracy", 0.0);
            event.augmented_accuracy = object.GetNamedNumber(L"augmented_accuracy", 0.0);
            event.accuracy_gain = object.GetNamedNumber(L"accuracy_gain", 0.0);
            event.recall_gain = object.GetNamedNumber(L"recall_gain", 0.0);
            event.selected_model = std::wstring(object.GetNamedString(L"selected_model", L"").c_str());
            event.train_samples = static_cast<uint32_t>(object.GetNamedNumber(L"train_samples", 0));
            event.valid_samples = static_cast<uint32_t>(object.GetNamedNumber(L"valid_samples", 0));
            event.test_samples = static_cast<uint32_t>(object.GetNamedNumber(L"test_samples", 0));
            auto families_json = object.GetNamedValue(L"families");
            if (families_json && families_json.ValueType() == winrt::Windows::Data::Json::JsonValueType::Array) {
                auto raw = winrt::to_string(families_json.Stringify());
                size_t pos = 0;
                while (pos < raw.size()) {
                    auto start = raw.find('"', pos);
                    if (start == std::string::npos) break;
                    auto end = raw.find('"', start + 1);
                    if (end == std::string::npos) break;
                    event.families.push_back(std::wstring(winrt::to_hstring(raw.substr(start + 1, end - start - 1))));
                    pos = end + 1;
                }
            }
            return true;
        }
        if (event.type == L"result") {
            is_result_line = true;
            // The final report line carries the exported model path.
            result_model_path =
                std::wstring(object.GetNamedString(L"onnx_path", L"").c_str());
            if (!result_model_path.empty()) {
                return true;
            }
            error_text = L"training finished without a model path";
            return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

TrainingRunner::~TrainingRunner() {
    Stop();
}

bool TrainingRunner::Start(
    winrt::Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
    EventHandler on_event,
    FinishedHandler on_finished,
    std::wstring* error) {
    Stop();
    m_last_error.clear();
    m_dispatcher = dispatcher;
    m_on_event = std::move(on_event);
    m_on_finished = std::move(on_finished);

    try {
        const std::wstring directory = EngineProcess::ExeDirectory();
        if (directory.empty()) {
            m_last_error = L"Unable to determine the GUI executable directory.";
            NotifyWinUiStage(L"TrainingRunner: " + m_last_error);
            if (error) *error = m_last_error;
            return false;
        }

        const std::filesystem::path engine_path =
            std::filesystem::path(directory) / L"everbloom_engine.exe";
        std::error_code file_error;
        if (!std::filesystem::is_regular_file(engine_path, file_error)) {
            m_last_error = L"The EverbloomSecurity engine executable was not found: " + engine_path.wstring();
            NotifyWinUiStage(L"TrainingRunner: " + m_last_error);
            if (error) *error = m_last_error;
            return false;
        }

        SECURITY_ATTRIBUTES security{};
        security.nLength = sizeof(security);
        security.bInheritHandle = TRUE;

        HANDLE child_stdin_read = INVALID_HANDLE_VALUE;
        HANDLE parent_stdin_write = INVALID_HANDLE_VALUE;
        HANDLE parent_stdout_read = INVALID_HANDLE_VALUE;
        HANDLE child_stdout_write = INVALID_HANDLE_VALUE;
        HANDLE child_stderr = INVALID_HANDLE_VALUE;

        if (!CreatePipe(&child_stdin_read, &parent_stdin_write, &security, 0)
            || !SetHandleInformation(parent_stdin_write, HANDLE_FLAG_INHERIT, 0)
            || !CreatePipe(&parent_stdout_read, &child_stdout_write, &security, 0)
            || !SetHandleInformation(parent_stdout_read, HANDLE_FLAG_INHERIT, 0)) {
            m_last_error = FormatWin32Error(GetLastError());
            NotifyWinUiStage(L"TrainingRunner: pipes failed: " + m_last_error);
            if (error) *error = m_last_error;
            return false;
        }

        child_stderr = CreateFileW(
            L"NUL",
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        // Force a fresh corpus plus a per-run seed so every training session
        // sees new samples instead of reusing a stale, identical dataset.
        const auto seed =
            static_cast<unsigned long long>(
                std::chrono::steady_clock::now().time_since_epoch().count());
        std::wstring command_line =
            QuoteCommandLineArgument(engine_path.wstring()) + L" --train-synthetic --force --seed "
            + std::to_wstring(seed);
        std::vector<wchar_t> command_buffer(command_line.begin(), command_line.end());
        command_buffer.push_back(L'\0');

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = child_stdin_read;
        startup.hStdOutput = child_stdout_write;
        startup.hStdError = child_stderr != INVALID_HANDLE_VALUE ? child_stderr : nullptr;
        PROCESS_INFORMATION process{};

        if (!CreateProcessW(
                engine_path.c_str(),
                command_buffer.data(),
                nullptr,
                nullptr,
                TRUE,
                CREATE_NO_WINDOW,
                nullptr,
                directory.c_str(),
                &startup,
                &process)) {
            m_last_error = FormatWin32Error(GetLastError());
            for (HANDLE handle : {child_stdin_read, parent_stdin_write, parent_stdout_read,
                                  child_stdout_write, child_stderr}) {
                if (handle != INVALID_HANDLE_VALUE && handle != nullptr) CloseHandle(handle);
            }
            NotifyWinUiStage(L"TrainingRunner: CreateProcess failed: " + m_last_error);
            if (error) *error = m_last_error;
            return false;
        }

        CloseHandle(child_stdin_read);
        CloseHandle(child_stdout_write);
        if (child_stderr != INVALID_HANDLE_VALUE) CloseHandle(child_stderr);
        CloseHandle(process.hThread);

        m_process = process;
        m_stdin_write = parent_stdin_write;
        m_stdout_read = parent_stdout_read;
        NotifyWinUiStage(
            L"TrainingRunner: started pid=" + std::to_wstring(process.dwProcessId));

        // Reader thread: NDJSON lines -> UI dispatcher.
        const HANDLE stdout_handle = m_stdout_read;
        const HANDLE process_handle = m_process.hProcess;
        std::thread reader([this, stdout_handle, process_handle]() {
            constexpr DWORD kExitSuccess = 0;
            std::string pending;
            std::wstring model_relative;
            bool saw_result = false;

            auto dispatch_event = [this](const TrainingRunnerEvent& event) {
                if (!m_dispatcher) return;
                m_dispatcher.TryEnqueue([this, event] {
                    if (m_on_event) m_on_event(event);
                });
            };

            std::array<char, 4096> buffer{};
            DWORD read = 0;
            for (;;) {
                if (!ReadFile(stdout_handle, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &read, nullptr) || read == 0) {
                    break;
                }
                pending.append(buffer.data(), read);
                size_t newline = pending.find('\n');
                while (newline != std::string::npos) {
                    const std::string line = pending.substr(0, newline);
                    pending.erase(0, newline + 1);
                    if (!line.empty()) {
                        TrainingRunnerEvent event;
                        std::wstring result_path;
                        std::wstring line_error;
                        bool is_result = false;
                        if (ParseTrainingLine(line, event, result_path, line_error, is_result)) {
                            if (is_result) {
                                saw_result = true;
                                model_relative = result_path;
                            } else {
                                dispatch_event(event);
                            }
                        }
                    }
                    newline = pending.find('\n');
                }
            }

            DWORD exit_code = 1;
            if (process_handle != nullptr) {
                WaitForSingleObject(process_handle, 15000);
                GetExitCodeProcess(process_handle, &exit_code);
            }

            bool success = saw_result && exit_code == kExitSuccess && !model_relative.empty();
            std::wstring detail;
            if (success) {
                std::error_code absolute_error;
                detail = std::filesystem::absolute(
                             std::filesystem::path(model_relative), absolute_error)
                             .wstring();
                if (absolute_error) detail = model_relative;
                NotifyWinUiStage(L"TrainingRunner: success model=" + detail);
            } else {
                detail = L"training process exited with code "
                    + std::to_wstring(exit_code);
                NotifyWinUiStage(L"TrainingRunner: " + detail);
            }

            if (!m_dispatcher) return;
            m_dispatcher.TryEnqueue([this, success, detail] {
                if (m_on_finished) m_on_finished(success, detail);
            });
        });
        reader.detach();
        return true;
    } catch (const std::exception& exception) {
        m_last_error = FromNarrow(exception.what());
    } catch (...) {
        m_last_error = L"Unknown exception while starting training.";
    }
    NotifyWinUiStage(L"TrainingRunner: failed: " + m_last_error);
    if (error) *error = m_last_error;
    return false;
}

void TrainingRunner::ResetHandles() {
    if (m_stdout_read != INVALID_HANDLE_VALUE) {
        CloseHandle(m_stdout_read);
        m_stdout_read = INVALID_HANDLE_VALUE;
    }
    if (m_stdin_write != INVALID_HANDLE_VALUE) {
        CloseHandle(m_stdin_write);
        m_stdin_write = INVALID_HANDLE_VALUE;
    }
}

void TrainingRunner::Stop() {
    // Terminate first: the child's stdout write end closing gives the reader
    // thread a clean EOF, so handles are released only afterwards.
    HANDLE process = m_process.hProcess;
    if (process != nullptr) {
        DWORD exit_code = STILL_ACTIVE;
        if (GetExitCodeProcess(process, &exit_code) && exit_code == STILL_ACTIVE) {
            NotifyWinUiStage(L"TrainingRunner: terminating pid="
                + std::to_wstring(m_process.dwProcessId));
            TerminateProcess(process, 1);
            WaitForSingleObject(process, 3000);
        }
        CloseHandle(process);
        m_process = {};
    }
    ResetHandles();
}

bool TrainingRunner::IsRunning() const {
    if (m_process.hProcess == nullptr) {
        return false;
    }
    DWORD exit_code = 0;
    return GetExitCodeProcess(m_process.hProcess, &exit_code) != FALSE
        && exit_code == STILL_ACTIVE;
}

std::wstring TrainingRunner::LastError() const {
    return m_last_error;
}

} // namespace everbloom::gui
