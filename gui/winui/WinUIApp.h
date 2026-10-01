#pragma once

#include <atomic>
#include <functional>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <unknwn.h>
#ifdef GetCurrentTime
#undef GetCurrentTime
#endif
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>

#include "WinUIEngineClient.h"
#include "WinUIEngineProcess.h"
#include "WinUILocalization.h"
#include "WinUIProtectionMonitor.h"
#include "WinUITrayIcon.h"

namespace everbloom::gui {

enum class UiStyle {
    FluentLight,
    FluentDark,
    Aurora,
    HighContrast,
    Glass,
    Graphite,
    Rose,
};

enum class UiAccent {
    Blue,
    Teal,
    Orange,
    Violet,
};

struct UiFeatureSettings {
    bool yara_enabled{true};
    bool heuristic_enabled{true};
    bool ai_enabled{false};
    bool sandbox_enabled{false};
    bool cloud_placeholder_enabled{false};
    bool r3_enabled{false};
    bool driver_enabled{false};
    bool notifications_enabled{true};
    bool translucent_panels{true};
    // 0 is fully opaque; higher values reveal more of the selected
    // background image. The UI clamps this to a safe 0..55% range.
    uint8_t transparency_percent{12};
    bool start_with_windows_enabled{false};
};

// Rebuilds replace the visual tree, not the engine session. This snapshot is
// the small durable bridge that keeps an in-flight scan visible while the user
// changes theme, accent, language or background image.
struct ScanUiThreatSnapshot {
    std::wstring path;
    std::wstring reason;
};

struct ScanUiSnapshot {
    uint64_t files_processed{0};
    uint64_t total_files{0};
    uint64_t threat_count{0};
    uint64_t error_count{0};
    bool scan_active{false};
    bool engine_connected{false};
    uint64_t engine_disconnects{0};
    uint32_t scan_indicator_frame{0};
    std::chrono::steady_clock::time_point scan_started_at{};
    // These collections live outside the visual tree so a theme/language
    // rebuild can recreate the checkboxes without losing the user's current
    // scan and HIPS evidence.
    std::vector<ScanUiThreatSnapshot> scan_threats;
    std::vector<ScanUiThreatSnapshot> realtime_threats;
    std::vector<EngineAttackChain> attack_chains;
    std::wstring sandbox_analysis;
    uint64_t kernel_events_dropped{0};
    std::vector<std::wstring> engine_errors;
};

struct App : winrt::Microsoft::UI::Xaml::ApplicationT<App> {
    App();
    ~App();

    void OnLaunched(winrt::Microsoft::UI::Xaml::LaunchActivatedEventArgs const& args);

private:
    void ApplyBorderlessWindow();
    void StartEngineInBackground();
    void RequestStartupScanIfReady();
    void Rebuild(UiStyle style, UiLanguage language, UiAccent accent, std::wstring background_image);
    void ApplyFeatureSettings(const UiFeatureSettings& settings);
    void ShowRealtimeThreatDialog(const EngineScanResponse& response);
    void ShowSandboxAnalysisDialog(const EngineScanResponse& response);
    void ShowCustomScanPicker(std::function<void(std::vector<std::wstring>)> submit);

    std::unique_ptr<EngineProcess> m_engine_process;
    std::shared_ptr<EngineClient> m_engine_client;
    std::shared_ptr<ProtectionMonitor> m_protection_monitor;
    std::wstring m_endpoint;
    std::wstring m_engine_start_error;
    std::atomic<bool> m_engine_starting{false};
    std::vector<std::wstring> m_startup_scan_targets;
    winrt::Microsoft::UI::Xaml::Window m_window{nullptr};
    HWND m_native_window{nullptr};
    winrt::Microsoft::UI::Xaml::UIElement m_title_bar_element{nullptr};
    std::unique_ptr<TrayIcon> m_tray;
    UiStyle m_style{UiStyle::FluentLight};
    UiLanguage m_language{UiLanguage::English};
    UiAccent m_accent{UiAccent::Blue};
    std::wstring m_background_image;
    UiFeatureSettings m_feature_settings;
    std::shared_ptr<ScanUiSnapshot> m_scan_snapshot{std::make_shared<ScanUiSnapshot>()};
};

void NotifyWinUiLaunched();
void NotifyWinUiStage(const std::wstring& stage);
void NotifyWinUiWindowReady();

winrt::Microsoft::UI::Xaml::UIElement BuildMainContent();
winrt::Microsoft::UI::Xaml::UIElement BuildMainContent(
    UiStyle style,
    UiLanguage language,
    UiAccent accent,
    std::wstring background_image,
    std::shared_ptr<EngineClient> client,
    std::shared_ptr<ProtectionMonitor> protection_monitor,
    std::function<void(UiStyle, UiLanguage, UiAccent, std::wstring)> on_preferences_changed,
    std::wstring engine_start_error = {},
    std::function<void(const EngineScanResponse&)> on_realtime_threat = {},
    UiFeatureSettings feature_settings = {},
    std::function<void(const UiFeatureSettings&)> on_feature_settings_changed = {},
    std::shared_ptr<ScanUiSnapshot> scan_snapshot = {},
    std::function<void(const EngineScanResponse&)> on_sandbox_analysis = {},
    std::function<void(std::function<void(std::vector<std::wstring>)>)> on_custom_scan = {},
    std::function<HWND(void)> native_window_provider = {},
    std::function<void()> on_close_caption = {},
    std::function<void(winrt::Microsoft::UI::Xaml::UIElement)> on_caption_ready = {});

} // namespace everbloom::gui
