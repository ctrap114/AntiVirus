#include "pch.h"
#include "App.xaml.h"
#include "EverbloomButton.h"
#include "EverbloomCard.h"
#include "EverbloomNavigationView.h"
#include "EverbloomScanRing.h"
#include "MaterialAdapter.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;
using namespace Microsoft::UI::Xaml::Controls;
using namespace Microsoft::UI::Xaml::Controls::Primitives;
using namespace Microsoft::UI::Xaml::Media;
using namespace Microsoft::UI::Xaml::Controls::Primitives;
using namespace EverbloomSecurity::GUI::WinUI;
using namespace EverbloomSecurity::GUI::WinUI::Controls;

namespace EverbloomSecurity::GUI::WinUI
{
    App::App()
    {
        InitializeComponent();
        
        // Register custom controls
        RegisterCustomControls();
        
        // Initialize Material Adapter
        MaterialAdapter::Current.Initialize();
    }

    App::~App()
    {
    }

    void App::OnLaunched(LaunchActivatedEventArgs const& args)
    {
        m_window = Window();
        m_window.Activate();

        // Apply borderless window style
        ApplyBorderlessWindow();

        // Build main content with new design system
        auto content = BuildMainContent(
            m_style,
            m_language,
            m_accent,
            m_background_image,
            m_engine_client,
            m_protection_monitor,
            [this](UiStyle style, UiLanguage language, UiAccent accent, std::wstring background) {
                Rebuild(style, language, accent, background);
            },
            m_engine_start_error,
            [this](EngineScanResponse const& response) {
                ShowRealtimeThreatDialog(response);
            },
            m_feature_settings,
            [this](UiFeatureSettings const& settings) {
                ApplyFeatureSettings(settings);
            },
            m_scan_snapshot,
            [this](EngineScanResponse const& response) {
                ShowSandboxAnalysisDialog(response);
            },
            [this](std::function<void(std::vector<std::wstring>)> submit) {
                ShowCustomScanPicker(submit);
            },
            [this]() { return m_native_window; },
            [this]() { on_close_caption(); },
            [this](winrt::Microsoft::UI::Xaml::UIElement element) {
                on_caption_ready(element);
            });

        m_window.Content(content);
        m_window.Activate();

        // Start engine in background
        StartEngineInBackground();

        // Request startup scan if ready
        RequestStartupScanIfReady();
    }

    void App::RegisterCustomControls()
    {
        // Register custom controls for XAML usage
        // The controls are registered automatically via their class definitions
        // This function ensures they're loaded
    }

    // ... rest of existing App methods remain unchanged ...
}