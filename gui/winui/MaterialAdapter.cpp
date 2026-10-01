#include "pch.h"
#include "MaterialAdapter.h"
#include <winrt/Microsoft.UI.Xaml.Media.h>
#include <winrt/Microsoft.UI.Composition.h>
#include <winrt/Microsoft.UI.Composition.Effects.h>
#include <winrt/Windows.UI.h>
#include <winrt/Windows.UI.Composition.h>
#include <winrt/Windows.UI.Composition.Effects.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.UI.Composition.Effects.h>

namespace EverbloomSecurity::GUI::WinUI
{
    MaterialAdapter::MaterialAdapter()
    {
    }

    void MaterialAdapter::Initialize()
    {
        if (m_initialized) return;
        
        if (Window::Current())
        {
            TryApplyMaterial();
            m_initialized = true;
        }
        else
        {
            Window::Current().Activated({ this, &MaterialAdapter::OnWindowActivated });
        }
    }

    void MaterialAdapter::OnWindowActivated(IInspectable const&, WindowActivatedEventArgs const& args)
    {
        if (args.WindowActivationState() != WindowActivationState::Deactivated)
        {
            Window::Current().Activated(*this, &MaterialAdapter::OnWindowActivated);
            TryApplyMaterial();
            m_initialized = true;
        }
    }

    void MaterialAdapter::TryApplyMaterial()
    {
        try
        {
            auto window = Window::Current();
            if (!window || !window.Content())
                return;

            auto root = window.Content().try_as<FrameworkElement>();
            if (!root)
                return;

            // Detect OS version & API support
            auto version = Windows::System::Profile::AnalyticsInfo::VersionInfo().DeviceFamilyVersion();
            // Parse version: 10.0.22000 = Win11
            unsigned long long versionNum = 0;
            try {
                versionNum = std::stoull(std::wstring(version.Data()));
            } catch (...) {
                versionNum = 0;
            }
            bool isWin11 = versionNum >= 22000;
            bool isWin10_1809Plus = (versionNum >= 17763);

            // Try Mica first (Win11+)
            if (TrySetMica())
            {
                return;
            }

            // Fallback: Desktop Acrylic (Win10 1809+)
            if (TrySetDesktopAcrylic())
            {
                return;
            }

            // Fallback: Solid background
            ApplySolidFallback();
        }
        catch (...)
        {
            ApplySolidFallback();
        }
    }

    bool MaterialAdapter::TrySetMica()
    {
        try
        {
            auto window = Window::Current();
            if (!window) return false;

            // Try Mica (Win11+)
            auto micaController = MicaController::CreateForDispatcherQueue(
                DispatcherQueue::GetForCurrentThread());
            micaController.Kind(MicaKind::Base); // Base for light, BaseAlt for dark
            micaController.IsInputActive(true);
            micaController.SetTarget(window);
            
            m_controller = micaController;
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    bool MaterialAdapter::TrySetDesktopAcrylic()
    {
        try
        {
            auto window = Window::Current();
            if (!window) return false;

            // Use DesktopAcrylicController (Win10 1809+)
            auto acrylicController = DesktopAcrylicController::CreateForDispatcherQueue(
                DispatcherQueue::GetForCurrentThread());
            
            acrylicController.TintColor(ColorHelper::FromArgb(255, 0x1A, 0x1A, 0x20));
            acrylicController.TintOpacity(0.85);
            acrylicController.LuminosityOpacity(0.45);
            acrylicController.FallbackColor(ColorHelper::FromArgb(255, 0x12, 0x12, 0x16));
            
            acrylicController.IsInputActive(true);
            acrylicController.SetTarget(Window::Current());
            
            m_controller = acrylicController;
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    void MaterialAdapter::ApplySolidFallback()
    {
        try
        {
            if (Window::Current() && Window::Current().Content())
            {
                auto root = Window::Current().Content().try_as<FrameworkElement>();
                if (root)
                {
                    auto fallbackBrush = SolidColorBrush(ColorHelper::FromArgb(255, 0x12, 0x12, 0x16));
                    root.Background(fallbackBrush);
                }
            }
        }
        catch (...) {}
    }

    void MaterialAdapter::SwitchMaterial(MaterialKind kind)
    {
        if (m_controller)
        {
            m_controller = nullptr;
        }

        switch (kind)
        {
            case MaterialKind::Mica:
                TrySetMica();
                break;
            case MaterialKind::DesktopAcrylic:
                TrySetDesktopAcrylic();
                break;
            default:
                ApplySolidFallback();
                break;
        }
    }
}