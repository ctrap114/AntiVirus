#pragma once

#include "EverbloomButton.g.h"
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Media.h>
#include <winrt/Microsoft.UI.Xaml.Controls.Primitives.h>
#include <winrt/Windows.UI.h>

namespace EverbloomSecurity::GUI::WinUI::Controls
{
    enum class ButtonVariant
    {
        Primary,
        Secondary,
        Subtle,
        Ghost,
        Destructive
    };

    struct EverbloomButton : EverbloomButtonT<EverbloomButton>
    {
    public:
        EverbloomButton();

        // Dependency Properties
        static winrt::Microsoft::UI::Xaml::DependencyProperty VariantProperty;
        static winrt::Microsoft::UI::Xaml::DependencyProperty CornerRadiusProperty;
        static winrt::Microsoft::UI::Xaml::DependencyProperty SlashAngleProperty;
        static winrt::Microsoft::UI::Xaml::DependencyProperty ShowSwordAccentProperty;
        static winrt::Microsoft::UI::Xaml::DependencyProperty VariantProperty;

        // Properties
        ButtonVariant Variant();
        void Variant(ButtonVariant value);

        winrt::Microsoft::UI::Xaml::CornerRadius CornerRadius();
        void CornerRadius(winrt::Microsoft::UI::Xaml::CornerRadius value);

        double SlashAngle();
        void SlashAngle(double value);

        bool ShowSwordAccent();
        void ShowSwordAccent(bool value);

        EverbloomButton();

    protected:
        void OnApplyTemplate() override;
        void OnPointerEntered(winrt::Microsoft::UI::Xaml::Input::PointerRoutedEventArgs const& e);
        void OnPointerExited(winrt::Microsoft::UI::Xaml::Input::PointerRoutedEventArgs const& e);
        void OnPointerPressed(winrt::Microsoft::UI::Xaml::Input::PointerRoutedEventArgs const& e);
        void OnPointerReleased(winrt::Microsoft::UI::Xaml::Input::PointerRoutedEventArgs const& e);
        void OnPointerCanceled(winrt::Microsoft::UI::Xaml::Input::PointerRoutedEventArgs const& e);

    private:
        void OnLoaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
        void UpdateVisualState();
        void UpdateVisualState();

        winrt::Microsoft::UI::Xaml::Controls::Border m_swordAccent{ nullptr };
        bool m_isPointerOver{ false };
        bool m_isPressed{ false };
    };
}

namespace winrt::EverbloomSecurity::GUI::WinUI::Controls::factory_implementation
{
    struct EverbloomButton : EverbloomButtonT<EverbloomButton, implementation::EverbloomButton>
    {
    };
}