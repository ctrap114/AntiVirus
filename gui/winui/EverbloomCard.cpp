#include "pch.h"
#include "EverbloomCard.h"
#include "EverbloomCard.g.cpp"

namespace EverbloomSecurity::GUI::WinUI::Controls::implementation
{
    using namespace winrt;
    using namespace Microsoft::UI::Xaml;
    using namespace Microsoft::UI::Xaml::Controls;
    using namespace Microsoft::UI::Xaml::Media;
    using namespace Microsoft::UI::Xaml::Controls::Primitives;
    using namespace Microsoft::UI::Xaml::Input;
    using namespace Microsoft::UI::Xaml::Media::Animation;
    using namespace Windows::UI;

    EverbloomCard::EverbloomCard()
    {
        DefaultStyleKey(winrt::box_value(L"EverbloomSecurity.GUI.WinUI.Controls.EverbloomCard"));
        Loaded({ this, &EverbloomCard::OnLoaded });
        PointerEntered({ this, &EverbloomCard::OnPointerEntered });
        PointerExited({ this, &EverbloomCard::OnPointerExited });
        PointerPressed({ this, &EverbloomCard::OnPointerPressed });
        PointerReleased({ this, &EverbloomCard::OnPointerReleased });
        PointerCanceled({ this, &EverbloomCard::OnPointerCanceled });
    }

    void EverbloomCard::OnLoaded(winrt::Windows::Foundation::IInspectable const& sender, RoutedEventArgs const& e)
    {
        UpdateVisualState();
    }

    void EverbloomCard::OnPointerEntered(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        if (IsInteractive())
        {
            VisualStateManager::GoToState(*this, L"PointerOver", true);
        }
    }

    void EverbloomCard::OnPointerExited(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        VisualStateManager::GoToState(*this, L"Normal", true);
    }

    void EverbloomCard::OnPointerPressed(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        VisualStateManager::GoToState(*this, L"Pressed", true);
    }

    void EverbloomCard::OnPointerReleased(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        VisualStateManager::GoToState(*this, L"PointerOver", true);
    }

    void EverbloomCard::OnPointerCanceled(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        VisualStateManager::GoToState(*this, L"Normal", true);
    }

    void EverbloomCard::UpdateVisualState()
    {
        if (IsInteractive())
        {
            VisualStateManager::GoToState(*this, L"Normal", false);
        }
    }

    // Dependency Property Definitions
    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomCard::s_cornerRadiusProperty = 
        DependencyProperty::Register(
            L"CornerRadius",
            winrt::xaml_typename<CornerRadius>(),
            winrt::xaml_typename<EverbloomCard>(),
            PropertyMetadata(winrt::box_value(CornerRadius(8))));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomCard::s_borderBrushProperty =
        DependencyProperty::Register(
            L"BorderBrush",
            winrt::xaml_typename<Brush>(),
            winrt::xaml_typename<EverbloomCard>(),
            PropertyMetadata(nullptr));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomCard::s_borderThicknessProperty =
        DependencyProperty::Register(
            L"BorderThickness",
            winrt::xaml_typename<Thickness>(),
            winrt::xaml_typename<EverbloomCard>(),
            PropertyMetadata(winrt::box_value(Thickness(1))));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomCard::s_backgroundProperty =
        DependencyProperty::Register(
            L"Background",
            winrt::xaml_typename<Brush>(),
            winrt::xaml_typename<EverbloomCard>(),
            PropertyMetadata(nullptr));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomCard::s_hoverBackgroundProperty =
        DependencyProperty::Register(
            L"HoverBackground",
            winrt::xaml_typename<Brush>(),
            winrt::xaml_typename<EverbloomCard>(),
            PropertyMetadata(nullptr));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomCard::s_showSwordAccentProperty =
        DependencyProperty::Register(
            L"ShowSwordAccent",
            winrt::xaml_typename<bool>(),
            winrt::xaml_typename<EverbloomCard>(),
            PropertyMetadata(winrt::box_value(false)));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomCard::s_isInteractiveProperty =
        DependencyProperty::Register(
            L"IsInteractive",
            winrt::xaml_typename<bool>(),
            winrt::xaml_typename<EverbloomCard>(),
            PropertyMetadata(winrt::box_value(false), OnIsInteractiveChanged));

    void EverbloomCard::OnIsInteractiveChanged(DependencyObject const& d, DependencyPropertyChangedEventArgs const& e)
    {
        if (auto card = d.try_as<EverbloomCard>())
        {
            card.UpdateVisualState();
        }
    }

    // Property Accessors
    CornerRadius EverbloomCard::CornerRadius()
    {
        return GetValue(s_cornerRadiusProperty).as<CornerRadius>();
    }

    void EverbloomCard::CornerRadius(CornerRadius value)
    {
        SetValue(s_cornerRadiusProperty, winrt::box_value(value));
    }

    Brush EverbloomCard::BorderBrush()
    {
        return GetValue(s_borderBrushProperty).as<Brush>();
    }

    void EverbloomCard::BorderBrush(Brush value)
    {
        SetValue(s_borderBrushProperty, value);
    }

    Thickness EverbloomCard::BorderThickness()
    {
        return GetValue(s_borderThicknessProperty).as<Thickness>();
    }

    void EverbloomCard::BorderThickness(Thickness value)
    {
        SetValue(s_borderThicknessProperty, winrt::box_value(value));
    }

    Brush EverbloomCard::Background()
    {
        return GetValue(s_backgroundProperty).as<Brush>();
    }

    void EverbloomCard::Background(Brush value)
    {
        SetValue(s_backgroundProperty, value);
    }

    Brush EverbloomCard::HoverBackground()
    {
        return GetValue(s_hoverBackgroundProperty).as<Brush>();
    }

    void EverbloomCard::HoverBackground(Brush value)
    {
        SetValue(s_hoverBackgroundProperty, value);
    }

    bool EverbloomCard::ShowSwordAccent()
    {
        return unbox_value<bool>(GetValue(s_showSwordAccentProperty));
    }

    void EverbloomCard::ShowSwordAccent(bool value)
    {
        SetValue(s_showSwordAccentProperty, winrt::box_value(value));
    }

    bool EverbloomCard::IsInteractive()
    {
        return unbox_value<bool>(GetValue(s_isInteractiveProperty));
    }

    void EverbloomCard::IsInteractive(bool value)
    {
        SetValue(s_isInteractiveProperty, winrt::box_value(value));
    }
}