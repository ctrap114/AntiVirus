#include "pch.h"
#include "EverbloomButton.h"
#include "EverbloomButton.g.cpp"

namespace EverbloomSecurity::GUI::WinUI::Controls::implementation
{
    using namespace winrt;
    using namespace Microsoft::UI::Xaml;
    using namespace Microsoft::UI::Xaml::Controls;
    using namespace Microsoft::UI::Xaml::Controls::Primitives;
    using namespace Microsoft::UI::Xaml::Media;
    using namespace Microsoft::UI::Xaml::Input;
    using namespace Microsoft::UI::Xaml::Media::Animation;
    using namespace Microsoft::UI::Xaml::Shapes;
    using namespace Windows::UI;
    using namespace winrt::Microsoft::UI;

    EverbloomButton::EverbloomButton()
    {
        DefaultStyleKey(winrt::box_value(L"EverbloomSecurity.GUI.WinUI.Controls.EverbloomButton"));
        Loaded({ this, &EverbloomButton::OnLoaded });
        PointerEntered({ this, &EverbloomButton::OnPointerEntered });
        PointerExited({ this, &EverbloomButton::OnPointerExited });
        PointerPressed({ this, &EverbloomButton::OnPointerPressed });
        PointerReleased({ this, &EverbloomButton::OnPointerReleased });
        PointerCanceled({ this, &EverbloomButton::OnPointerCanceled });
    }

    void EverbloomButton::OnLoaded(winrt::Windows::Foundation::IInspectable const& sender, RoutedEventArgs const& e)
    {
        UpdateVisualState();
    }

    void EverbloomButton::OnPointerEntered(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        m_isPointerOver = true;
        VisualStateManager::GoToState(*this, L"PointerOver", true);
    }

    void EverbloomButton::OnPointerExited(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        m_isPointerOver = false;
        VisualStateManager::GoToState(*this, L"Normal", true);
    }

    void EverbloomButton::OnPointerPressed(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        m_isPressed = true;
        VisualStateManager::GoToState(*this, L"Pressed", true);
    }

    void EverbloomButton::OnPointerReleased(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        m_isPressed = false;
        VisualStateManager::GoToState(*this, m_isPointerOver ? L"PointerOver" : L"Normal", true);
    }

    void EverbloomButton::OnPointerCanceled(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        m_isPressed = false;
        VisualStateManager::GoToState(*this, L"Normal", true);
    }

    void EverbloomButton::OnApplyTemplate()
    {
        ButtonBase::OnApplyTemplate();

        // Find the sword accent border in the template
        m_swordAccent = GetTemplateChild(L"SwordAccent").try_as<Border>();
        
        UpdateVisualState();
    }

    void EverbloomButton::UpdateVisualState()
    {
        auto variant = Variant();
        switch (variant)
        {
        case ButtonVariant::Primary:
            VisualStateManager::GoToState(*this, L"Primary", false);
            break;
        case ButtonVariant::Secondary:
            VisualStateManager::GoToState(*this, L"Secondary", false);
            break;
        case ButtonVariant::Subtle:
            VisualStateManager::GoToState(*this, L"Subtle", false);
            break;
        case ButtonVariant::Ghost:
            VisualStateManager::GoToState(*this, L"Ghost", false);
            break;
        case ButtonVariant::Destructive:
            VisualStateManager::GoToState(*this, L"Destructive", false);
            break;
        }
    }

    // Dependency Property Definitions
    ButtonVariant EverbloomButton::Variant()
    {
        return static_cast<ButtonVariant>(static_cast<int>(GetValue(s_variantProperty)));
    }

    void EverbloomButton::Variant(ButtonVariant value)
    {
        SetValue(s_variantProperty, winrt::box_value(static_cast<int>(value)));
    }

    winrt::Microsoft::UI::Xaml::CornerRadius EverbloomButton::CornerRadius()
    {
        return GetValue(s_cornerRadiusProperty).as<CornerRadius>();
    }

    void EverbloomButton::CornerRadius(winrt::Microsoft::UI::Xaml::CornerRadius value)
    {
        SetValue(s_cornerRadiusProperty, winrt::box_value(value));
    }

    double EverbloomButton::SlashAngle()
    {
        return unbox_value<double>(GetValue(s_slashAngleProperty));
    }

    void EverbloomButton::SlashAngle(double value)
    {
        SetValue(s_slashAngleProperty, winrt::box_value(value));
    }

    bool EverbloomButton::ShowSwordAccent()
    {
        return unbox_value<bool>(GetValue(s_showSwordAccentProperty));
    }

    void EverbloomButton::ShowSwordAccent(bool value)
    {
        SetValue(s_showSwordAccentProperty, winrt::box_value(value));
    }

    // Dependency Property Definitions
    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomButton::s_variantProperty = 
        DependencyProperty::Register(
            L"Variant",
            winrt::xaml_typename<ButtonVariant>(),
            winrt::xaml_typename<EverbloomButton>(),
            PropertyMetadata(winrt::box_value(static_cast<int>(ButtonVariant::Primary)), OnVariantChanged));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomButton::s_cornerRadiusProperty =
        DependencyProperty::Register(
            L"CornerRadius",
            winrt::xaml_typename<CornerRadius>(),
            winrt::xaml_typename<EverbloomButton>(),
            PropertyMetadata(winrt::box_value(CornerRadius(6))));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomButton::s_slashAngleProperty =
        DependencyProperty::Register(
            L"SlashAngle",
            winrt::xaml_typename<double>(),
            winrt::xaml_typename<EverbloomButton>(),
            PropertyMetadata(winrt::box_value(15.0)));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomButton::s_showSwordAccentProperty =
        DependencyProperty::Register(
            L"ShowSwordAccent",
            winrt::xaml_typename<bool>(),
            winrt::xaml_typename<EverbloomButton>(),
            PropertyMetadata(winrt::box_value(false)));

    void EverbloomButton::OnVariantChanged(DependencyObject const& d, DependencyPropertyChangedEventArgs const& e)
    {
        if (auto btn = d.try_as<EverbloomButton>())
        {
            btn.UpdateVisualState();
        }
    }
}