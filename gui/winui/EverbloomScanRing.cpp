#include "pch.h"
#include "EverbloomScanRing.h"
#include "EverbloomScanRing.g.cpp"

namespace EverbloomSecurity::GUI::WinUI::Controls::implementation
{
    using namespace winrt;
    using namespace Microsoft::UI::Xaml;
    using namespace Microsoft::UI::Xaml::Controls;
    using namespace Microsoft::UI::Xaml::Controls::Primitives;
    using namespace Microsoft::UI::Xaml::Media;
    using namespace Microsoft::UI::Xaml::Media::Animation;
    using namespace Microsoft::UI::Xaml::Shapes;
    using namespace Microsoft::UI::Composition;
    using namespace Microsoft::UI::Composition::Animations;
    using namespace Microsoft::UI::Composition::Effects;
    using namespace Microsoft::UI::Composition::Interactions;
    using namespace Windows::UI;
    using namespace Windows::Foundation;
    using namespace Windows::Foundation::Numerics;
    using namespace System;
    using namespace System::Collections::Generic;
    using namespace System::Collections::ObjectModel;
    using namespace System::Numerics;

    EverbloomScanRing::EverbloomScanRing()
    {
        DefaultStyleKey(winrt::box_value(L"EverbloomSecurity.GUI.WinUI.Controls.EverbloomScanRing"));
        Loaded({ this, &EverbloomScanRing::OnLoaded });
        Unloaded({ this, &EverbloomScanRing::OnUnloaded });
        SizeChanged({ this, &EverbloomScanRing::OnSizeChanged });
    }

    void EverbloomScanRing::OnLoaded(winrt::Windows::Foundation::IInspectable const& sender, RoutedEventArgs const& e)
    {
        InitializeComposition();
        InitializeAnimations();
    }

    void EverbloomScanRing::OnUnloaded(IInspectable const& sender, RoutedEventArgs const& e)
    {
        Cleanup();
    }

    void EverbloomScanRing::OnSizeChanged(IInspectable const& sender, SizeChangedEventArgs const& e)
    {
        if (m_rootVisual)
        {
            m_rootVisual.Size({ static_cast<float>(ActualWidth()), static_cast<float>(ActualHeight()) });
        }
    }

    void EverbloomScanRing::InitializeComposition()
    {
        if (!CompositionTarget::GetCurrentView())
            return;

        m_compositor = Compositor();
        m_rootVisual = m_compositor.CreateContainerVisual();
        ElementCompositionPreview::SetElementChildVisual(*this, m_rootVisual);

        CreateRingVisuals();
        CreatePetalLayer();
        CreateAnimations();
    }

    void EverbloomScanRing::CreateRingVisuals()
    {
        if (!m_compositor)
            return;

        // Track visual (background ring)
        m_trackVisual = m_compositor.CreateSpriteVisual();
        m_trackVisual.Size({ static_cast<float>(ActualWidth()), static_cast<float>(ActualHeight()) });
        m_trackVisual.Brush(m_compositor.CreateColorBrush(ColorHelper::FromArgb(255, 0x2A, 0x2A, 0x35)));
        m_trackVisual.CenterPoint({ static_cast<float>(ActualWidth() / 2), static_cast<float>(ActualHeight() / 2), 0 });
        m_rootVisual.Children().InsertAtBottom(m_trackVisual);

        // Progress ring using CompositionPath
        m_progressVisual = m_compositor.CreateSpriteVisual();
        m_progressVisual.Size({ 200, 200 });
        m_progressVisual.CenterPoint({ 100, 100, 0 });
        m_progressVisual.AnchorPoint({ 0.5f, 0.5f });

        // Create ring geometry
        auto pathBuilder = Microsoft::UI::Composition::CanvasPathBuilder(m_compositor);
        float radius = 96;
        float thickness = 4;
        
        // Outer circle
        pathBuilder.BeginFigure({ 100, 0 });
        pathBuilder.AddArc({ 100, 100 }, 100, 100, 0, static_cast<float>(2 * 3.14159265359));
        pathBuilder.EndFigure(CanvasFigureLoop::Closed);
        
        // Inner circle (hole)
        pathBuilder.BeginFigure({ 100, 100 - 96 });
        pathBuilder.AddArc({ 100, 100 }, 96, 96, 0, static_cast<float>(2 * 3.14159265359 * 2));
        pathBuilder.EndFigure(CanvasFigureLoop::Closed);

        auto geometry = CanvasGeometry::CreatePathGeometry(pathBuilder);
        auto ringShape = m_compositor.CreateSpriteShape(geometry);
        ringShape.FillBrush(m_compositor.CreateColorBrush(ColorHelper::FromArgb(255, 0xC8, 0x3B, 0x55)));
        
        m_progressVisual = m_compositor.CreateShapeVisual();
        m_progressVisual.Shapes().Append(ringShape);
        m_progressVisual.Size({ 200, 200 });
        m_progressVisual.CenterPoint({ 100, 100, 0 });
        m_progressVisual.AnchorPoint({ 0.5f, 0.5f });
        m_rootVisual.Children().InsertAtTop(m_progressVisual);
    }

    void EverbloomScanRing::CreatePetalLayer()
    {
        m_petalLayer = m_compositor.CreateContainerVisual();
        m_petalLayer.Size({ 200, 200 });
        m_petalLayer.CenterPoint({ 100, 100, 0 });
        m_petalLayer.AnchorPoint({ 0.5f, 0.5f });
        m_rootVisual.Children().InsertAtTop(m_petalLayer);
    }

    void EverbloomScanRing::CreateAnimations()
    {
        if (!m_compositor) return;

        // Progress animation
        m_progressPropertySet = m_compositor.CreatePropertySet();
        m_progressPropertySet.InsertScalar(L"Progress", 0.0f);

        m_progressAnimation = m_compositor.CreateScalarKeyFrameAnimation();
        m_progressAnimation.Duration(std::chrono::seconds(3));
        m_progressAnimation.IterationBehavior(AnimationIterationBehavior::Forever);
        m_progressAnimation.InsertKeyFrame(0.0f, 0.0f);
        m_progressAnimation.InsertKeyFrame(1.0f, 1.0f);
        m_progressAnimation.IterationBehavior(AnimationIterationBehavior::Forever);

        // Petal animation
        m_petalPropertySet = m_compositor.CreatePropertySet();
        m_petalPropertySet.InsertScalar(L"PetalProgress", 0.0f);

        m_petalAnimation = m_compositor.CreateScalarKeyFrameAnimation();
        m_petalAnimation.Duration(std::chrono::seconds(3));
        m_petalAnimation.IterationBehavior(AnimationIterationBehavior::Forever);
        m_petalAnimation.InsertKeyFrame(0.0f, 0.0f);
        m_petalAnimation.InsertKeyFrame(1.0f, 1.0f);

        // Petal position animation (expression)
        m_petalPositionAnimation = m_compositor.CreateExpressionAnimation();
        m_petalPositionAnimation.Expression(
            L"Vector2("
            "cos(Progress * 2 * PI) * Radius,"
            "sin(Progress * 2 * PI) * Radius"
            L")");
        m_petalPositionAnimation.SetReferenceParameter(L"Progress", m_petalPropertySet.GetScalar(L"PetalProgress"));
        m_petalPositionAnimation.SetScalarParameter(L"Radius", 80.0f);
        m_petalPositionAnimation.SetVector2Parameter(L"Center", Vector2(100, 100));

        // Rotation animation for the ring
        m_rotationAnimation = m_compositor.CreateScalarKeyFrameAnimation();
        m_rotationAnimation.Duration(std::chrono::seconds(20));
        m_rotationAnimation.IterationBehavior(AnimationIterationBehavior::Forever);
        m_rotationAnimation.InsertKeyFrame(0.0f, 0.0f);
        m_rotationAnimation.InsertKeyFrame(1.0f, 360.0f);
    }

    void EverbloomScanRing::CreatePetalParticles()
    {
        if (!m_compositor || !m_petalLayer) return;

        // Clear existing petals
        for (auto petal : m_petals)
        {
            petal.Dispose();
        }
        m_petals.clear();

        // Create petal particles
        for (int i = 0; i < 12; i++)
        {
            auto petal = m_compositor.CreateSpriteVisual();
            petal.Size({ 8, 8 });
            petal.CenterPoint({ 4, 4, 0 });
            petal.AnchorPoint({ 0.5f, 0.5f });
            petal.Margin({ 0, 0, 0, 0 });

            // Petal shape - small diamond
            auto petalGeometry = m_compositor.CreatePathGeometry();
            auto pathBuilder = Microsoft::UI::Composition::CanvasPathBuilder(m_compositor);
            pathBuilder.BeginFigure({ 4, 0 });
            pathBuilder.AddLine({ 8, 4 });
            pathBuilder.AddLine({ 4, 8 });
            pathBuilder.AddLine({ 0, 4 });
            pathBuilder.EndFigure(CanvasFigureLoop::Closed);
            auto geometry = CanvasGeometry::CreatePathGeometry(pathBuilder);

            auto shape = m_compositor.CreateSpriteShape(geometry);
            shape.FillBrush(m_compositor.CreateColorBrush(ColorHelper::FromArgb(26, 0xD9, 0x5B, 0x72)));
            shape.StrokeBrush(m_compositor.CreateColorBrush(ColorHelper::FromArgb(76, 0xD9, 0x5B, 0x72)));
            shape.StrokeThickness(1);

            auto petalVisual = m_compositor.CreateSpriteVisual();
            petalVisual.Size({ 8, 8 });
            petalVisual.CenterPoint({ 4, 4, 0 });
            petalVisual.AnchorPoint({ 0.5f, 0.5f });

            // Position on ring
            float angle = static_cast<float>(i * 3.14159265359 * 2 / 12);
            float radius = 96;
            petalVisual.Offset({
                100 + static_cast<float>(std::cos(angle) * 96),
                100 + static_cast<float>(std::sin(angle) * 96),
                0
            });
            petalVisual.CenterPoint({ 4, 4, 0 });

            // Add rotation animation
            auto rotationAnim = m_compositor.CreateScalarKeyFrameAnimation();
            rotationAnim.Duration(std::chrono::seconds(20));
            rotationAnim.IterationBehavior(AnimationIterationBehavior::Forever);
            rotationAnim.InsertKeyFrame(0.0f, 0.0f);
            rotationAnim.InsertKeyFrame(1.0f, 360.0f);
            petalVisual.StartAnimation(L"RotationAngleInDegrees", rotationAnim);

            // Add petal fall animation
            auto fallAnim = m_compositor.CreateScalarKeyFrameAnimation();
            fallAnim.Duration(std::chrono::seconds(3));
            fallAnim.IterationBehavior(AnimationIterationBehavior::Forever);
            fallAnim.InsertKeyFrame(0.0f, 0.0f);
            fallAnim.InsertKeyFrame(1.0f, 1.0f);

            auto positionAnimation = m_compositor.CreateExpressionAnimation();
            positionAnimation.Expression(
                L"Vector2("
                "Center.X + cos(Progress * 2 * PI) * Radius,"
                "Center.Y + sin(Progress * 2 * PI) * Radius"
                L")");
            positionAnimation.SetScalarParameter(L"Progress", m_petalPropertySet.GetScalar(L"PetalProgress"));
            positionAnimation.SetScalarParameter(L"Radius", 96.0f);
            positionAnimation.SetVector2Parameter(L"Center", Vector2(100, 100));

            m_petalPropertySet = m_compositor.CreatePropertySet();
            m_petalPropertySet.InsertScalar(L"PetalProgress", 0.0f);

            m_petalAnimation = m_compositor.CreateScalarKeyFrameAnimation();
            fallAnim.Duration(std::chrono::seconds(3));
            fallAnim.IterationBehavior(AnimationIterationBehavior::Forever);
            fallAnim.InsertKeyFrame(0.0f, 0.0f);
            fallAnim.InsertKeyFrame(1.0f, 1.0f);

            m_petalPropertySet.StartAnimation(L"PetalProgress", fallAnim);

            m_petalLayer->Children().InsertAtTop(petalVisual);
            m_petals.push_back(petalVisual);
        }
    }

    void EverbloomScanRing::InitializeAnimations()
    {
        if (!m_compositor) return;

        // Progress animation
        m_progressAnimation = m_compositor.CreateScalarKeyFrameAnimation();
        m_progressAnimation.Duration(std::chrono::seconds(3));
        m_progressAnimation.IterationBehavior(AnimationIterationBehavior::Forever);
        m_progressAnimation.InsertKeyFrame(0.0f, 0.0f);
        m_progressAnimation.InsertKeyFrame(1.0f, 1.0f);
        m_progressAnimation.IterationBehavior(AnimationIterationBehavior::Forever);

        // Petal animation
        m_petalAnimation = m_compositor.CreateScalarKeyFrameAnimation();
        m_petalAnimation.Duration(std::chrono::seconds(3));
        m_petalAnimation.IterationBehavior(AnimationIterationBehavior::Forever);
        m_petalAnimation.InsertKeyFrame(0.0f, 0.0f);
        m_petalAnimation.InsertKeyFrame(1.0f, 1.0f);

        // Rotation animation
        m_rotationAnimation = m_compositor.CreateScalarKeyFrameAnimation();
        m_rotationAnimation.Duration(std::chrono::seconds(20));
        m_rotationAnimation.IterationBehavior(AnimationIterationBehavior::Forever);
        m_rotationAnimation.InsertKeyFrame(0.0f, 0.0f);
        m_rotationAnimation.InsertKeyFrame(1.0f, 360.0f);

        // Petal fall animation
        auto petalFallAnim = m_compositor.CreateScalarKeyFrameAnimation();
        petalFallAnim.Duration(std::chrono::seconds(3));
        petalFallAnim.IterationBehavior(AnimationIterationBehavior::Forever);
        petalFallAnim.InsertKeyFrame(0.0f, 0.0f);
        petalFallAnim.InsertKeyFrame(1.0f, 1.0f);

        m_petalPropertySet = m_compositor.CreatePropertySet();
        m_petalPropertySet.InsertScalar(L"PetalProgress", 0.0f);
        m_petalPropertySet.StartAnimation(L"PetalProgress", m_petalAnimation);
    }

    void EverbloomScanRing::StartAnimations()
    {
        if (m_progressPropertySet && m_progressAnimation)
        {
            m_progressPropertySet.StartAnimation(L"Progress", m_progressAnimation);
        }
        if (m_petalPropertySet && m_petalAnimation)
        {
            m_petalPropertySet.StartAnimation(L"PetalProgress", m_petalAnimation);
        }
    }

    void EverbloomScanRing::StopAnimations()
    {
        if (m_progressPropertySet)
        {
            m_progressPropertySet.StopAnimation(L"Progress");
        }
        if (m_petalPropertySet)
        {
            m_petalPropertySet.StopAnimation(L"PetalProgress");
        }
    }

    void EverbloomScanRing::OnProgressChanged(winrt::Windows::UI::Xaml::DependencyObject const& d, winrt::Microsoft::UI::Xaml::DependencyPropertyChangedEventArgs const& e)
    {
        if (auto ring = d.try_as<EverbloomScanRing>())
        {
            ring.OnProgressChanged(ring, e);
        }
    }

    void EverbloomScanRing::OnIsScanningChanged(winrt::Windows::UI::Xaml::DependencyObject const& d, winrt::Microsoft::UI::Xaml::DependencyPropertyChangedEventArgs const& e)
    {
        if (auto ring = d.try_as<EverbloomScanRing>())
        {
            ring.OnIsScanningChanged(unbox_value<bool>(e.NewValue()));
        }
    }

    void EverbloomScanRing::OnShowPetalfallChanged(winrt::Windows::UI::Xaml::DependencyObject const& d, winrt::Microsoft::UI::Xaml::DependencyPropertyChangedEventArgs const& e)
    {
        if (auto ring = d.try_as<EverbloomScanRing>())
        {
            ring.OnShowPetalfallChanged(unbox_value<bool>(e.NewValue()));
        }
    }

    void EverbloomScanRing::OnProgressChanged(EverbloomScanRing const& ring, DependencyPropertyChangedEventArgs const& e)
    {
        if (ring.m_progressPropertySet)
        {
            ring.m_progressPropertySet.InsertScalar(L"Progress", static_cast<float>(unbox_value<double>(e.NewValue())));
        }
    }

    void EverbloomScanRing::OnIsScanningChanged(bool isScanning)
    {
        if (isScanning)
        {
            StartAnimations();
            VisualStateManager::GoToState(*this, L"Scanning", true);
        }
        else
        {
            StopAnimations();
            VisualStateManager::GoToState(*this, L"Idle", true);
        }
    }

    void EverbloomScanRing::OnShowPetalfallChanged(bool show)
    {
        if (m_petalLayer)
        {
            m_petalLayer.IsVisible(show);
        }
    }

    void EverbloomScanRing::StartAnimations()
    {
        if (m_progressPropertySet && m_progressAnimation)
        {
            m_progressPropertySet.StartAnimation(L"Progress", m_progressAnimation);
        }
        if (m_petalPropertySet && m_petalAnimation)
        {
            m_petalPropertySet.StartAnimation(L"PetalProgress", m_petalAnimation);
        }
    }

    void EverbloomScanRing::StopAnimations()
    {
        if (m_progressPropertySet)
        {
            m_progressPropertySet.StopAnimation(L"Progress");
        }
        if (m_petalPropertySet)
        {
            m_petalPropertySet.StopAnimation(L"PetalProgress");
        }
    }

    void EverbloomScanRing::Cleanup()
    {
        for (auto petal : m_petals)
        {
            petal.Dispose();
        }
        m_petals.clear();

        m_petalLayer = nullptr;
        m_rootVisual = nullptr;
        m_compositor = nullptr;
    }
}