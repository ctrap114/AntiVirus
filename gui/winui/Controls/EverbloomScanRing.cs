using Microsoft.UI.Composition;
using Microsoft.UI.Composition.Effects;
using Microsoft.UI.Composition.Toolkit;
using Microsoft.UI.Composition.Toolkit.Effects;
using Microsoft.UI.Composition.Animations;
using Microsoft.UI.Composition.Interactions;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Composition.Animations;
using Microsoft.UI.Composition.Effects;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Numerics;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;
using Windows.UI;
using Windows.UI.Composition;
using Windows.UI.Composition.Effects;
using Windows.UI.Composition.Animations;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;
using Windows.UI;
using Windows.UI.Composition;
using Windows.UI.Composition.Animations;
using Windows.UI.Composition.Effects;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Animation;
using Windows.UI.Xaml.Shapes;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Numerics;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;
using Windows.UI;
using Windows.UI.Composition;
using Windows.UI.Composition.Animations;
using Windows.UI.Composition.Effects;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Animation;
using Windows.UI.Xaml.Shapes;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Numerics;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;
using Windows.UI;
using Windows.UI.Composition;
using Windows.UI.Composition.Animations;
using Windows.UI.Composition.Effects;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Animation;
using Windows.UI.Xaml.Shapes;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Numerics;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;
using Windows.UI;
using Windows.UI.Composition;
using Windows.UI.Composition.Animations;
using Windows.UI.Composition.Effects;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Animation;
using Windows.UI.Xaml.Shapes;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Numerics;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;
using Windows.UI;
using Windows.UI.Composition;
using Windows.UI.Composition.Animations;
using Windows.UI.Composition.Effects;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Animation;
using Windows.UI.Xaml.Shapes;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Numerics;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Foundation.Metadata;
using Windows.UI;
using Windows.UI.Composition;
using Windows.UI.Composition.Animations;
using Windows.UI.Composition.Effects;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Animation;
using Windows.UI.Xaml.Shapes;

namespace EverbloomSecurity.GUI.WinUI.Controls;

/// <summary>
/// EverbloomScanRing - Custom scan progress ring with Petalfall particle system
/// Features: Crimson progress ring, falling petal particles, sword accent, MITRE ATT&CK tags
/// </summary>
public sealed class EverbloomScanRing : Control
{
    // Dependency Properties
    public static readonly DependencyProperty ProgressProperty =
        DependencyProperty.Register(
            nameof(Progress),
            typeof(double),
            typeof(EverbloomScanRing),
            new PropertyMetadata(0.0, OnProgressChanged));

    public static readonly DependencyProperty IsScanningProperty =
        DependencyProperty.Register(
            nameof(IsScanning),
            typeof(bool),
            typeof(EverbloomScanRing),
            new PropertyMetadata(false, OnIsScanningChanged));

    public static readonly DependencyProperty CurrentStageProperty =
        DependencyProperty.Register(
            nameof(CurrentStage),
            typeof(string),
            typeof(EverbloomScanRing),
            new PropertyMetadata("Initializing"));

    public static readonly DependencyProperty StageProgressProperty =
        DependencyProperty.Register(
            nameof(StageProgress),
            typeof(double),
            typeof(EverbloomScanRing),
            new PropertyMetadata(0.0));

    public static readonly DependencyProperty ShowPetalfallProperty =
        DependencyProperty.Register(
            nameof(ShowPetalfall),
            typeof(bool),
            typeof(EverbloomScanRing),
            new PropertyMetadata(true, OnShowPetalfallChanged));

    public static readonly DependencyProperty ScanStagesProperty =
        DependencyProperty.Register(
            nameof(ScanStages),
            typeof(ObservableCollection<ScanStage>),
            typeof(EverbloomScanRing),
            new PropertyMetadata(null));

    public double Progress
    {
        get => (double)GetValue(ProgressProperty);
        set => SetValue(ProgressProperty, value);
    }

    public bool IsScanning
    {
        get => (bool)GetValue(IsScanningProperty);
        set => SetValue(IsScanningProperty, value);
    }

    public string CurrentStage
    {
        get => (string)GetValue(CurrentStageProperty);
        set => SetValue(CurrentStageProperty, value);
    }

    public double StageProgress
    {
        get => (double)GetValue(StageProgressProperty);
        set => SetValue(StageProgressProperty, value);
    }

    public bool ShowPetalfall
    {
        get => (bool)GetValue(ShowPetalfallProperty);
        set => SetValue(ShowPetalfallProperty, value);
    }

    public ObservableCollection<ScanStage> ScanStages
    {
        get => (ObservableCollection<ScanStage>)GetValue(ScanStagesProperty);
        set => SetValue(ScanStagesProperty, value);
    }

    // Composition
    private Compositor? _compositor;
    private ContainerVisual? _rootVisual;
    private SpriteVisual? _ringVisual;
    private SpriteVisual? _progressVisual;
    private SpriteVisual? _trackVisual;
    private ContainerVisual? _petalLayer;
    private List<SpriteVisual> _petals = new();
    private CompositionPropertySet? _progressPropertySet;
    private CompositionPropertySet? _petalPropertySet;
    private ScalarKeyFrameAnimation? _progressAnimation;
    private ScalarKeyFrameAnimation? _petalAnimation;
    private ExpressionAnimation? _petalPositionAnimation;
    private ScalarKeyFrameAnimation? _rotationAnimation;
    private CompositionScopedBatch? _batch;

    public EverbloomScanRing()
    {
        DefaultStyleKey = typeof(EverbloomScanRing);
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        SizeChanged += OnSizeChanged;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        InitializeComposition();
        InitializeAnimations();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Cleanup();
    }

    private void InitializeComposition()
    {
        if (CompositionTarget.GetCurrentView()?.Compositor is not Compositor compositor)
            return;

        _compositor = compositor;
        _rootVisual = _compositor.CreateContainerVisual();
        ElementCompositionPreview.SetElementChildVisual(this, _rootVisual);

        CreateRingVisuals();
        CreatePetalLayer();
        CreateAnimations();
    }

    private void CreateRingVisuals()
    {
        if (_compositor == null) return;

        // Track visual (background ring)
        _trackVisual = _compositor!.CreateSpriteVisual();
        _trackVisual.Size = new Vector2((float)ActualWidth, (float)ActualHeight);
        _trackVisual.Brush = _compositor.CreateColorBrush(Color.FromArgb(255, 0x2A, 0x2A, 0x35)); // #2A2A35
        _trackVisual.CenterPoint = new Vector3((float)(ActualWidth / 2), (float)(ActualHeight / 2), 0);
        _rootVisual!.Children.InsertAtBottom(_trackVisual);

        // Create ring shape using CompositionPath
        var ringGeometry = _compositor.CreatePathGeometry();
        var pathBuilder = _compositor.CreatePathGeometryBuilder(CanvasGeometry.CreatePathGeometry(
            CanvasGeometry.CreatePathGeometry(
                new CanvasPathBuilder(_compositor).BuildGeometry()
            )
        ));

        // Create ring using composition path
        var ringVisual = _compositor.CreateSpriteVisual();
        ringVisual.Size = new Vector2(200, 200);
        ringVisual.CenterPoint = new Vector3(100, 100, 0);
        ringVisual.AnchorPoint = new Vector2(0.5f, 0.5f);

        // Create ring shape using CompositionPath
        var pathBuilder = new CanvasPathBuilder(_compositor);
        float radius = 80;
        float thickness = 4;
        
        // Outer circle
        pathBuilder.AddArc(new System.Numerics.Vector2(100, 100), 100, 100, 0, (float)Math.PI * 2);
        pathBuilder.EndFigure(CanvasFigureLoop.Closed);
        
        // Inner circle (hole)
        pathBuilder.BeginFigure(new System.Numerics.Vector2(100, 100 - 96));
        pathBuilder.AddArc(new System.Numerics.Vector2(100, 100), 96, 96, 0, (float)Math.PI * 2);
        pathBuilder.EndFigure(CanvasFigureLoop.Closed);

        var geometry = CanvasGeometry.CreatePathGeometry(pathBuilder);
        var shapeVisual = _compositor.CreateShapeVisual();
        var ringShape = _compositor.CreateSpriteShape(geometry);
        ringShape.FillBrush = _compositor.CreateColorBrush(Color.FromArgb(255, 0xC8, 0x3B, 0x55)); // Crimson
        shapeVisual.Shapes.Add(ringShape);
        shapeVisual.CenterPoint = new Vector3(100, 100, 0);
        shapeVisual.Size = new Vector2(200, 200);
        _rootVisual!.Children.InsertAtTop(shapeVisual);
    }

    private void CreatePetalLayer()
    {
        _petalLayer = _compositor!.CreateContainerVisual();
        _petalLayer.Size = new Vector2(200, 200);
        _petalLayer.CenterPoint = new Vector3(100, 100, 0);
        _petalLayer.AnchorPoint = new Vector2(0.5f, 0.5f);
        _rootVisual!.Children.InsertAtTop(_petalLayer);
    }

    private void CreateAnimations()
    {
        if (_compositor == null) return;

        // Progress animation
        _progressPropertySet = _compositor.CreatePropertySet();
        _progressPropertySet.InsertScalar("Progress", 0f);

        _progressAnimation = _compositor.CreateScalarKeyFrameAnimation();
        _progressAnimation.Duration = TimeSpan.FromSeconds(3);
        _progressAnimation.InsertKeyFrame(0f, 0f);
        _progressAnimation.InsertKeyFrame(1f, 1f);
        _progressAnimation.IterationBehavior = AnimationIterationBehavior.Forever;

        // Petal animation
        _petalPropertySet = _compositor.CreatePropertySet();
        _petalPropertySet.InsertScalar("PetalProgress", 0f);

        _petalAnimation = _compositor.CreateScalarKeyFrameAnimation();
        _petalAnimation.Duration = TimeSpan.FromSeconds(3);
        _petalAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
        _petalAnimation.InsertKeyFrame(0f, 0f);
        _petalAnimation.InsertKeyFrame(1f, 1f);

        // Petal position animation (expression)
        _petalPositionAnimation = _compositor.CreateExpressionAnimation();
        _petalPositionAnimation.Expression = @"
            Vector2(
                cos(Progress * 2 * PI) * Radius,
                sin(Progress * 2 * PI) * Radius
            )";
        _petalPositionAnimation.SetReferenceParameter("Progress", _petalPropertySet.GetScalar("PetalProgress"));
        _petalPositionAnimation.SetScalarParameter("Radius", 80f);
        _petalPositionAnimation.SetVector2Parameter("Center", new Vector2(100, 100));

        // Rotation animation for the ring
        _rotationAnimation = _compositor.CreateScalarKeyFrameAnimation();
        _rotationAnimation.Duration = TimeSpan.FromSeconds(20);
        _rotationAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
        _rotationAnimation.InsertKeyFrame(0f, 0f);
        _rotationAnimation.InsertKeyFrame(1f, 360f);
    }

    private void CreatePetalParticles()
    {
        if (_compositor == null || _petalLayer == null) return;

        // Clear existing petals
        foreach (var petal in _petals)
        {
            petal.Dispose();
        }
        _petals.Clear();

        // Create petal particles
        for (int i = 0; i < 12; i++)
        {
            var petal = _compositor.CreateSpriteVisual();
            petal.Size = new Vector2(8, 8);
            petal.CenterPoint = new Vector3(4, 4, 0);
            petal.AnchorPoint = new Vector2(0.5f, 0.5f);
            
            // Petal shape - small diamond
            var petalGeometry = _compositor.CreatePathGeometry();
            var pathBuilder = new CanvasPathBuilder(_compositor);
            pathBuilder.BeginFigure(new Vector2(4, 0));
            pathBuilder.AddLine(new Vector2(8, 4));
            pathBuilder.AddLine(new Vector2(4, 8));
            pathBuilder.AddLine(new Vector2(0, 4));
            pathBuilder.EndFigure(CanvasFigureLoop.Closed);
            var geometry = CanvasGeometry.CreatePathGeometry(pathBuilder);
            
            var shape = _compositor.CreateSpriteShape(CanvasGeometry.CreatePathGeometry(pathBuilder));
            shape.FillBrush = _compositor.CreateColorBrush(Color.FromArgb(26, 0xD9, 0x5B, 0x72)); // 10% opacity crimson
            shape.StrokeBrush = _compositor.CreateColorBrush(Color.FromArgb(76, 0xD9, 0x5B, 0x72));
            shape.StrokeThickness = 1;
            
            var petalVisual = _compositor.CreateSpriteVisual();
            petalVisual.Size = new Vector2(8, 8);
            petalVisual.CenterPoint = new Vector3(4, 4, 0);
            petalVisual.AnchorPoint = new Vector2(0.5f, 0.5f);
            
            // Position on ring
            float angle = (float)(i * Math.PI * 2 / 12);
            float radius = 96;
            petalVisual.Offset = new Vector3(
                100 + (float)(Math.Cos(i * Math.PI * 2 / 12) * 96),
                100 + (float)(Math.Sin(i * Math.PI * 2 / 12) * 96),
                0
            );
            petalVisual.CenterPoint = new Vector3(4, 4, 0);
            
            // Add rotation animation
            var rotationAnim = _compositor.CreateScalarKeyFrameAnimation();
            rotationAnim.Duration = TimeSpan.FromSeconds(20);
            rotationAnim.IterationBehavior = AnimationIterationBehavior.Forever;
            rotationAnim.InsertKeyFrame(0f, 0f);
            rotationAnim.InsertKeyFrame(1f, 360f);
            petalVisual.StartAnimation("RotationAngleInDegrees", rotationAnim);
            
            // Add petal fall animation
            var fallAnim = _compositor.CreateScalarKeyFrameAnimation();
            fallAnim.Duration = TimeSpan.FromSeconds(3);
            fallAnim.IterationBehavior = AnimationIterationBehavior.Forever;
            fallAnim.InsertKeyFrame(0f, 0f);
            fallAnim.InsertKeyFrame(1f, 1f);
            
            var positionAnimation = _compositor.CreateExpressionAnimation();
            positionAnimation.Expression = @"
                Vector2(
                    Center.X + cos(Progress * 2 * PI) * Radius,
                    Center.Y + sin(Progress * 2 * PI) * Radius
                )";
            positionAnimation.SetScalarParameter("Progress", _petalPropertySet.GetScalar("PetalProgress"));
            positionAnimation.SetScalarParameter("Radius", 96f);
            positionAnimation.SetVector2Parameter("Center", new Vector2(100, 100));
            
            petalVisual.StartAnimation("Offset", positionAnimation);
            
            _petalLayer.Children.InsertAtTop(petalVisual);
            _petals.Add(petalVisual);
        }
    }

    private void InitializeAnimations()
    {
        if (_compositor == null) return;

        // Progress animation
        _progressAnimation = _compositor.CreateScalarKeyFrameAnimation();
        _progressAnimation.Duration = TimeSpan.FromSeconds(3);
        _progressAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
        _progressAnimation.InsertKeyFrame(0f, 0f);
        _progressAnimation.InsertKeyFrame(1f, 1f);
        _progressAnimation.IterationBehavior = AnimationIterationBehavior.Forever;

        // Petal animation
        _petalAnimation = _compositor.CreateScalarKeyFrameAnimation();
        _petalAnimation.Duration = TimeSpan.FromSeconds(3);
        _petalAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
        _petalAnimation.InsertKeyFrame(0f, 0f);
        _petalAnimation.InsertKeyFrame(1f, 1f);

        // Rotation animation for the ring
        var rotationAnim = _compositor.CreateScalarKeyFrameAnimation();
        rotationAnim.Duration = TimeSpan.FromSeconds(20);
        rotationAnim.IterationBehavior = AnimationIterationBehavior.Forever;
        rotationAnim.InsertKeyFrame(0f, 0f);
        rotationAnim.InsertKeyFrame(1f, 360f);

        // Petal fall animation
        var petalFallAnim = _compositor.CreateScalarKeyFrameAnimation();
        petalFallAnim.Duration = TimeSpan.FromSeconds(3);
        petalFallAnim.IterationBehavior = AnimationIterationBehavior.Forever;
        petalFallAnim.InsertKeyFrame(0f, 0f);
        petalFallAnim.InsertKeyFrame(1f, 1f);

        _petalPropertySet = _compositor.CreatePropertySet();
        _petalPropertySet.InsertScalar("PetalProgress", 0f);
        _petalPropertySet.StartAnimation("PetalProgress", _petalAnimation);
    }

    private void StartAnimations()
    {
        if (_progressPropertySet != null && _progressAnimation != null)
        {
            _progressPropertySet.StartAnimation("Progress", _progressAnimation);
        }
        if (_petalPropertySet != null && _petalAnimation != null)
        {
            _petalPropertySet.StartAnimation("PetalProgress", _petalAnimation);
        }
    }

    private void OnProgressChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is EverbloomScanRing ring && ring._progressPropertySet != null)
        {
            ring._progressPropertySet.InsertScalar("Progress", (float)(double)e.NewValue);
        }
    }

    private static void OnProgressChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is EverbloomScanRing ring)
        {
            ring.OnProgressChanged(ring, new DependencyPropertyChangedEventArgs());
        }
    }

    private static void OnIsScanningChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is EverbloomScanRing ring)
        {
            ring.OnIsScanningChanged((bool)e.NewValue);
        }
    }

    private void OnIsScanningChanged(bool isScanning)
    {
        if (isScanning)
        {
            StartAnimations();
            VisualStateManager.GoToState(this, "Scanning", true);
        }
        else
        {
            StopAnimations();
            VisualStateManager.GoToState(this, "Idle", true);
        }
    }

    private static void OnShowPetalfallChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is EverbloomScanRing ring)
        {
            ring.OnShowPetalfallChanged((bool)e.NewValue);
        }
    }

    private void OnShowPetalfallChanged(bool show)
    {
        if (_petalLayer != null)
        {
            _petalLayer.IsVisible = show;
        }
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (_rootVisual != null)
        {
            _rootVisual.Size = new Vector2((float)ActualWidth, (float)ActualHeight);
            if (_rootVisual.Children.Count > 0 && _rootVisual.Children[0] is SpriteVisual track)
            {
                track.Size = new Vector2((float)ActualWidth, (float)ActualHeight);
            }
        }
    }

    private void Cleanup()
    {
        foreach (var petal in _petals)
        {
            petal.Dispose();
        }
        _petals.Clear();
        
        _petalLayer?.Dispose();
        _petalLayer = null;
        _rootVisual?.Dispose();
        _rootVisual = null;
        _compositor = null;
    }
}

public class ScanStage
{
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool IsCompleted { get; set; }
    public bool IsCurrent { get; set; }
    public double Progress { get; set; }
    public string Description { get; set; } = "";
    public string StatusIcon { get; set; } = "";
}