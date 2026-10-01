# Everbloom Security GUI 启动故障修复与技术栈能力分析报告

# Everbloom Security GUI Startup Failure Fix and Technical Stack Capability Analysis Report

- 报告日期 / Report date: 2026-09-13
- 项目 / Project: Everbloom Security
- 范围 / Scope: 修复 GUI 无法启动、重新编译 GUI、重建 Inno Setup 安装包，并分析技术栈与能力边界。
- 状态 / Status: Fixed, rebuilt, smoke-tested

---

## 1. 执行摘要 / Executive Summary

### 中文

本次 GUI 无法启动的直接原因是 WinUI 视觉树中的控件被重复挂载到同一个父容器。标题栏按钮工厂函数 window_button 已经把新建按钮加入 caption_actions，调用方又再次追加汉堡按钮和通知按钮。WinUI 3 不允许同一个 UIElement 被重复作为父容器的子元素，因此抛出：

Element is already the child of another element.

修复内容是删除两处重复追加语句，保留 window_button 内部唯一的挂载路径。修复后的 GUI 已成功使用真实 WinUI 3 后端编译，新的 GUI 已同步到安装包暂存目录，Inno Setup 安装包已重新生成。

实际启动冒烟测试已确认：

- BuildMainContent: complete
- OnLaunched: main content built; assigning to Window
- OnLaunched: main content assigned
- WinUI main window activated
- Navigation: page visibility switched

### English

The direct cause of the GUI startup failure was a duplicated child attachment in the WinUI visual tree. The window_button factory had already appended every newly created button to caption_actions, while the caller appended the hamburger and notification buttons again. WinUI 3 rejects a UIElement that is attached to the same parent more than once and raised:

Element is already the child of another element.

The fix removes the two duplicate append statements and keeps one ownership path inside window_button. The corrected GUI was compiled with the real WinUI 3 backend, copied into the installer staging tree, and packaged again with Inno Setup.

The smoke test confirmed visual-tree completion, window content assignment, window activation, and navigation.

---

## 2. 交付结果 / Delivered Results

| 项目 / Item | 结果 / Result |
|---|---|
| 源码修复 / Source fix | 删除标题栏汉堡按钮和通知按钮的重复挂载 |
| GUI 构建 / GUI build | 成功，选择真实 WinUI 3 后端 |
| GUI 大小 / GUI size | 2,029,056 bytes |
| GUI SHA-256 | 4793ACDD7E1A35A13003277883CEA744D70FA2DAE6807D3C6938371073C0C4C5 |
| 安装包 / Installer | E:\EverbloomSecurity\EverbloomSecurity\artifacts\package\output\EverbloomSecurity-0.1.0-Windows-Setup.exe |
| Inno Setup 结果 / Inno result | exit code 0 |
| 安装包大小 / Installer size | 62.13 MB |
| GUI staging hash | 与编译输出完全一致 / identical to build output |
| 工作区清理 / Workspace cleanup | 已删除本次构建产生的临时 vcpkg 工具、缓存和兼容层 |

主要产物 / Main artifacts:

- GUI: E:\EverbloomSecurity\EverbloomSecurity\artifacts\gui\install\bin\everbloom_gui.exe
- GUI staging: E:\EverbloomSecurity\EverbloomSecurity\artifacts\package\install\bin\everbloom_gui.exe
- Installer: E:\EverbloomSecurity\EverbloomSecurity\artifacts\package\output\EverbloomSecurity-0.1.0-Windows-Setup.exe
- Startup log: C:\Users\Administrator\AppData\Local\Temp\EverbloomSecurity-gui-startup.log

---

## 3. 故障现象与根因 / Failure Symptoms and Root Cause

### 3.1 修复前日志 / Pre-fix log

修复前日志在页面表完成后立即失败：

~~~text
BuildMainContent: page table ready
OnLaunched: WinRT exception 0x2148470784: Element is already the child of another element.
WinUI unhandled exception 0x2148470784: Element is already the child of another element.
~~~

这证明以下阶段已经成功：

1. Windows App SDK Bootstrap 成功。
2. WinUI Application 创建成功。
3. 主窗口创建成功。
4. Dashboard、Scan、Protection、Threats、Settings 等页面创建成功。
5. 失败发生在 page table 之后、BuildMainContent: complete 之前。

### 3.2 触发错误的源代码 / Source code that triggered the error

文件：

E:\EverbloomSecurity\EverbloomSecurity\gui\winui\WinUIApp.cpp

修复前的工厂函数已经完成挂载：

~~~cpp
auto window_button = [palette, &caption_actions, glass_state](
    winrt::hstring const& glyph,
    bool danger) {
    auto button = controls::Button();
    // configure brush, icon and pointer events
    caption_actions.Children().Append(button);
    return std::make_pair(button, icon);
};
~~~

调用方又进行了重复挂载：

~~~cpp
auto hamburger_pair = window_button(L"\u2630", false);
caption_actions.Children().Append(hamburger_pair.first);

auto bell_pair = window_button(L"\u1F514", false);
caption_actions.Children().InsertAt(0, bell_pair.first);
~~~

执行顺序：

1. window_button 创建汉堡按钮并加入 caption_actions。
2. 调用方再次加入同一个汉堡按钮。
3. WinUI 发现元素已经拥有父关系，抛出异常。
4. 通知按钮存在同样的问题。

### 3.3 修复后的源代码 / Corrected source code

修复后只保留工厂函数内部的挂载：

~~~cpp
auto window_button = [palette, &caption_actions, glass_state](
    winrt::hstring const& glyph,
    bool danger) {
    // configure button
    caption_actions.Children().Append(button);
    return std::make_pair(button, icon);
};

auto hamburger_pair = window_button(L"\u2630", false);
auto bell_pair = window_button(L"\u1F514", false);
auto minimize_pair = window_button(L"\uE921", false);
auto maximize_pair = window_button(zoomed ? L"\uE923" : L"\uE922", false);
auto close_pair = window_button(L"\uE8BB", true);
~~~

删除的逻辑：

~~~diff
- caption_actions.Children().Append(hamburger_pair.first);
- caption_actions.Children().InsertAt(0, bell_pair.first);
~~~

### English root-cause analysis

The error was not caused by the driver, CAT file, Windows App Runtime installation, or engine process. The startup log proves that Windows App SDK initialization and page creation completed. The failure was a visual-tree ownership violation introduced by the new title-bar style.

The relevant invariant is:

A WinUI visual element must have one valid parent relationship at a time.

The factory had already established the parent relationship. The caller attempted to establish it again. Removing the caller-side append operations restores one-way ownership.

---

## 4. 技术栈分析 / Technology Stack Analysis

### 4.1 操作系统与原生工具链 / OS and native toolchain

| 层级 / Layer | 技术 / Technology | 能力分析 / Capability analysis |
|---|---|---|
| OS | Windows x64 | GUI、Windows App Runtime、驱动和 Inno Setup 都是 Windows 原生部署链 |
| Compiler | MSVC 14.51.36231 | 提供 C++23 编译、Windows ABI 和资源编译 |
| Windows SDK | 10.0.26100.0 | 提供 Win32 API、WinRT metadata、cppwinrt.exe 和系统库 |
| Build system | CMake + Ninja | 负责目标选择、投影生成、并行编译、链接和安装 |
| Language | C++23 | 支持现代 C++、WinRT projection、lambda、智能指针和异步状态 |
| Resource compiler | MSVC RC | 编译 GUI 图标和 Windows resource |
| Packaging | Inno Setup 6 | 将 staging tree 变成单一 Setup executable |

English: The toolchain is Windows-first and ABI-oriented. MSVC provides the C++23 and resource pipeline; CMake selects the real WinUI target; Ninja performs parallel compilation; the Windows SDK supplies WinRT metadata and native libraries; Inno Setup produces the distributable installer.

### 4.2 GUI 框架 / GUI framework

项目使用 WinUI 3 desktop，而不是 Qt 或 WebView desktop UI。

关键配置位于：

E:\EverbloomSecurity\EverbloomSecurity\gui\CMakeLists.txt

~~~cmake
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(EVERBLOOM_GUI_FORCE_STUB
       "Build the emergency console stub instead of WinUI" OFF)
set(EVERBLOOM_WINAPPSDK_BUNDLE_VERSION "2.3.1")
set(EVERBLOOM_CPPWINRT_VERSION "2.0.250303.1")
~~~

主要能力：

- WinUI 3 controls 和 Windows XAML object model。
- C++/WinRT projection，使用类型安全的 WinRT ABI 包装。
- Windows App SDK Bootstrap，按版本加载 Windows App Runtime。
- 原生 HWND 访问，用于无边框窗口、最小化、最大化、关闭和托盘。
- DispatcherQueue，将后台 IPC 和训练事件安全地切回 UI 线程。
- 主页面主要由 C++ 代码构建，不依赖一套大型 XAML markup 文件。

### 4.3 Windows App SDK 启动生命周期 / Windows App SDK startup lifecycle

入口文件：

E:\EverbloomSecurity\EverbloomSecurity\gui\main.cpp

核心代码：

~~~cpp
int __stdcall wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    init_apartment(apartment_type::single_threaded);
    ShowStartupWindow();

    const HRESULT bootstrap_result = MddBootstrapInitialize2(
        WINDOWSAPPSDK_RELEASE_MAJORMINOR,
        WINDOWSAPPSDK_RELEASE_VERSION_TAG_W,
        PACKAGE_VERSION{WINDOWSAPPSDK_RUNTIME_VERSION_UINT64},
        MddBootstrapInitializeOptions_None);

    if (FAILED(bootstrap_result)) {
        ShowStartupError(L"Windows App SDK Bootstrap", bootstrap_result);
        RunStartupMessageLoop();
        return static_cast<int>(bootstrap_result);
    }

    Application::Start([](auto&&) {
        g_app_instance = winrt::make_self<everbloom::gui::App>();
    });
}
~~~

生命周期：

1. 初始化单线程 COM apartment。
2. 显示启动状态窗口，避免启动失败看起来像隐藏进程。
3. 调用 MddBootstrapInitialize2 加载 Windows App Runtime。
4. 进入 Application::Start。
5. 创建 App implementation object。
6. App::OnLaunched 创建 Window 和主视觉树。
7. 将 BuildMainContent 返回的 root 设置为 Window Content。
8. 激活窗口。
9. 延后启动 engine process 和 protection monitor。

该设计把 runtime 初始化失败、WinUI 创建失败、页面构建失败和 engine 启动失败分成独立阶段。

### 4.4 视觉树与布局 / Visual tree and layout

WinUIApp.cpp 使用：

- Grid：根布局、列定义、行定义、标题栏和主体。
- Border：卡片、状态徽章、图标背景和面板。
- StackPanel：页面内容、导航行和标题行。
- ScrollViewer：主体滚动区域。
- Button：导航、扫描、窗口控制和操作。
- ComboBox：风格和配置选择。
- ToggleSwitch：引擎、驱动和保护开关。
- FontIcon 和文本 helper：标题栏和侧边栏图标。

页面由 NavigationPage 表驱动。页面先全部挂载到 page_host，再使用 Visibility 切换：

~~~cpp
for (size_t index = 0; index < pages->size(); ++index) {
    auto page_content = (*pages)[index].content;
    page_content.Visibility(
        index == 0
            ? xaml::Visibility::Visible
            : xaml::Visibility::Collapsed);
    page_host.Children().Append(page_content);
}
~~~

优点是页面对象和导航按钮共享同一状态。风险是每个 UIElement 的父容器必须唯一，不能重复 Append 或 InsertAt。

### 4.5 风格、主题和本地化 / Styling, themes and localization

支持的 UiStyle：

~~~cpp
enum class UiStyle {
    FluentLight,
    FluentDark,
    Aurora,
    HighContrast,
    Glass,
    Graphite,
    Rose,
};
~~~

支持的 accent：

- Blue
- Teal
- Orange
- Violet

能力范围：

- 浅色、深色、高对比度。
- 玻璃和半透明面板。
- 背景图片。
- 多种 accent。
- 中英文 UI string table。
- 运行时切换风格、语言、accent 和背景。
- 通过 ScanUiSnapshot 保存扫描状态，重建视觉树时不丢失进度和威胁数据。

运行时重建视觉树意味着每次风格、语言或背景切换都必须重新满足单父节点约束。业务状态可以复用，视觉控件不应跨父容器复用。

### 4.6 引擎进程和 IPC / Engine process and IPC

GUI 与 engine 是进程隔离架构。

文件：

E:\EverbloomSecurity\EverbloomSecurity\gui\winui\WinUIEngineProcess.h

核心说明：

~~~cpp
// The active transport is anonymous-pipe NDJSON on stdin/stdout.
bool Start(std::wstring endpoint = {});
HANDLE TakeStdinWriteHandle() noexcept;
HANDLE TakeStdoutReadHandle() noexcept;
~~~

EngineProcess 负责：

- 创建 everbloom_engine.exe 子进程。
- 创建 stdin/stdout anonymous pipes。
- 管理 PROCESS_INFORMATION 和 pipe handles。
- 暴露进程状态和 Win32 错误。

EngineClient 负责：

- 发送扫描、配置、模型、隔离区请求。
- 读取 NDJSON response/event frames。
- 转换进度、威胁、攻击链和连接状态。
- 使用 DispatcherQueue 将后台结果转回 UI 线程。
- 支持取消边界和超时边界。
- 提供 driver availability、realtime threat、quarantine 和 model validation 回调。

这种隔离可以分别处理 UI 崩溃、engine 崩溃和通信中断。

### 4.7 AI 训练子进程 / AI training subprocess

WinUITrainingRunner 使用独立子进程传回 NDJSON 事件：

- stage
- progress
- epoch
- comparison

训练能力：

- 生成 synthetic corpus。
- 训练 baseline 和 augmented model。
- 报告 epoch、loss、accuracy、best accuracy。
- 对比 baseline 和 augmented model。
- 导出胜出的 ONNX artifact。
- 训练进程运行时保持主 engine 的扫描 IPC 服务。

### 4.8 驱动和安装包 / Driver and installer

Inno Setup 脚本：

E:\EverbloomSecurity\EverbloomSecurity\tools\installer.iss

payload 组织：

~~~ini
Source: "{#SourceDir}\bin\*";    DestDir: "{app}\bin";    Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\doc\*";    DestDir: "{app}\doc";    Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\share\*";  DestDir: "{app}\share";  Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\driver\*"; DestDir: "{app}\driver"; Flags: ignoreversion recursesubdirs createallsubdirs
~~~

驱动安装是可选 task：

- 用户选择 driver task 后执行 install_driver.cmd。
- 驱动需要 INF、SYS 和 CAT。
- CAT 的签名由人工签名流程负责。
- 驱动安装可能需要管理员权限和重启。
- GUI 启动问题与驱动安装不是同一故障域；GUI 在 driver 初始化之前就会构建。

---

## 5. GUI 能力分析 / GUI Capability Analysis

| 页面 / Page | 能力 / Capability |
|---|---|
| Dashboard | 引擎状态、扫描统计、最近活动、快速扫描 |
| Scan | 快速扫描、全盘扫描、自定义路径、YARA、启发式、AI、Sandbox |
| Protection | R3 protection、driver protection、文件保护、quiet mode |
| Threats | 实时威胁、扫描威胁、批量允许、清理、隔离区 |
| Quarantine | 隔离项目、恢复、删除、批量操作 |
| Attack Chain | 多步骤行为链、链条详情和清理 |
| Activity | 引擎活动和系统事件 |
| Notifications | 通知列表、全部读取、清空 |
| Protected Device | 设备保护状态、保护统计和快速扫描 |
| Updates | 更新检查、病毒库/规则导入和状态 |
| AI Training | synthetic training、epoch 进度、模型对比、模型导出 |
| Settings | 风格、语言、accent、背景、上下文菜单、引擎开关、透明度、开机启动 |

可靠性能力 / Reliability capabilities:

- 启动阶段日志写入 TEMP。
- Windows App SDK 初始化失败时显示可见错误。
- WinRT、标准 C++ 和未知 exception 分层处理。
- EngineClient 与 UI 解耦。
- UI 重建时使用 ScanUiSnapshot 保留业务状态。
- RunUiSafely 包装大量事件处理器。
- 环境变量可以禁用 engine、tray、scan page 或限制页面数量。
- 页面切换使用 Visibility，而不是销毁 engine session。

---

## 6. 构建、打包和验证 / Build, Package and Verification

### 6.1 GUI 构建 / GUI build

使用仓库脚本：

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_modules.ps1 -Modules gui -Configuration Release
~~~

脚本执行：

1. 初始化 MSVC 和 Windows SDK 环境。
2. CMake configure，选择 Ninja。
3. 确认真实 WinUI backend，而不是 placeholder。
4. 编译 GUI C++ 源码和 Windows resource。
5. 链接 Windows App Runtime Bootstrap library。
6. 安装到 artifacts/gui/install。
7. 复制 GUI、PDB 和 Bootstrap DLL 到 artifacts/gui/bin。

构建日志包含：

~~~text
Building Everbloom Security GUI as a WinUI 3 desktop application using local NuGet Windows App SDK packages.
Configuring done
Generating done
Linking CXX executable everbloom_gui.exe
~~~

### 6.2 安装包构建 / Installer build

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_installer.ps1 -IsccPath "D:\Inno Setup 6\ISCC.exe"
~~~

结果：

~~~text
Installer built:
E:\EverbloomSecurity\EverbloomSecurity\artifacts\package\output\EverbloomSecurity-0.1.0-Windows-Setup.exe
(62.13 MB)
~~~

GUI 构建输出和 staging 文件 SHA-256 完全一致：

~~~text
SourceSHA256 = 4793ACDD7E1A35A13003277883CEA744D70FA2DAE6807D3C6938371073C0C4C5
StagedSHA256 = 4793ACDD7E1A35A13003277883CEA744D70FA2DAE6807D3C6938371073C0C4C5
Match        = True
~~~

### 6.3 冒烟测试 / Smoke test

测试时禁用了外部 engine/tray，仅验证完整 WinUI 主视觉树：

~~~powershell
$env:EVERBLOOM_DISABLE_ENGINE_PROCESS = "1"
$env:EVERBLOOM_DISABLE_ENGINE_CLIENT  = "1"
$env:EVERBLOOM_DISABLE_NATIVE_TRAY   = "1"
~~~

通过标准：

- 进程没有在页面构建阶段退出。
- BuildMainContent: complete 出现。
- Window Content 成功分配。
- Window 成功激活。
- 导航按钮能够改变页面 Visibility。

实际日志还确认：

~~~text
2026-9-13 8:52:29 | BuildMainContent: complete
2026-9-13 8:52:29 | OnLaunched: main content assigned
2026-9-13 8:52:29 | WinUI main window activated
2026-9-13 8:52:33 | Navigation: page visibility switched
~~~

---

## 7. 剩余问题和风险 / Remaining Issues and Risks

### 7.1 非致命的无边框窗口警告 / Non-fatal borderless-window warning

冒烟测试仍记录：

~~~text
ApplyBorderlessWindow: WinRT exception 0x2147500034
~~~

但随后继续出现：

~~~text
WinUI main window activated
OnLaunched: completed
~~~

因此这不是当前启动阻断问题。它说明某个边框处理接口在当前系统或 Windows App SDK 能力集中不可用。建议后续：

1. 增加 API contract 或 capability check。
2. 将该接口降级为 optional enhancement。
3. 失败时保留标准 window chrome，或使用兼容 HWND API。
4. 不要让该非致命异常影响主窗口激活。

### 7.2 C++/WinRT 依赖恢复 / C++/WinRT dependency restoration

本次构建前，工作区之前清理了 vcpkg/installed，导致固定版本 cppwinrt 无法直接从网络恢复。构建过程中复用了本机 Windows SDK 能力，建立了临时本地兼容层，并在构建完成后删除临时工具、vcpkg build cache 和兼容层。

后续全新工作区构建建议：

- 保留固定版 cppwinrt 的二进制缓存。
- 或把 cppwinrt 与 Windows App SDK artifact 放入内部缓存。
- 构建前检查 cppwinrt.exe、cppwinrt-config.cmake 和投影头文件是否存在。
- 保留 CMake 的严格版本校验，避免投影、metadata 和 runtime bundle 混用。

### 7.3 运行时依赖 / Runtime dependencies

安装包必须同时保证：

- Microsoft.WindowsAppRuntime.Bootstrap.dll
- Windows App Runtime MSIX packages
- 与 GUI 匹配的 WinUI metadata
- 正确的 everbloom_gui.exe
- engine executable 和 engine data
- driver payload、INF、SYS、CAT

GUI 运行失败时，建议顺序：

1. 查看 EverbloomSecurity-gui-startup.log。
2. 判断 Windows App SDK Bootstrap 是否成功。
3. 判断是否出现 BuildMainContent: complete。
4. 判断 Window Content assignment 是否成功。
5. 最后检查 engine process 和 driver availability。

---

## 8. 工程改进建议 / Engineering Recommendations

### 中文

1. 将标题栏按钮工厂改成纯工厂，返回 button/icon，由调用方统一负责 Append；或者将函数重命名为 CreateAndAppendWindowButton，明确其副作用。
2. 添加 debug-only AppendUniqueChild helper，在添加前检查 Parent 或维护 ownership registry。
3. 为 BuildMainContent 增加集成测试，至少覆盖页面表、标题栏、root Content assignment 和 window activation。
4. 统一启动日志编码为 UTF-8 或 UTF-16，避免当前日志中的部分中文乱码。
5. 将 ApplyBorderlessWindow 的 optional API 失败降级为 warning，并提供 HWND fallback。
6. CI 中比较 build output、package staging 和最终 installer source tree 的 GUI SHA-256。
7. 将 cppwinrt 和 Windows App SDK 包放入内部 artifact cache，避免 clean build 依赖外网。

### English

1. Make the title-bar helper a pure factory, or rename it to CreateAndAppendWindowButton so its side effect is explicit.
2. Add a debug-only AppendUniqueChild helper or ownership registry before inserting visual elements.
3. Add integration checks for page-table construction, title-bar construction, root content assignment, and window activation.
4. Standardize startup-log encoding to UTF-8 or UTF-16.
5. Treat borderless-window APIs as optional capabilities and provide an HWND fallback.
6. Compare GUI SHA-256 across build output, package staging, and installer input in CI.
7. Cache cppwinrt and Windows App SDK artifacts internally so clean builds do not depend on unstable external downloads.

---

## 9. 最终结论 / Final Conclusion

### 中文

本次 GUI 无法启动问题已解决。故障根因是新标题栏风格代码重复将同一 WinUI button 加入父容器。删除两处重复挂载后，GUI 可以完整构建主视觉树、分配窗口内容、激活窗口并响应页面导航。新的 GUI 已同步到并重新打包进 Inno Setup 安装包。

### English

The GUI startup failure has been resolved. The root cause was a duplicated parent attachment of the same WinUI button introduced by the new title-bar style. After removing the two duplicate append operations, the GUI completes visual-tree construction, assigns window content, activates the window, and responds to navigation. The corrected GUI is included in the rebuilt Inno Setup installer.
