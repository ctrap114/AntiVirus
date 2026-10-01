# 7. 桌面 GUI

`gui/` 是 Everbloom Security 的用户界面层：一个 C++23 / WinUI 3 / C++-WinRT 的 Windows 桌面应用，产物为 `everbloom_gui.exe`。

代码规模：`gui/winui/` 共 **10,532 行**（其中 `WinUIApp.cpp` 单文件 5,085 行）。

---

## 7.1 进程与启动链

### `main.cpp`（251 行）——引导入口

启动顺序：

**① 引导 Windows App SDK 运行时**

```cpp
const HRESULT bootstrap_result = MddBootstrapInitialize2(
    WINDOWSAPPSDK_RELEASE_MAJORMINOR,
    WINDOWSAPPSDK_RELEASE_VERSION_TAG_W,
    PACKAGE_VERSION{ WINDOWSAPPSDK_RUNTIME_VERSION_UINT64 },
    MddBootstrapInitializeOptions_None);
```

`MddBootstrapInitialize2` 把打包应用（MSIX）之外的进程"接"到已安装的 Windows App SDK 运行时上。返回失败时，进程不会静默退出——而是走下面的启动状态窗口路径。

**② 显示一个 Win32 启动状态窗口**

在 WinUI 初始化完成之前，先弹一个原生 Win32 窗口显示启动进度。窗口图标来自资源 `IDI_EVERBLOOM_ICON`：

```cpp
window_class.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_EVERBLOOM_ICON));
```

这个"启动中"窗口的存在是为了解决一个实际问题：WinUI 3 的初始化（含 XAML 元数据加载、投影解析）在冷启动时可能需要数百毫秒到数秒，期间若无反馈，用户会以为程序没启动。

**③ 启动 WinUI 应用**

```cpp
Application::Start([](auto&&) {
    StartupLog(L"Application::Start callback entered");
    ...
    g_app_instance = winrt::make_self<everbloom::gui::App>();
    StartupLog(L"Application::Start callback completed");
});
```

**④ 关闭引导**

```cpp
MddBootstrapShutdown();
```

### 启动日志

```cpp
std::filesystem::path StartupLogPath() { ... }
```

日志写入 `%TEMP%\EverbloomSecurity-gui-startup.log`。这是排查"GUI 起不来"的第一手资料——因为 GUI 子系统进程的 stdout 通常无处可去。

日志覆盖的里程碑：`MddBootstrapInitialize2` 结果、`Application::Start` 进入/返回、App 实例创建完成、异常类型与消息。

### 异常处理

```cpp
catch (const std::exception& e)  { SetStartupStatus(L"WinUI Application failed with a standard C++ exception.\nLog: " + StartupLogPath().wstring()); }
catch (...)                      { SetStartupStatus(L"WinUI Application failed with an unknown exception.\nLog: " + StartupLogPath().wstring()); }
```

异常不会让进程"无声消失"——状态窗口会显示失败原因并指向日志路径。

---

## 7.2 应用主体（`WinUIApp.cpp` / `WinUIApp.h`）

### `App` 类

```cpp
struct App : winrt::Microsoft::UI::Xaml::ApplicationT<App> { ... };
```

命名空间 `everbloom::gui`，实现在 `WinUIApp.cpp`（5,085 行），声明在 `WinUIApp.h`（147 行）。

### 用户可配置项（`WinUIApp.h`）

**7 种视觉风格**

```cpp
enum class UiStyle {
    FluentLight, FluentDark, Aurora, HighContrast, Glass, Graphite, Rose,
};
```

**4 种强调色**

```cpp
enum class UiAccent { Blue, Teal, Orange, Violet };
```

**功能开关**

```cpp
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
    uint8_t transparency_percent{12};       // 0 = 完全不透明，UI 钳制在 0..55%
    bool start_with_windows_enabled{false};
};
```

注意默认值反映的是**保守策略**：YARA 与启发式默认开启（纯本地、零成本），AI 与沙箱默认关闭（AI 需要模型加载，沙箱需要额外资源），R3 防护与驱动防护默认关闭（需用户显式开启）。

### 视觉树构建策略

`WinUIApp.cpp` 的视觉树**完全由本地辅助函数构建**，不依赖任何自定义 WinRT 控件：

```cpp
controls::Border EverbloomCard(xaml::UIElement const& child, const ThemePalette& palette);
controls::Button EverbloomButton(winrt::hstring const& label, const ThemePalette& palette);
controls::Image  SidebarIcon(const wchar_t* asset_name, double size);
controls::Border HeroEverbloomCard(const UiStrings& strings, const ThemePalette& palette);
```

`EverbloomCard()` 返回一个普通 `controls::Border`（圆角 + 背景 + 内边距），`EverbloomButton()` 返回普通 `controls::Button`（应用了主题调色板）。这套做法的直接收益是**零投影依赖**——因为项目的 cppwinrt 调用只为 Windows App SDK 生成投影，不生成自定义组件。

`gui/winui/` 下确实存在 6 个自定义控件的源码（`App.xaml`、`EverbloomButton`、`EverbloomCard`、`EverbloomNavigationView`、`EverbloomScanRing`、`MaterialAdapter`），但它们**不参与构建**——`gui/CMakeLists.txt` 通过 `EVERBLOOM_WIP_CONTROL_SOURCES` 过滤循环显式排除。签入的 `*.g.h` 文件是 `#pragma once` + include 的空壳，不是真实的 C++/WinRT 组件头。

### 侧栏

侧栏是普通圆角 `Border`：

```cpp
auto sidebar = controls::Border();
sidebar.Background(Brush(palette.sidebar));
```

它承载 `SidebarIcon()` 生成的 SVG 图标（来自 `gui/assets/sidebar/*.svg`，安装到 `share/everbloom/assets/sidebar/`）。

### 主内容构建

```cpp
winrt::Microsoft::UI::Xaml::UIElement BuildMainContent(
    UiStyle style, UiLanguage language, UiAccent accent,
    std::wstring background_image,
    std::function<void(UiStyle, UiLanguage, UiAccent, std::wstring)> on_preferences_changed,
    ... /* 共 15 个参数 */);
```

15 个参数的签名反映了一个刻意的设计：**视觉树是纯函数式的**——给定（风格、语言、强调色、背景图、各回调、各状态快照），返回一棵完整的视觉树。

### 重建而非增量更新

```cpp
void Rebuild(UiStyle style, UiLanguage language, UiAccent accent, std::wstring background_image);
```

`Rebuild()` **替换整棵视觉树，但不重启引擎会话**。这是关键设计：

> *"Rebuilds replace the visual tree, not the engine session. This snapshot is the small durable bridge that keeps an in-flight scan visible while the user re-themes the UI."*

`ScanUiSnapshot` / `ScanUiThreatSnapshot` 就是这个"持久桥"——把扫描状态从旧树搬到新树，使用户在换主题时不会丢失正在进行的扫描进度。

---

## 7.3 与引擎的通信（`WinUIEngineClient.cpp`，1,297 行）

### `EngineClient` 类

```cpp
class EngineClient final {
public:
    EngineClient(std::wstring endpoint,
                 winrt::Microsoft::UI::Dispatching::DispatcherQueue dispatcher,
                 HANDLE stdin_write = INVALID_HANDLE_VALUE,
                 HANDLE stdout_read = INVALID_HANDLE_VALUE);
    void Start();  void Stop();  void CancelScan();
    ...
};
```

构造时接收**两个已经建立好的管道句柄**（stdin 写端、stdout 读端），这些句柄由 `EngineProcess` 创建（见 7.4）。`DispatcherQueue` 用于把回调派发回 UI 线程。

### 三线程模型

```cpp
void Start() {
    m_worker   = std::thread([this] { WorkerLoop();   });   // 读 stdout、解码 JSON
    m_writer   = std::thread([this] { WriteLoop();    });   // 写 stdin
    m_watchdog = std::thread([this] { WatchdogLoop(); });   // 超时看门狗
}
```

| 线程 | 职责 |
|------|------|
| `WorkerLoop` | 逐行读引擎 stdout → `DecodeJsonLine` → 派发到 DispatcherQueue |
| `WriteLoop` | 从 `m_write_queue` 取行写 stdin |
| `WatchdogLoop` | 扫描超时检测 |

三个线程分离的理由：写操作不能阻塞读操作（否则引擎返回大量事件时会死锁），看门狗必须独立于两者才能可靠地检测"引擎不响应"。

### 请求队列

```cpp
constexpr size_t kMaximumQueuedRequests = 256;
constexpr size_t kMaximumLineSize = 16U * 1024U * 1024U;   // 16 MiB
```

队列满时的策略：**优先丢弃实时事件（realtime），保留手动扫描请求**。

```cpp
while (m_write_queue.size() >= kMaximumQueuedRequests) {
    const auto realtime_to_drop = std::find_if(m_write_queue.begin(), m_write_queue.end(),
        [](const auto& item) { return item.realtime; });
    if (realtime_to_drop == m_write_queue.end()) { rejected = true; break; }
    m_write_queue.erase(realtime_to_drop);
}
```

这条策略保证"用户主动发起的操作不会被后台遥测挤掉"。

### 单问单答与协作式取消

```cpp
void CancelScan();
```

注释明确说明设计约束：

> *"The protocol is deliberately one-question/one-answer. A second control frame cannot be consumed while Rust is scanning, so cancellation is cooperative: queued work is removed immediately and the in-flight request is allowed to return its timeout/cancelled response."*

即：

- **已入队**的扫描请求 → **立即移除**；
- **在途**的请求 → 等它自己超时或返回 cancelled（引擎在扫描期间不能读第二条控制帧）。

### 手动扫描的排他性

```cpp
const bool manual_already_present = m_scan_active.load() || m_inflight_scan
    || std::any_of(m_write_queue.begin(), m_write_queue.end(),
                   [](const auto& item) { return item.scan_request && !item.realtime; });
if (manual_already_present) { ReportError(L"A manual scan is already queued or running."); return; }
```

同一时刻只允许一个手动扫描在途/排队。实时扫描（`realtime = true`）不受此限。

### AI + 沙箱的独立超时

```cpp
constexpr uint32_t kAiSandboxScanTimeoutMs = 5U * 60U * 1000U;   // 5 分钟

uint32_t EffectiveScanTimeout(uint32_t requested_timeout_ms, bool sandbox_enabled, bool ai_enabled) {
    if (sandbox_enabled && ai_enabled) {
        return std::max(requested_timeout_ms, kAiSandboxScanTimeoutMs);
    }
    return requested_timeout_ms;
}
```

注释解释：

> *"AI inference plus a disposable VM/AppContainer can legitimately take longer than a normal static scan. Keep this timeout independent from the normal GUI scan timeout so the protocol deadline does not kill a healthy sandbox session while it is still collecting evidence."*

### 事件风暴限流

```cpp
constexpr uint32_t kMaximumR3EventsPerSecond = 8;
```

`DecodeJsonLine` 只由 worker 线程调用，但 R3 遥测事件可能成批涌入（例如一个进程加载了大量合法可执行区域）。因此设了每秒 8 条的预算：

```cpp
ULONGLONG m_r3_event_window_started_ms;
uint32_t  m_r3_event_window_count;
uint64_t  m_r3_event_window_suppressed;
```

`m_r3_event_window_suppressed` 记录被压制的数量——**压制是可见的**，不会静默丢事件。

### 进度节流

```cpp
std::mutex m_progress_throttle_mutex;
ULONGLONG m_last_progress_dispatch_ms;
```

注释说明：

> *"Progress is sampled on the IPC worker and delivered to WinUI at a bounded rate so a large directory scan cannot enqueue thousands of UI callbacks at once."*

大目录扫描可能产生数万条进度更新；如果每条都派发到 UI 线程，UI 会被回调淹没。

### 命令构造

所有出站帧由纯函数构造：

| 函数 | 命令 |
|------|------|
| `BuildScanLine(...)` | 扫描请求 |
| `BuildCommandLine(cmd, path?, strategy?, r3, driver)` | 通用控制命令 |
| `BuildQuarantineFileLine(path, reason)` | `QUARANTINE_FILE` |
| `BuildQuarantineRestoreLine(id, restore_path, overwrite)` | `RESTORE_QUARANTINE` |
| `BuildQuarantineDeleteLine(id)` | `DELETE_QUARANTINE` |
| `BuildQuarantineListLine(include_inactive)` | `LIST_QUARANTINE` |

路径统一经过 `NormalizePath()`（反斜杠 → 正斜杠），字符串统一经 `JsonString()` 转义（含 `\uXXXX` 控制字符转义）。

### 回调注册

九种事件处理器，全部通过 `Set*Handler` 注册：

```cpp
ProgressHandler             // 扫描进度
ResponseHandler             // 扫描结果
ConnectionHandler           // 连接状态
ErrorHandler                // 错误
ConfigHandler               // 配置重载结果
DriverAvailabilityHandler   // 驱动可用性
RealtimeThreatHandler       // 实时威胁
QuarantineHandler           // 隔离区操作结果
ModelValidationHandler      // 模型校验结果
```

`SetConnectionHandler` 有一个特殊行为：若客户端已启动或已连接，注册时会**立即回调当前状态**一次：

```cpp
const bool should_report_current_state = m_started.load() || m_connected.load();
...
if (should_report_current_state && m_connection_handler) {
    Dispatch([handler = m_connection_handler, connected] { handler(connected); });
}
```

这避免了"UI 注册太晚而错过连接事件，界面永远显示未连接"的问题。

### 停止语义

```cpp
void Stop();
```

- `EXIT` 命令是 **best-effort**：只有在引擎就绪、无扫描在途、无等待响应时才发送；
- 否则直接关闭 stdin/stdout —— 因为此时阻塞 GUI 等引擎读完边界，不如让 `EngineProcess` 的终止兜底来处理；
- 停止后清空队列、重置所有状态、清空实时路径集合。

---

## 7.4 引擎进程管理（`WinUIEngineProcess.cpp`，377 行）

### 启动流程

```cpp
bool EngineProcess::Start(std::wstring endpoint);
```

**① 定位引擎**

```cpp
const std::filesystem::path engine_path = std::filesystem::path(directory) / L"everbloom_engine.exe";
if (!std::filesystem::is_regular_file(engine_path, engine_file_error)) {
    m_last_error = L"The staged EverbloomSecurity engine was not found: " + engine_path.wstring();
    return false;
}
```

引擎与 GUI **同目录**。找不到时返回带完整路径的错误。

**② 设置传输环境**

```cpp
SetEnvironmentVariableW(L"EVERBLOOM_IPC_ENDPOINT", nullptr);              // 清空 → 走 NDJSON
SetEnvironmentValue(L"EVERBLOOM_PARENT_PID", std::to_wstring(GetCurrentProcessId()));
```

清空 `EVERBLOOM_IPC_ENDPOINT` 是让引擎的 `use_ndjson_transport()` 兜底判定选择 NDJSON；`EVERBLOOM_PARENT_PID` 用于引擎侧的父子进程关联（进程树分析）。

**③ 准备模型目录**

```cpp
std::filesystem::path UserModelDirectory();   // %LOCALAPPDATA%\EverbloomSecurity\models
```

创建目录并设置：

```cpp
SetEnvironmentValue(L"EVERBLOOM_AI_MODEL_DIR", model_directory.wstring());
SetEnvironmentValue(L"EVERBLOOM_AI_MODELS_CONFIG", (model_directory / L"models.json").wstring());
```

**④ 探测可选资源**

```cpp
// 哈希库
const auto hash_db = directory / L"data" / L"local_hashes.sqlite";
if (is_regular_file(hash_db)) { SetEnvironmentValue(L"EVERBLOOM_HASH_DB", hash_db.wstring()); }
else { SetEnvironmentVariableW(L"EVERBLOOM_HASH_DB", nullptr); }

// 规则目录
const auto rules_directory = directory / L"data" / L"rules";
if (is_directory(rules_directory)) { SetEnvironmentValue(L"EVERBLOOM_RULES_DIR", ...); }
```

找不到时**显式清空**环境变量（而不是留着旧值），避免继承到错误路径。

**⑤ 创建管道**

```cpp
CreatePipe(&child_stdin_read, &parent_stdin_write, &security_attributes, 0);
SetHandleInformation(parent_stdin_write, HANDLE_FLAG_INHERIT, 0);   // 父端不可继承
CreatePipe(&parent_stdout_read, &child_stdout_write, &security_attributes, 0);
SetHandleInformation(parent_stdout_read, HANDLE_FLAG_INHERIT, 0);
```

`SetHandleInformation(..., HANDLE_FLAG_INHERIT, 0)` 是关键：**父端句柄不可被子进程继承**。否则子进程会持有自己的 stdout 读端，导致父进程关闭句柄后子进程仍不退出。

子进程 stderr 被重定向到 `NUL`。

**⑥ 创建进程**

```cpp
std::wstring command_line = QuoteCommandLineArgument(engine_path.wstring()) + L" --ndjson";
CreateProcessW(engine_path.c_str(), command_line_buffer.data(), nullptr, nullptr,
               TRUE,                 // bInheritHandles
               CREATE_NO_WINDOW,     // 无控制台窗口
               nullptr, directory.c_str(), &startup, &process);
```

`CREATE_NO_WINDOW` 保证引擎不弹控制台窗口（引擎是 GUI 子系统，本来也不弹，但显式指定更稳妥）。

**⑦ 移交句柄**

```cpp
m_process      = process;
m_stdin_write  = parent_stdin_write;
m_stdout_read  = parent_stdout_read;
```

或者通过 `TakeStdinWriteHandle()` / `TakeStdoutReadHandle()` 移交给 `EngineClient`。

### 停止流程

```cpp
void EngineProcess::Stop();
```

1. 关闭 stdin / stdout 句柄（让引擎读到 EOF）；
2. 查询退出码：
   - 仍在运行 → `TerminateProcess` + 等待 3 秒；
   - 已退出 → 记录实际退出码；
3. 关闭进程句柄。

日志中区分三种结局：

```
RUST_ENGINE_EXIT status=observed code=<n>           // 引擎自己退出了
RUST_ENGINE_TERMINATING reason=gui_stop             // 需要强制终止
RUST_ENGINE_EXIT status=terminated_by_gui code=<n>  // 强制终止完成
```

### 辅助函数

| 函数 | 作用 |
|------|------|
| `QuoteCommandLineArgument()` | 命令行参数引号处理（含 `"` 转义） |
| `FromNarrow()` | 窄字符串 → 宽字符串，UTF-8 优先，失败回退 `CP_ACP` |
| `ErrorCodeMessage()` | `std::error_code` → 可读消息 |
| `FormatWin32Error()` | Win32 错误码 → 消息（`FormatMessageW`，去尾部换行） |
| `ExecutableDirectory()` | 取 GUI 自身所在目录 |
| `IsRunning()` | 进程是否仍在运行 |

`FromNarrow` 的双编码回退值得注意：先试 UTF-8，失败再试 ANSI 代码页。这使错误消息在两种常见编码下都能正确显示。

---

## 7.5 实时防护监视（`WinUIProtectionMonitor.cpp`，166 行）

```cpp
class ProtectionMonitor final {
public:
    using EventHandler = std::function<void(const std::wstring&)>;
    bool Start(std::vector<std::wstring> directories, EventHandler handler);
    void Stop();
    bool IsRunning() const;
private:
    void WorkerLoop(std::vector<std::wstring> directories, EventHandler handler);
    void MonitorDirectory(std::wstring directory, HANDLE handle, EventHandler handler);
    std::vector<HANDLE> m_handles;
};
```

这是 GUI 侧的**目录变更监视器**：对一组受保护目录（由 `ProtectionDirectories()` 提供）注册变更通知，把事件交给 `EventHandler`。

与引擎的 HIPS 不同，这一层是 GUI 侧的轻量监视，用于在 UI 上即时反映"受保护目录发生了变动"。它与引擎的行为采集是**互补**关系，不重复。

---

## 7.6 托盘图标（`WinUITrayIcon.cpp`，235 行）

```cpp
class TrayIcon final {
public:
    using Callback = ...;
    bool Install(HWND main_window, Callback show_callback, Callback exit_callback);
    void Remove();
    void AllowClose();
    bool IsInstalled() const noexcept;
private:
    void ShowContextMenu();
    void ShowMainWindow();
    void RequestExit();
    bool m_allow_close{false};
    bool m_installed{false};
};
```

### 关闭语义

`m_allow_close` 是"是否允许真正关闭窗口"的开关。典型流程：

1. 用户点击窗口关闭按钮 → `m_allow_close == false` → 窗口隐藏到托盘，进程继续运行；
2. 用户从托盘菜单选"退出" → `RequestExit()` 设 `m_allow_close = true` 再关闭 → 进程真正退出。

这是安全软件的标准交互：**关窗口 ≠ 关防护**。

---

## 7.7 本地化（`WinUILocalization.cpp`，736 行）

### 5 种语言

```cpp
enum class UiLanguage {
    English, SimplifiedChinese, TraditionalChinese, Japanese, Spanish,
};
```

显示名：

| 枚举 | 显示名 |
|------|--------|
| `SimplifiedChinese` | 简体中文 |
| `TraditionalChinese` | 繁體中文 |
| `Japanese` | 日本語 |
| `Spanish` | Español |
| `English` | English |

### 语言检测

```cpp
if (name.rfind(L"zh", 0) == 0) return UiLanguage::SimplifiedChinese;
if (name.rfind(L"ja", 0) == 0) return UiLanguage::Japanese;
if (name.rfind(L"es", 0) == 0) return UiLanguage::Spanish;
return UiLanguage::English;
```

先判 `TraditionalChinese`（`zh-TW` / `zh-HK` 等），再判 `zh*` 归入简体——顺序很重要，否则繁体会被简体分支先捕获。

### `UiStrings` 结构

```cpp
struct UiStrings {
    std::wstring app_subtitle{L"Endpoint security console"};
    std::wstring engine_connecting{L"Engine connecting..."};
    std::wstring engine_connected{L"Engine connected"};
    std::wstring engine_disconnected{L"Engine disconnected"};
    ...
};
```

所有字符串有**英文默认值**，缺翻译时自动回退——不会出现空字符串。

### 攻击链本地化

```cpp
std::wstring LocalizeChainStage(const std::wstring& stage, const UiStrings& strings);
std::wstring LocalizeChainStep(const std::wstring& label, const UiStrings& strings);
```

引擎返回的攻击链步骤标签是**引擎侧签名的原始字符串**（`EngineAttackChain::step_labels`）。GUI 通过这两个函数把它们映射到本地化文本。这保持了引擎与 GUI 的解耦：引擎不需要知道 UI 语言，GUI 也不需要知道引擎内部的关联名。

---

## 7.8 训练运行器（`WinUITrainingRunner.cpp`，380 行）

```cpp
struct TrainingRunnerEvent { ... };

class TrainingRunner final {
public:
    using FinishedHandler = std::function<void(bool success, const std::wstring& detail)>;
    bool Start(...);
    void Stop();
    bool IsRunning() const;
private:
    void ResetHandles();
};
```

`TrainingRunner` 让 GUI 能驱动引擎的 `--train-synthetic` 模式：以子进程方式启动引擎、读取其 JSON 输出、把进度转成 `TrainingRunnerEvent`、结束时回调 `FinishedHandler`。

因为引擎的 `--train-synthetic` 是**带外模式**（不占用 IPC 服务），GUI 可以在引擎继续对外扫描的同时跑训练。

---

## 7.9 GUI ↔ 引擎协议要点

| 项 | 值 / 规则 |
|----|-----------|
| 传输 | NDJSON over 匿名管道（stdin/stdout） |
| 编码 | UTF-8，`\n` 结尾 |
| 请求上限 | 16 MiB / 行 |
| 队列上限 | 256 条（满时优先丢实时事件） |
| 手动扫描 | 同一时刻最多 1 个在途/排队 |
| 取消 | 协作式：队列立即清、在途等超时 |
| AI+沙箱超时 | 至少 5 分钟 |
| R3 事件限流 | 8 条/秒（压制计数可见） |
| 进度 | 节流派发，避免 UI 回调淹没 |
| 路径规范化 | `\` → `/` |
| 引擎定位 | 与 GUI 同目录的 `everbloom_engine.exe` |

---

## 7.10 能力考量小结

| 考量 | 设计 |
|------|------|
| 冷启动无反馈 | 原生 Win32 "启动中"窗口 + 启动日志 |
| 引擎找不到 | 返回带完整路径的错误，不静默失败 |
| UI 线程安全 | 所有回调经 `DispatcherQueue` 派发 |
| 事件风暴 | 每秒预算 + 压制计数可见 |
| 大目录扫描 | 进度节流 |
| 换主题不丢状态 | `ScanUiSnapshot` 持久桥，重建视觉树而非会话 |
| 关窗口 ≠ 关防护 | 托盘图标 + `m_allow_close` 开关 |
| 自建控件不可用 | 视觉树全部由 `controls::Border` / `controls::Button` 本地辅助函数构建 |
| 引擎不响应 | 独立看门狗线程 |
| 句柄继承陷阱 | 父端管道句柄显式清除 `HANDLE_FLAG_INHERIT` |
