# WinUI 3 GUI

Everbloom Security 的桌面 GUI 已切换为 WinUI 3 + C++/WinRT。`gui/winui/` 是唯一参与
`everbloom_gui` 构建的桌面实现；Qt 桌面实现已移除，不再进入构建或打包链路。

## 已迁移功能

- Dashboard、Scan、Protection、Threats、Activity、Updates、Settings 页面。
- Fluent Light、Fluent Dark、Aurora、High Contrast 四种运行时主题。
- 英语、简体中文、日语、西班牙语完整界面目录；启动时跟随 Windows 区域语言，也可在 Settings 中即时切换。
- 纯 Win32 GUI 客户端，通过 Rust 引擎常驻进程的 stdin/stdout NDJSON 单行帧通信。
- WinUI 自主启动/停止 Rust 引擎，等待 `ready` 握手，区分 stdout EOF、读取错误和进程退出，并通过父进程 PID 自动回收引擎。
- Quick、Full、Custom 扫描，YARA/启发式/AI/沙箱开关，扫描进度和威胁结果展示。
- Win32 `ReadDirectoryChangesW` 用户态目录监控，将桌面、下载、文档和临时目录变化送入扫描 IPC；执行前阻断仍以驱动回调为准。
- 保护策略、规则语言、数据库热重载和运行时诊断页面。

## 本地依赖

- `cppwinrt:x64-windows`：`vcpkg/installed/x64-windows`。
- Windows App SDK NuGet metadata：`external/nuget/packages`。
- 需要 Visual Studio 的 Windows Desktop Development 工作负载和 Windows SDK。

## 构建

```powershell
cmake -S . -B build `
  -DCMAKE_TOOLCHAIN_FILE="$PWD/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DEVERBLOOM_VCPKG_TRIPLET=x64-windows
cmake --build build --config Release --target everbloom_gui
```

如果 CMake 找不到 Windows App SDK 或 cppwinrt，Windows 构建会退回到明确标记的
紧急 console stub；安装依赖后重新 configure 即可恢复 WinUI 构建。只有在 CI 或
依赖诊断场景才应显式使用 `-DEVERBLOOM_GUI_FORCE_STUB=ON`。

## 运行时目录

GUI 与 `everbloom_engine.exe` 放在同一目录时，会自动使用旁边的 `data/`、规则目录和
模型文件。GUI 不直接加载驱动，也不直接写 hash 数据库；内核阻断和数据库热重载仍由
引擎/驱动边界负责。
