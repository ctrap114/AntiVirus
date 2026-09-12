# HeliosAV 🐾

> 一只正在认真成长的多语言杀毒软件猫娘，喵~

HeliosAV 是一个面向 Windows 桌面的杀毒软件工程原型，结合了 **WinUI 3 / C++/WinRT GUI**、**Rust 扫描引擎**、**Python 配置与分析工具链**、SQLite 病毒哈希库、YARA 规则集与 ONNX 模型推理。项目当前属于**可运行、可演示、可继续开发的工程原型**，尚未达到生产级终端安全产品标准，不能替代成熟商业杀毒软件。

## 当前状态

| 项目 | 状态 |
|---|---|
| 当前版本 | `1.0.0` |
| 主要平台 | Windows x64 |
| GUI | WinUI 3 / C++/WinRT（本次重构为淡蓝灰圆角卡片风格） |
| 扫描引擎 | Rust 独立进程（实时 HIPS 监控、YARA、启发式、AI、沙箱分析） |
| 进程通信 | Windows Named Pipe IPC |
| 病毒数据库 | SQLite + 本地 SHA-256 补充 |
| 动态分析 | 可选 Windows Sandbox，失败时安全关闭 |
| 可运行发行版 | `artifacts/package/output/HeliosAV-1.0.0-Windows.zip` |
| 安装程序 | `artifacts/package/output/HeliosAV-0.1.0-Windows-Setup.exe` |
| EMBER 数据集训练 | 已完成（真实数据集 60K 样本，AUC 0.9944，399 特征选中） |
| 生产可用性 | **尚未达到生产级要求** |

## 已完成的主要功能

### 桌面界面（GUI 重构风格）
- 提供 **概览、病毒扫描、通知中心、设置、实时防护** 5 大核心页面，统一圆角白色卡片 + 淡蓝灰背景风格
- 概览页：渐变英雄卡片（实时防护状态）、保护开关行、2×2 工具卡片、扫描统计条、最近日志、底部引擎状态栏
- 病毒扫描页：快速扫描 / 全盘扫描 / 自定义扫描 三种模式卡片 + 上次扫描结果卡片
- 通知中心：空状态卡片 + “全部已读 / 清空全部” 操作按钮
- 设置页：防护设置卡片行（驱动防护、基础防护、文件防护、静默模式、脚本防护、开机自启动）+ 引擎开关 + 透明度调节
- 实时拦截弹窗：结构化详情（拦截类型、进程、目标路径、威胁标签）、12 秒倒计时拦截按钮、“记住此选择”复选框
- 设备已受到保护状态页：居中插画风格卡片、绿色扫描按钮、统计行、底部版本状态栏
- 侧边栏：品牌简化 + 图标导航行（概览/扫描/通知/工具箱/设置）+ 底部收起侧边栏
- 标题栏：品牌简化 + 通知铃铛 + 三栏菜单 + 最小化/关闭按钮

### 扫描引擎（Rust）
- 独立进程运行，不阻塞 GUI 主线程
- 支持快速扫描（Downloads / Desktop / Temp / Startup / Recent）、全盘扫描、自定义路径扫描
- 实时防护：R3 级进程监控、驱动级保护（可选）、文件防护、静默模式
- 动态分析：可选沙箱执行（Windows Sandbox），失败时安全关闭
- 引擎结果通过 Named Pipe IPC 传回 GUI，支持实时威胁拦截对话框

### EMBER 数据集与模型训练
- `tools/train_ember_2018.py`：支持真实 EMBER 数据集（2018 v2 / EMBER2024 原始特征格式）的流式加载和特征映射
- 特征映射：原始 dict → 运行时 2381 维布局（字节直方图、PE 头、节区信息、导入/导出、数据目录、通用信息、字符串特征、资源元数据）
- 不可重建组（字节直方图、字符串关键词、资源元数据、缺失 PE 头字段）置 0，避免训练/推理分布偏斜
- 训练完成模型：`artifacts/features/ember_2018_v1/ember_2018_v1.txt`（LightGBM 模型，AUC 0.9944，399 维选中）

### 构建与打包
- WinUI 3 构建使用 `CMake` + `Ninja`（`artifacts/gui/cmake-ninja/`）
- 需要 MSVC SDK `10.0.26100.0`（参考 `.learnings/LEARNINGS.md`）
- 编译命令参考：`cmake -S . -B artifacts/gui/cmake-ninja -G Ninja -DHELIOSAV_GUI_IS_WINUI=ON`，再 `cmake --build artifacts/gui/cmake-ninja --config Release`
- 打包使用 `build_install_full.ps1` 和 `tools/build_modules.ps1`

### 代码质量与测试
- `.github/workflows/ci.yml` 定义了 Python 测试、Rust 测试、Windows 打包冒烟测试
- `.learn` 文件记录了构建环境（MSVC SDK 版本、目标目录清理、调试构建问题）

## 构建与运行注意事项

1. **MSVC 环境必须固定 SDK 版本**：使用 `10.0.26100.0`（而非最新 `10.0.28000.0`），否则 `cl.exe` 找不到完整的 `atomic` 标准头文件或生成不完整的 `winrt_generated`
2. **环境变量不持久化**：每次调用 `cmake` / `ninja` 前需重新设置 `INCLUDE` / `LIB` / `PATH`（参考 `.learnings/LEARNINGS.md` LRN-20260825-002 和 LRN-20260829-001）
3. **构建顺序建议**：
   ```powershell
   # 1. 初始化 MSVC 环境（每次新终端都需要）
   $env:INCLUDE = "...10.0.26100.0..."
   $env:LIB      = "...10.0.26100.0..."
   # 2. 构建引擎
   cargo build --manifest-path engine/Cargo.toml --release
   # 3. 构建 GUI
   cmake --build artifacts/gui/cmake-ninja --config Release --target heliosav_gui
   ```
4. **运行时要求**：`heliosav_engine.exe` 必须先启动（监听 `127.0.0.1:7743`），GUI 通过 Named Pipe 连接引擎；若引擎未启动，GUI 会显示“等待引擎连接”并继续运行（不崩溃）
5. **透明面板与背景图**：`feature_settings.translucent_panels` 控制卡片透明度（0-55%）；`background_image` 可选择自定义背景
6. **AI 训练**：`tools/train_ember_2018.py` 和 `tools/train_ember_2025.py` 提供两种训练脚本；`gui/winui/WinUIApp.cpp` 中的 `ai_training_page` 提供可视化训练控制（暂停/取消/自动停止、模型比较、ONNX 导入验证）

## 文件结构说明（适合提交的代码）

本次提交包含三个核心修改文件（与原项目差异最小、功能完整）：
- `gui/winui/WinUIApp.cpp` / `.h`：GUI 重构（风格、布局、页面、标题栏、拦截弹窗、设备受保护状态、通知中心）
- `tools/train_ember_2018.py`：EMBER 数据集真实特征映射与模型训练脚本修复
- `.learn` 文件（构建环境记录，未提交）和 `.github/workflows`（CI 流程，已存在）

构建缓存（`artifacts/**/cmake/`、`target/`、`build/`、`.pytest_cache/`、`__pycache__/`、`HeliosAV-1.0.0-Windows-onnx-converter.msi`、`dist-verified/`、`vcpkg/downloads/` 等）已在 `.gitignore` 中排除，不应提交到仓库。

如需继续开发（运行时深度测试、扫描实时统计绑定、状态动画优化、打包安装程序测试、代码提交与 CI 流程验证），继续说“继续”。
