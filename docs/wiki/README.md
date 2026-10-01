# Everbloom Security — 项目 Wiki

> 版本：`1.0.0` · 目标平台：Windows 10 1903+ / Windows 11（x64）· 文档语言：简体中文

本 Wiki 面向**产品维护者、集成方与安全评审人**，系统性说明 Everbloom Security 的每一部分代码、所用技术栈，以及关键的能力考量（capability considerations）——即"这个模块在什么约束下工作、它能做到什么、它的边界在哪里"。

文档按**默认每个模块正常工作**的前提撰写：描述的是模块的设计契约与运行时行为，而不是缺陷清单。少数确实属于工程约束的硬边界（例如内核态不能使用浮点、minifilter altitude 必须在 Microsoft 分配区间内）会在[第 11 章](11-能力考量与安全边界.md)中作为设计前提说明。

---

## 目录

| # | 页面 | 内容 |
|---|------|------|
| 1 | [架构总览](01-架构总览.md) | 三层进程模型、模块地图、数据流、目录职责 |
| 2 | [技术栈](02-技术栈.md) | Rust / C++ / C 的技术选型与依赖清单 |
| 3 | [构建与打包](03-构建与打包.md) | CMake + Ninja + cargo 三段构建、暂存、Inno Setup 打包 |
| 4 | [扫描引擎](04-扫描引擎.md) | `everbloom_engine` 的扫描流水线、传输层、缓存、HIPS、沙箱 |
| 5 | [检测层详解](05-检测层详解.md) | `layers/` 的 18 个模块逐一拆解：哈希 / YARA / 启发式 / AI / 融合 / 静态沙箱 / 行为序列 / 威胁情报 / 内存快照 / 解包 / 回滚 / Cookie 防护（含缓存与合成语料等非检测模块） |
| 6 | [内核驱动](06-内核驱动.md) | 6 个拦截面、`g_enforcement_matrix`、整数推理核心、IOCTL ABI、altitude 策略 |
| 7 | [桌面 GUI](07-桌面GUI.md) | WinUI 3 + C++/WinRT 客户端、与引擎的 NDJSON 传输、托盘、本地化、训练运行器 |
| 8 | [支撑模块](08-支撑模块.md) | `libeverbloom_rs` PyO3 绑定、`proto`、`python` 包、`edr`、`hashdb`、`data`、`quarantine`、`sandbox_monitor` |
| 9 | [工具链与模型训练](09-工具链与模型训练.md) | `tools/` 全部脚本：数据获取、特征抽取、模型训练与转换、质量基线、驱动运维 |
| 10 | [配置与数据格式](10-配置与数据格式.md) | 策略 JSON、allowlist、哈希库 schema、规则目录、模型契约文件 |
| 11 | [能力考量与安全边界](11-能力考量与安全边界.md) | 权限模型、隐私边界、性能预算、内核约束、威胁模型 |
| 12 | [检测质量与验证](12-检测质量与验证.md) | 验证体系设计、已实测基线、误报归因、阈值校准、待实测清单 |

---

## 一句话概括

Everbloom Security 是一套**Windows 端点防护系统**，由三部分组成：

1. **内核驱动**（`everbloom_driver.sys`，**C++17**，WDK 约束下近似 C 风格）——6 个低成本、早介入的拦截面，负责"在伤害发生前挡住"；
2. **用户态引擎**（`everbloom_engine.exe`，Rust，约 3.7 万行）——多引擎检测流水线，负责"判断与决策"，是唯一持有最终裁决权的一方；
3. **桌面 GUI**（`everbloom_gui.exe`，C++/WinUI 3）——面向用户的控制台，通过 NDJSON 与引擎通信。

设计上遵循一条主线：**决策在用户态，内核只做低成本的早期拦截**。内核不解析文件内容、不跑启发式、不做网络请求；它把"值得关注"的事实交给用户态，由用户态融合全部证据后再回灌策略。

---

## 快速开始（构建）

```bash
# 1. Rust 引擎
cargo build --release --manifest-path engine/Cargo.toml

# 2. GUI + 驱动（需 MSVC + WDK，见第 3 章）
cmake -S . -B artifacts/package/cmake-build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build artifacts/package/cmake-build

# 3. 暂存安装内容
cmake --install artifacts/package/cmake-build --prefix artifacts/package/install
```

---

## 阅读建议

- **第一次接触**：第 1 章 → 第 4 章 → 第 5 章。
- **做内核/驱动相关工作**：第 6 章 → 第 11 章。
- **做 GUI 或产品集成**：第 7 章 → 第 10 章。
- **做模型/检测效果调优**：第 5 章 → 第 9 章。
