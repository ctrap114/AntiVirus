# Everbloom Security — 安装内容构建清单

生成时间：2026-10-01 08:27

**暂存树**：`artifacts/package/install/`  ·  54 个文件  ·  107.2 MB

已构建完成，**停在 Inno Setup 打包之前**（未调用 `ISCC.exe`）。

## 目录结构

| 目录 | 文件数 | 大小 | 说明 |
| --- | ---: | ---: | --- |
| `bin/` | 27 | 62.5 MB | 引擎、GUI、模型、哈希库、YARA 规则、运行时引导 DLL 与辅助脚本 |
| `doc/` | 2 | 22.0 KB | 随包文档 |
| `driver/` | 3 | 90.3 KB | Inno Setup 的 [Files] driver\* 源（INF / CAT / SYS） |
| `bin/data/` | 6 | 23.4 MB | 哈希库 / 允许列表 / 易受攻击驱动清单 / YARA 规则 |
| `bin/driver/` | 5 | 4.6 MB | 内核驱动载荷（INF / SYS / stub / core lib） |
| `bin/models/` | 3 | 694.3 KB | 密集树集成模型 |
| `bin/tools/` | 1 | 8.4 KB | ONNX 转换工具 |
| `share/doc/` | 2 | 10.6 KB | 安装到 {app}\share 的文档副本 |
| `share/everbloom/assets/` | 15 | 1.1 MB | 图标与侧边栏 SVG（含 SetupIconFile 用的 .ico） |
| `share/everbloom/windows-app-runtime/` | 5 | 43.4 MB | Windows App SDK 运行时 MSIX |

## 全部文件

| 路径 | 大小 |
| --- | ---: |
| `bin/Microsoft.WindowsAppRuntime.Bootstrap.dll` | 384.8 KB |
| `bin/everbloom_engine.exe` | 31.2 MB |
| `bin/everbloom_feature_cnn.onnx` | 313.8 KB |
| `bin/everbloom_gui.exe` | 2.0 MB |
| `bin/features.json` | 22.4 KB |
| `bin/install_driver.cmd` | 1.9 KB |
| `bin/install_windows_app_runtime.cmd` | 2.3 KB |
| `bin/launch_gui.cmd` | 629 B |
| `bin/model_contract.json` | 102 B |
| `bin/register_context_menu.cmd` | 1.2 KB |
| `bin/uninstall_driver.cmd` | 1.4 KB |
| `bin/unregister_context_menu.cmd` | 343 B |
| `bin/data/HashDB.db` | 22.7 MB |
| `bin/data/allowlist.json` | 95 B |
| `bin/data/local_hashes.sqlite` | 576.0 KB |
| `bin/data/vulnerable_drivers.json` | 184 B |
| `bin/data/rules/everbloom_core.yar` | 34.3 KB |
| `bin/data/rules/everbloom_extended.yar` | 31.6 KB |
| `bin/driver/README.md` | 7.5 KB |
| `bin/driver/everbloom_driver.inf` | 4.2 KB |
| `bin/driver/everbloom_driver.sys` | 85.0 KB |
| `bin/driver/everbloom_driver_core.lib` | 3.6 MB |
| `bin/driver/everbloom_driver_stub.exe` | 923.0 KB |
| `bin/models/tree_ensemble/everbloom_dense_tree.onnx` | 689.2 KB |
| `bin/models/tree_ensemble/features.json` | 5.0 KB |
| `bin/models/tree_ensemble/model_contract.json` | 102 B |
| `bin/tools/convert_onnx_for_everbloom.py` | 8.4 KB |
| `doc/README.md` | 17.8 KB |
| `doc/SANDBOX_SECURITY.md` | 4.2 KB |
| `driver/everbloom_driver.cat` | 1.1 KB |
| `driver/everbloom_driver.inf` | 4.2 KB |
| `driver/everbloom_driver.sys` | 85.0 KB |
| `share/doc/EverbloomSecurity/README.md` | 6.4 KB |
| `share/doc/EverbloomSecurity/SANDBOX_SECURITY.md` | 4.2 KB |
| `share/everbloom/assets/everbloom_icon.ico` | 89.1 KB |
| `share/everbloom/assets/everbloom_icon.png` | 1.0 MB |
| `share/everbloom/assets/sidebar/activity.svg` | 290 B |
| `share/everbloom/assets/sidebar/ai-training.svg` | 715 B |
| `share/everbloom/assets/sidebar/attack-chain.svg` | 549 B |
| `share/everbloom/assets/sidebar/brand-mark.svg` | 348 B |
| `share/everbloom/assets/sidebar/dashboard.svg` | 464 B |
| `share/everbloom/assets/sidebar/device.svg` | 321 B |
| `share/everbloom/assets/sidebar/notifications.svg` | 307 B |
| `share/everbloom/assets/sidebar/protection.svg` | 337 B |
| `share/everbloom/assets/sidebar/scan.svg` | 315 B |
| `share/everbloom/assets/sidebar/settings.svg` | 347 B |
| `share/everbloom/assets/sidebar/sidebar-toggle.svg` | 254 B |
| `share/everbloom/assets/sidebar/threats.svg` | 311 B |
| `share/everbloom/assets/sidebar/updates.svg` | 354 B |
| `share/everbloom/windows-app-runtime/win10-x64/MSIX.inventory` | 428 B |
| `share/everbloom/windows-app-runtime/win10-x64/Microsoft.WindowsAppRuntime.2.msix` | 43.1 MB |
| `share/everbloom/windows-app-runtime/win10-x64/Microsoft.WindowsAppRuntime.DDLM.2.msix` | 102.8 KB |
| `share/everbloom/windows-app-runtime/win10-x64/Microsoft.WindowsAppRuntime.Main.2.msix` | 83.7 KB |
| `share/everbloom/windows-app-runtime/win10-x64/Microsoft.WindowsAppRuntime.Singleton.2.msix` | 160.7 KB |

## 校验

| 检查项 | 结果 |
| --- | --- |
| 树内旧名（`helios`/`heliosav`/`HeliosAV`）残留 | 0 |
| `installer.iss` SetupIconFile `share/everbloom/assets/everbloom_icon.ico` | 就位 |
| `LicenseFile` / `InfoBeforeFile`（tools/ 下） | 就位 |
| `UninstallDisplayIcon` `bin/everbloom_gui.exe` | 就位 |
| [Run]/[UninstallRun] 的 4 个 .cmd | 就位 |
| `everbloom_gui.exe` | x64 · subsystem 2 (Windows GUI) · 与构建产物 md5 一致 |
| `everbloom_engine.exe` | x64 · subsystem 2 (Windows GUI) · 与 cargo 产物 md5 一致 |
| `driver/everbloom_driver.sys` | x64 · subsystem 1 (Native) · 与 driver/build 产物 md5 一致 |
| `driver/everbloom_driver.cat` | Inf2Cat 重新生成（Errors: None / Warnings: None），只含 everbloom 条目 |

> 旧名文件未删除，已移至 `artifacts/package/_stale-pre-rename/`（在暂存树之外，不会被 `installer.iss` 的递归 `bin\* / doc\* / share\* / driver\*` 打进安装包）。
