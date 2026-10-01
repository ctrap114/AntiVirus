# Everbloom Security 模块化构建

`tools/build_modules.ps1` 将 Rust、WinUI 和驱动模块分别构建到 `artifacts/<模块名>/`，并在 `artifacts/build-manifest.json` 中记录本次构建状态和产物数量。

## 一次构建全部模块

在仓库根目录执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\build_modules.ps1 `
  -Modules all `
  -Configuration Release
```

脚本会自动探测 MSVC、Windows SDK 和 Ninja。Ninja 是单配置生成器，因此脚本会同时传递 `CMAKE_BUILD_TYPE`，确保 `Release` 不会意外使用 Debug 运行库。

## 按模块构建

```powershell
# Rust 引擎可执行文件
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_modules.ps1 -Modules engine

# Rust cdylib
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_modules.ps1 -Modules libeverbloom_rs

# Rust 沙箱监控库
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_modules.ps1 -Modules sandbox_monitor

# WinUI 3 GUI
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_modules.ps1 -Modules gui

# 用户态驱动核心、桩程序和 WDK 内核驱动
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build_modules.ps1 -Modules driver
```

## 产物目录

```text
artifacts/
├─ build-manifest.json
├─ engine/
│  ├─ target/                         # 该模块专属 Cargo target-dir
│  └─ bin/everbloom_engine.exe
├─ libeverbloom_rs/
│  ├─ target/
│  └─ bin/libeverbloom_rs.dll
├─ sandbox_monitor/
│  ├─ target/
│  └─ bin/libsandbox_monitor.rlib
├─ gui/
│  ├─ cmake-ninja/                    # 该模块专属 CMake/Ninja 中间文件
│  ├─ install/                        # CMake install 结果
│  └─ bin/everbloom_gui.exe
└─ driver/
   ├─ cmake-ninja/
   └─ bin/everbloom_driver.sys
```

脚本不会因为单个模块失败而提前退出；失败模块会在 manifest 中标记为 `failed` 并保留错误信息，便于继续处理其他模块。内核驱动安装和加载仍需要测试机、签名策略以及管理员权限，不应在日常开发机上直接加载未签名产物。
