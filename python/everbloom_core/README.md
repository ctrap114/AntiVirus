构建并安装本机扩展（Windows 示例）
=================================

先决条件
--------
- 已安装 Python（建议在项目虚拟环境中操作）
- Rust + Cargo 已安装（https://www.rust-lang.org/tools/install）
- Visual Studio Build Tools / Developer PowerShell（使 `cl` 可见）
- `maturin`（用于构建并安装 pyo3 扩展）

快速步骤
--------
1. 激活虚拟环境（示例）：

```powershell
& e:\EverbloomSecurity\.venv\Scripts\Activate.ps1
```

2. 安装 `maturin`：

```powershell
python -m pip install --upgrade pip
python -m pip install maturin
```

3. 在包含 Rust `Cargo.toml` 的工作目录（仓库根或 `libeverbloom_rs` 目录，根据项目）下运行：

```powershell
# 使用 with_yara 特性编译以启用 YARA
maturin develop --release --cargo-extra-args="--features with_yara"
```

这会在当前虚拟环境中构建并安装扩展为可 import 的模块（如 `libeverbloom_rs`）。

故障排查
--------
- 如果出现 `cl` 未找到，打开 Visual Studio 的 Developer PowerShell（或运行 VsDevCmd.bat）以注入编译器环境。
- 如果缺少 `yara` 依赖，请确保在 `Cargo.toml` 中启用了 `with_yara` 特性并安装了系统级 YARA（有些 yara-rust 绑定需要 libyara 可用）。

替代：如果你不想使用 `maturin`，也可以用 `pip install .` 或 `setuptools-rust`，但 `maturin` 更简单且跨平台。