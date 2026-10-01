# Everbloom Security 当前部署布局

本文只描述当前活动链路，不再引用已移除的旧 GUI/Python 检测实现。

## 运行时布局

```text
EverbloomSecurity/
├─ gui/winui/                         WinUI 3 + C++/WinRT 界面源码
├─ engine/                            Rust 扫描引擎、IPC 和检测层
├─ data/
│  ├─ local_hashes.sqlite             当前本地哈希库
│  ├─ allowlist.json                  保守白名单
│  └─ rules/everbloom_core.yar         当前发行版 YARA 规则
├─ hashdb/HashDB.db                   旧版哈希数据库兼容输入
├─ everbloom_feature_cnn.onnx          可选 ONNX 模型
├─ everbloom_feature_cnn.onnx.data     ONNX 外部权重数据
├─ artifacts/
│  ├─ package/install/                当前安装树
│  ├─ package/output/                 ZIP、MSI 和 WiX 输出
│  └─ */bin/                          独立模块编译产物
└─ docs/                              安全边界、配置和测试说明
```

## 构建原则

- `gui/winui/` 是唯一支持的桌面 GUI；Qt 源码和 PySide 原型不再参与构建。
- `engine/` 是唯一活动扫描引擎；发行包只复制 Release 引擎和运行时数据。
- `artifacts/package/output/` 是唯一正式发行输出目录，根目录和旧目录不再放置副本。
- `target/`、CMake/CPack 目录、vcpkg 下载缓存和 ZIP 冒烟目录均为可再生缓存。
- Python 仅承担配置、报表和测试辅助功能，不是 WinUI 扫描运行时依赖。

## 资源查找顺序

引擎按以下顺序查找运行时资源：

1. 对应环境变量，例如 `EVERBLOOM_HASH_DB`、`EVERBLOOM_RULES_DIR` 和 `EVERBLOOM_AI_MODEL`；
2. GUI/引擎可执行文件同级的 `data/`、规则和模型文件；
3. 开发环境下的仓库相对路径。

发行包必须在 `bin/` 下同时包含 `everbloom_gui.exe`、`everbloom_engine.exe`、`data/`
和 Windows App SDK 运行时文件；安装包生成后应执行 ZIP 内容检查和 WinUI 启动冒烟测试。
