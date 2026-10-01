EverbloomSecurity 安装前必读
====================

EverbloomSecurity 是一个工程原型级别的多语言杀毒软件，目的是把 WinUI 3 GUI、
Rust 扫描引擎、Python 分析工具、SQLite 哈希库、YARA 规则和 ONNX 模型
整合在一起进行研究与演示。

本程序并非生产级终端安全产品：

  * 不应替代 Microsoft Defender 或任何成熟商业杀毒软件；
  * 不应作为处理真实恶意样本的唯一安全边界；
  * 安装时建议在专用测试机或虚拟机上进行；
  * 安装后默认使用 {autopf}\EverbloomSecurity 作为目标目录，所有数据、规则、
    隔离区、日志都位于该目录的 bin\data\ 子目录下。

主要功能
--------

  * 文件/进程/注册表/网络遥测（ETW 内核 provider 解析）
  * YARA 规则扫描（默认 100+ 条规则，可热更新）
  * ONNX AI 模型推理（CPU/CPU-EP 路径）
  * 隔离区可移植变换（支持 EXPORT/IMPORT 备份还原）
  * 路径与 SHA-256 双重白名单
  * 攻击链（attack chain）关联
  * 命令行与 NDJSON IPC 通道

下一步
------

安装完成后：

  1. 双击桌面"EverbloomSecurity"图标启动 GUI；
  2. 在 Settings 中选择界面语言与是否启用云端占位（默认关闭）；
  3. 通过 Scan Center 拖入文件或目录，或在资源管理器右键"使用 EverbloomSecurity 扫描"
     (如果安装时勾选了"安装资源管理器右键扫描菜单")。

更多说明请见 doc\README.md 与 share\doc\EverbloomSecurity\README.md。
