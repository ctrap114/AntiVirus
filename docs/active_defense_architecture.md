# Active Defense Architecture for Everbloom Security

本文件将用户提供的“类似 Bitdefender + 卡巴斯基的主动防御多步主防”思路，映射到当前 Everbloom Security 引擎架构。

## 1. 数据采集与标准化（The Hook）

当前代码中已有的采集点：

- `engine/src/sandbox.rs`
  - sandbox 运行时监控文件变化、进程创建、网络连接、API 调用。
  - Windows 下使用 `sandbox_monitor::monitor_etw`，Unix 下可通过 `ptrace` 获取调用信息。
- `engine/src/layers/sandbox.rs` 中的 `SandboxReport` 已有结构化字段：
  - `files_changed`
  - `registry_writes`
  - `network_connections`
  - `processes`
  - `api_calls`

> 这里的关键点是：当前引擎已经有“行为日志采集层”，后续可以把 `sandbox_monitor` 扩展成真正的内核级 ETW/Minifilter 驱动采集器。

## 2. 计分引擎（ATC 风格）

新增模块：

- `engine/src/layers/behavior.rs`
  - `BehaviorEventKind`
  - `BehaviorEvent`
  - `BehavioralScorer`
  - `BehaviorScoreResult`

该模块负责将行为事件转换成归一化分数，用权重对恶意行为打分，并把这套机制做成进程级累积分数的 ATC 风格判定。

设计要点：

- 为每个进程维护“风险总分”，每个行为事件按类别赋予分值后累加。
- 增加可配置的安全级别：`激进` / `正常` / `宽松`，分别对应不同的触发阈值。
- 只有当进程风险总分达到当前级别阈值时，才认为该进程进入恶意判定。
- 持续监控进程行为，并将 `process_id -> behavior history` 作为长期信任状态的一部分。

当前默认权重示例：

- `ProcessInject`: 0.25
- `SuspiciousApiCall`: 0.20
- `RegistryWrite`: 0.18
- `FileWrite`: 0.15
- `NetworkConnect`: 0.12
- `PersistenceChange`: 0.15
- `DnsQuery`: 0.10

可补充的 ATC 典型行为类别：

- 凭证访问：凭证转储、访问 SAM 注册表、监控键盘输入
- 持久化：创建计划任务、注册服务、写入开机启动项
- 禁用服务：禁用 Windows 更新、终止安全进程
- 可疑文件操作：复制可疑文件、写双扩展名、隐藏系统文件
- 勒索软件行为：异常文件枚举、删除备份、批量加密痕迹
- 进程注入：DLL 注入、反射式 DLL 注入、进程镂空
- `ProcessInject`: 0.25
- `SuspiciousApiCall`: 0.20
- `RegistryWrite`: 0.18
- `FileWrite`: 0.15
- `NetworkConnect`: 0.12
- `PersistenceChange`: 0.15
- `DnsQuery`: 0.10

可补充的 ATC 典型行为类别：

- 凭证访问：凭证转储、访问 SAM 注册表、监控键盘输入
- 持久化：创建计划任务、注册服务、写入开机启动项
- 禁用服务：禁用 Windows 更新、终止安全进程
- 可疑文件操作：复制可疑文件、写双扩展名、隐藏系统文件
- 勒索软件行为：异常文件枚举、删除备份、批量加密痕迹
- 进程注入：DLL 注入、反射式 DLL 注入、进程镂空

并在 `engine/src/scanner.rs` 中加入：

- `Scanner::with_behavioral(...)`
- sandbox 后的行为评分逻辑
- 如果行为评分高于阈值，则触发恶意判定

## 3. 序列引擎（BSS 风格）

新增模块：

- `engine/src/layers/sequence.rs`
  - `SequenceSignature`
  - `SequenceMatcher`
  - `SequenceMatch`

该模块使用行为事件序列签名匹配恶意链。

当前默认签名示例：

- `process_injection_chain`
  - `ProcessCreate -> SuspiciousApiCall -> ProcessInject`
- `persistence_chain`
  - `RegistryWrite -> FileWrite -> ProcessCreate`
- `network_dropper`
  - `FileWrite -> NetworkConnect`

并在 `engine/src/scanner.rs` 中加入：

- `Scanner::with_sequence(...)`
- 如果序列匹配成功，则触发 `behavior_sequence` 判定

## 4. 综合裁决器与响应

目前扫描器执行顺序为：

1. `hash`
2. `yara`
3. `heuristic`按当前安全级别进行主动阻断、隔离或终止进程。
- 设计不同响应强度：激进级别可直接阻断/删除，正常级别先隔离并告警，宽松级别仅记录并跟踪。
- 记录文件/注册表/网络操作，用于后续“回滚”。
- 在检测到勒索行为时，提前备份可疑文件副本到临时目录，并在确认恶意后恢复被加密文件。
- 将采集到的行为事件保存到历史状态机，以便构建每个进程的长期行为状态。
- 通过进程洞察（PI）与 ATC 协同：ATC 负责风险评分与恶意判定，PI 负责监督受信任进程是否被劫持后执行异常行为。
6. `behavior` / `sequence`

这已经形成一个多层决策链：

- `hash` 和 `yara` 是静态规则层
- `heuristic` 和 `ai` 是特征+模型层
- `sandbox` 是行为监控层
- `behavior`/`sequence` 是行为评分与序列决策层

### 进一步响应能力

目前引擎已在 sandbox 超时后尝试终止目标进程，下一步可以扩展为：

- 如果检测结果为 `behavior_score` / `behavior_sequence`，按当前安全级别进行主动阻断、隔离或终止进程。
- 设计不同响应强度：激进级别可直接阻断/删除，正常级别先隔离并告警，宽松级别仅记录并跟踪。
- 记录文件/注册表/网络操作，用于后续“回滚”。
- 在检测到勒索行为时，提前备份可疑文件副本到临时目录，并在确认恶意后恢复被加密文件。
- 将采集到的行为事件保存到历史状态机，以便构建每个进程的长期行为状态。
- 通过进程洞察（PI）与 ATC 协同：ATC 负责风险评分与恶意判定，PI 负责监督受信任进程是否被劫持后执行异常行为。

## 5. 进阶方向。
- 实现类似卡巴斯基 System Watcher 的回滚逻辑：当行为序列匹配到恶意模式时，触发回滚。
- 回滚范围包括：
  - 文件活动：删除恶意软件创建的可执行文件，恢复被恶意修改或删除的文件。
  - 注册表活动：删除恶意软件创建的注册表键值（不恢复被修改或删除的键值）。
  - 系统活动：终止恶意进程或已被渗透的进程。
  - 网络活动：阻断恶意进程的网络访问。
- 对勒索软件行为额外保护：在可疑加密行为发生时，自动创建文件备份并保存到临时目录；一旦确认恶意，则恢复被加密文件。
- 未来实现可加入 `undo` 模块，将已知恶意操作反向执行。
### 高性能数据采集

- 将 `sandbox_monitor` 进一步增强为 Windows ETW 或 Minifilter 驱动
- 通过内核事件采集实时行为，避免当前 sandbox 机制的延迟与抽样问题

### 复杂规则/模式库

- 把更多行为特征与序列签名写成结构化规则库
- 例如，`YARA` 规则用于静态文件；`SequenceSignature` 用于运行时行为链

### 智能状态管理

- 为每个进程维护行为状态机
- 当前实现只是单次 sandbox 分析，后续可扩展为 `process_id -> behavior history`

### 精准回滚

- 在 `SandboxReport` 中记录的 `files_changed` / `registry_writes` 可作为回滚基础。
- 实现类似卡巴斯基 System Watcher 的回滚逻辑：当行为序列匹配到恶意模式时，触发回滚。
- 回滚范围包括：
  - 文件活动：删除恶意软件创建的可执行文件，恢复被恶意修改或删除的文件。
  - 注册表活动：删除恶意软件创建的注册表键值（不恢复被修改或删除的键值）。
  - 系统活动：终止恶意进程或已被渗透的进程。
  - 网络活动：阻断恶意进程的网络访问。
- 对勒索软件行为额外保护：在可疑加密行为发生时，自动创建文件备份并保存到临时目录；一旦确认恶意，则恢复被加密文件。
- 未来实现可加入 `undo` 模块，将已知恶意操作反向执行。

### 性能优化

- 目前 `SequenceMatcher` 是简单子串匹配
- 下一步可以使用 Aho-Corasick 或类似多模式匹配算法来加速行为模式识别

### 机器学习增强

- 现有 `AiModel` 已是结构化文件特征模型
- 可以新增行为序列模型，对 `BehaviorEvent` 序列进行异常检测

## 6. 当前改动位置

- `engine/src/layers/behavior.rs`
- `engine/src/layers/sequence.rs`
- `engine/src/layers/mod.rs`
- `engine/src/lib.rs`
- `engine/src/scanner.rs`
- `docs/active_defense_architecture.md`

---

这个改动已经把“多阶段行为评分 + 序列匹配 + 综合裁决”框架引入到当前引擎中。后续如果要继续推进，可以把 `sandbox` 数据源替换为真正的内核级 ETW/Minifilter 采集器，并补充回滚/终止执行逻辑。