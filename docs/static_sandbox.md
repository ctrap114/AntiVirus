# 静态沙箱（Static Sandbox）可行性分析与实现

## 1. 概念

"静态沙箱"指**不执行样本**、仅凭静态证据预测其在动态沙箱中会展现的行为
能力（网络 C2、持久化、进程注入、凭据窃取、反调试/反虚拟机等）的分析层。
它与 `engine/src/sandbox.rs` 的动态沙箱互补：

| 维度 | 动态沙箱 | 静态沙箱 |
| --- | --- | --- |
| 执行样本 | 是（AppContainer/Job 或 Windows Sandbox VM） | 否 |
| 成本 | 秒级~分钟级，需要隔离后端 | 毫秒级，纯内存字节分析 |
| 依赖 | Windows 特性/本地受限令牌；不可用即 fail-closed | 无 |
| 证据强度 | 观测到的行为（强） | 行为意图预测（弱，需佐证） |
| 覆盖 | 仅可执行扩展名（.exe/.com/.scr/.bat/.cmd/.ps1/.msi） | 任何可读取字节的文件 |

## 2. 可行性依据

1. **API 组合与行为强相关**。导入表是 Windows 二进制行为的可靠代理：
   `WriteProcessMemory + CreateRemoteThread` 几乎必然意味着注入；
   `CryptUnprotectData` / 浏览器 `Login Data` 字符串几乎必然意味着凭据窃取。
   引擎已有成熟先例——`heuristic.rs` 的
   `score_api_combinations` 与链式规则（privilege/hooking chain）正是基于
   导入组合打分。
2. **现成原语可复用**：
   - `sandbox.rs::detect_anti_sandbox_indicators` 已实现 ASCII +
     UTF-16LE 双编码的 needle 匹配（含持久化 needle 列表）；
   - `unpacking.rs` 提供大小写不敏感字节搜索、base64 解码、内嵌 PE 扫描；
   - 扫描器在 hash/clamav 之后已物化 ≤64 MiB 的 `static_bytes` 快照，
     静态层可直接消费，无额外 I/O。
3. **失败模式可控**。最坏情况是"漏报"或"仅升级为可疑"，不会像动态执行
   那样产生逃逸风险；误报可通过"高置信能力链 + 独立佐证"双门槛抑制。

## 3. 设计

### 能力检测器（`layers/static_sandbox.rs`）

| 能力族 | 权重 | 证据来源 |
| --- | --- | --- |
| `recovery_inhibition:shadow_or_backup_deletion` | 0.60 | `vssadmin delete shadows` / `wbadmin delete catalog` / `wmic shadowcopy delete` / `bcdedit /set` / `recoveryenabled no` |
| `impact:mass_file_encryption_or_deletion` | 0.45 | 破坏性导入 >= 2（CryptEncrypt / CryptGenKey / DeleteFile / MoveFileEx / SHFileOperation / recurse），或 >= 1 且同时出现 `encrypted` 与 `ransom` |
| `injection:*` | 0.30 | 导入组合（WriteProcessMemory / VirtualAllocEx / CreateRemoteThread / SetWindowsHookEx 等） |
| `persistence:*` | 0.25 | `CurrentVersion\Run`、`schtasks /create`、启动目录、RunOnce（ASCII + UTF-16LE） |
| `credential_access:*` | 0.25 | CryptUnprotectData / vaultcli / 浏览器数据路径字符串 |
| `network:c2_endpoints` | 0.20 | 提取的 http(s) URL（封顶记录）或网络栈导入组合 |
| `execution:command_interpreter` | 0.20 | 解释器标记 >= 2，或 >= 1 且存在 CreateProcess / ShellExecute / WinExec / system 导入 |
| `evasion:*` | 0.15 | IsDebuggerPresent、VirtualBox / VMware / Sandboxie 探测串 |
| `discovery:*` | 0.12（枚举到安全产品时 x2） | 进程枚举导入或枚举串；命中安全产品名时加倍 |
| `recon:system_discovery` | 0.10 | GetComputerName / GetUserName / 网卡枚举导入 |

综合分 = 概率 OR（`1-∏(1-w)`）+ 佐证加成，封顶 0.95。

### 保守裁决规则

* 单独的静态预测**永远不产生 malicious**。
* 仅当同时满足以下三条时，扫描器把 reason 升级为
  `fusion:sbox_static:<caps>`（前缀 `fusion:` ⇒ 判定 Suspicious，
  不触发回滚）：
  1. 高置信能力链成立：注入 ∧ 持久化 ∧（网络 ∨ 凭据）；
  2. 存在独立佐证：heuristic ≥ 0.5 或 AI ≥ 0.5；
  3. 动态沙箱未启用（动态观测一旦存在则以其为准，避免双计）。

### 集成点

* 扫描阶段：AI 之后、静态 fusion pass 之前计算并附加到
  `ScanResult.static_sandbox`（缓存结果不携带该字段，属即时遥测）。
* NDJSON 响应：触发的能力以 `sbox_static:<capability>` 出现在
  `matched_rules` 中，reason 升级沿用既有 `fusion:` 契约。
* 缓存一致性：预测不参与 `ScanContext`，也不影响
  `cached_summary_is_immutable`——它只增强展示，不改变缓存语义。

## 4. 局限与后续

* 加壳/混淆样本的字符串与导入表可能不可见——此时静默降级为无预测，
  交由动态沙箱与解包快照层兜底。
* URL 提取为启发式边界识别（长度/字符类约束），非完整 RFC 解析。
* 后续可把预测能力映射为 `BehaviorEventKind` 先验，供动态沙箱
  自适应超时（预测注入链的样本延长观察窗口）参考。

## 5. 实现状态（2026-08-25）

设计已落地：`engine/src/layers/static_sandbox.rs`（分析器 + 6 个单元测试）、
`engine/src/scanner.rs`（`ScanResult.static_sandbox` 字段、AI 阶段后的计算与
保守升级、全部构造点补 `None`）、`engine/src/ndjson.rs`（`matched_rules`
追加 `sbox_static:<capability>`，take(16)）。端到端验证：手工构造含注入
导入 + 持久化标记 + C2 URL 的 PE 经 NDJSON 扫描后，matched_rules 出现全部
五条能力且 verdict 保持 Undetected（无独立佐证时不升级，符合设计）。
