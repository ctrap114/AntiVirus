# 驱动矩阵（Driver Matrix）架构分析与落地设计

本文回答两个问题：**当前驱动代码存在哪些具体缺陷**，以及**把驱动改为「矩阵」形态在工程上意味着什么、代价是什么、应该怎么分阶段落地**。

文档中的每一项结论都对应可复核的证据（文件 + 行号 + 实测结果）。

---

## 一、当前驱动的真实结构

`driver/` 目录实际包含**两套互不相干的代码**，这一点在文档中长期被混为一谈。

| 组成 | 文件 | 行数 | 性质 |
|---|---|---|---|
| 内核入口 | `sys_driver.cpp` | 430 | 真实 WDM 控制面 |
| 内核策略 | `kernel_policy.cpp` | 938 | 策略表 + 事件环 |
| 内核拦截 | `kernel_components.cpp` | 987 | 6 个拦截面 |
| 用户态模块 | `src/*.cpp` | 每个 23–42 | **仿真桩** |

`driver/CMakeLists.txt:162-164` 明确说明：用户态策略库使用 STL / iostream / mutex，「**must never be linked into kernel mode**」。`src/main.cpp` 是一个打印决策的 demo 可执行文件。

因此 README 中列出的 6 个「驱动模块」（self_protection、file_protection、amsi、realtime_scan、network_firewall、advanced_threat）**只以约 40 行的仿真形式存在，并未接入 `.sys`**。真正的内核逻辑全部在 `kernel_components.cpp` 与 `kernel_policy.cpp` 中。这是文档与实现的第一处系统性偏差。

### 实际注册的内核拦截面（`kernel_components.cpp`）

```
PsSetCreateProcessNotifyRoutineEx    :930   进程创建/退出，可否决
PsSetLoadImageNotifyRoutine          :938   镜像加载，仅遥测（无否决权）
FltRegisterFilter / FltStartFiltering:943/948 文件系统 minifilter
CmRegisterCallbackEx                 :543   注册表
ObRegisterCallbacks                  :574   对象句柄
FwpsCalloutRegister2                 :870   WFP 网络
```

`driver/README.md:16-30` 只描述了其中 **3 个**，`docs/main_protection_driver_contract.md:42` 仍称其为「最小 WDM 控制面，不是完整的文件系统 minifilter」。两处描述均已过期。

---

## 二、已修复的具体缺陷

### 2.1 内核紧急门限存在确定性误报（已修复）

`sys_driver.cpp` 的紧急门限原先使用纯子串匹配，其中包含一个 **3 字节** 指示器：

```cpp
contains_ascii_case_insensitive(payload, length, "rop")
```

该针会命中 `Europe`、`property`、`drop`、`proxy`、`appropriate` 等普通单词，使内核拒绝路径在正常 payload 文本上触发。

**修复**：引入最短特异性约束 `kMinUnboundedNeedleLength = 5`。长度小于 5 字节的针必须落在**词边界**上（前后字节均非 `[A-Za-z0-9_]`）；长度 ≥ 5 字节的针保持子串语义，因此 `"powershell"` 仍可匹配 `...\WindowsPowerShell\v1.0\powershell.exe` 这类路径。该约束在匹配器内部统一实施，后续新增短针自动受保护。

### 2.2 IOCTL 白名单双份定义（已修复）

`is_supported_operation()` 与 `dispatch_device_control()` 内部各自维护一份操作码列表，`evaluate_request()` 又引用其中一份。新增 IOCTL 时若只改一处，会产生「不可达的 handler」或「未校验的路径」。

**修复**：`dispatch_device_control` 改为调用 `is_supported_operation(ioctl_code)`，并引入局部变量 `ioctl_code` 消除重复的 `stack->Parameters.DeviceIoControl.IoControlCode` 取值。白名单收敛为单一真值源。

### 2.3 内核搜索未锚定（已修复）

`contains_ascii_case_insensitive` 原先在**每个偏移**都完整比较整个针，5 字节针 × 64 KiB payload ≈ 32 万次字节比较。

**修复**：改为**首字节锚定**——先用一次比较排除绝大多数偏移，仅对候选位置执行完整比较。与 Rust 侧 `static_sandbox.rs` 的 `find_bytes` 采用同一策略。此改动不改变任何匹配结果，只改变到达结果的代价。

### 2.4 源文件编码卫生（已修复）

修复 2.1 时引入的破折号（U+2014）在 codepage 936 下触发 `warning C4819`。内核源码必须能在任意代码页下编译，已全部改为 ASCII。

### 2.5 构建可复现性（已验证）

驱动现在**可以完整构建并产出真实内核镜像**。实测结果：

```
everbloom_driver.sys   74,240 bytes
  machine         8664 (x64)
  entry point     0000000140001ED0  DriverEntry
  subsystem       1 (Native)
  imports         FLTMGR.SYS, fwpkclnt.sys
```

`everbloom_kernel_policy_path_tests.exe` 退出码 0。

可复现的构建配方（缺一不可）：

```bash
export PATH="/f/insiders/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64:/c/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64:$PATH"
export INCLUDE="F:/insiders/VC/Tools/MSVC/14.51.36231/include;C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/ucrt;C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um;C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/shared"
export LIB="F:/insiders/VC/Tools/MSVC/14.51.36231/lib/x64;C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/ucrt/x64;C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/um/x64"
cmake -S driver -B driver/build-ninja -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build driver/build-ninja
```

关键点：**WDK 内核工具链位于 `10.0.28000.0`，而非 `10.0.26100.0`**（后者只有 ucrt/um/shared，没有 `km`）。`CMakeLists.txt` 的 `find_path` 提示列表已优先探测 28000，因此无需改动。但 `rc.exe` / `mt.exe` 必须来自 `Windows Kits/10/bin/10.0.26100.0/x64` 并在 `PATH` 上，否则 CMake 的编译器探测阶段会失败。

---

## 三、把驱动改为「矩阵」：两种解读的可行性

「矩阵」在驱动语境下有两种合理技术含义，工程代价差别很大。

### 3.1 解读 A：驱动矩阵（拆分为多驱动）

**现状**：单个 `.sys` 内并列注册 6 个拦截面，全部共享一个 `DriverEntry`、一个卸载路径、一份策略存储。

**拆分方案**：

| 驱动 | 职责 | 理由 |
|---|---|---|
| `everbloom_core.sys` | 控制设备、IOCTL ABI、策略存储、进程/镜像/注册表/对象回调、自保护 | 状态所有者 |
| `everbloom_flt.sys` | 仅文件系统 minifilter | 独立的 altitude 与卸载语义 |
| `everbloom_net.sys` | 仅 WFP callout | 崩溃风险最高，隔离价值最大 |

驱动间通过**私有设备接口 + 版本化共享结构**通信（扩展 `include/everbloom_driver_protocol.h`），而不是共享内核全局变量。

**收益（客观）**：
- 故障隔离——WFP 分类回调是内核中最易出问题的位置，其缺陷不应连带文件保护。
- 独立更新节奏与独立卸载。

**代价（客观，且不可忽略）**：
1. **签名成本 ×3**：每个 `.sys` 都需要独立签名（EV 证书 + 认证签名）。
2. **minifilter altitude 是受限全局命名空间**：生产环境不能随意选取 altitude，必须使用 Microsoft 分配的区段。
3. **跨驱动 ABI 版本化成为硬约束**：3 个二进制必须同时一致，加载顺序与部分加载失败都要处理。
4. 调试与现场排障复杂度显著上升。

**结论**：拆分在**故障隔离**上确有价值，但把它作为第一步是不划算的——在单一 `.sys` 尚未稳定、且已有 2.1–2.3 这类确定缺陷的情况下，先拆分会把缺陷复制到 3 个二进制里。

### 3.2 解读 B：内核矩阵运算（模型下沉）

**先说不可行项**：把 `tract`/ONNX 运行时移植进内核**不可行**。`tract` 是用户态 Rust crate，依赖 rayon 线程池、动态分派与堆分配，无法链接进内核镜像。这不是「移植」，而是「重写」。

**内核侧的真实硬约束**：

| 约束 | 影响 |
|---|---|
| x64 内核默认**不可用浮点** | 需 `KeSaveExtendedProcessorState`，且**仅限 PASSIVE_LEVEL** |
| WFP classify 回调运行在 **DISPATCH_LEVEL** | 该路径**禁止浮点**，模型必须纯整数 |
| 内核栈仅 ~12 KB | 模型与特征缓冲**不得置于栈上**，须用 `ExAllocatePool2(POOL_FLAG_NON_PAGED)` |
| 代码/数据段可被换出 | DISPATCH_LEVEL 访问的权重必须置于**非分页段** |
| 整数除法昂贵 | 热路径用移位，避免 `div` |

**因此唯一可行的形态**是：**离线量化、仅整数、小规模**的模型（int8 权重 × int8 特征 → int32 累加），权重以 `const` 非分页数据嵌入 `.sys`。这正是实际杀软与反作弊产品在内核中所采用的做法。

**已落地的增量**：与内核无关的**整数推理核心**（int8 GEMV + 激活 + 定点输出）已实现于 `driver/include/everbloom_kernel_matrix.h`，并由独立用户态测试目标 `everbloom_kernel_matrix_tests` 验证（106 项断言，0 失败）。核心只依赖 `<stdint.h>`，因此同一份头文件既编入 `.sys`，也能在用户态被真实验证。

---

## 四、落地路径

按「先收敛缺陷、再分离边界、最后下沉模型」排序：

1. **已完成**：修复 2.1–2.4，建立可复现的内核构建（2.5）。
2. **已完成**：把 6 个拦截面重构为**统一的注册矩阵**，见「四之一」。
3. **已完成**：实现整数推理核心（3.2）与内核侧特征契约，见「四之二」。
4. **已完成**：把模型接入进程创建回调，评分以专用事件回传用户态，见「四之二」。
5. **最后**：在 3、4 稳定后，再评估是否把 WFP 与 minifilter 拆为独立驱动（3.1）。

---

## 四之一、已落地的注册矩阵

`kernel_components.hpp` 声明 6 个拦截面枚举，`kernel_components.cpp` 用一张表描述它们：

```cpp
struct EnforcementRow {
    const char* name;                  /* ASCII，用于诊断 */
    BOOLEAN required;                  /* 失败是否中止初始化 */
    ULONG64 capability_flags;          /* 安装后对外声明的能力位 */
    NTSTATUS (*install)(PDRIVER_OBJECT);
    VOID (*remove)();
    volatile LONG installed;
};
```

命名遵循文件既有约定：`src/` 内的本地类型用 PascalCase（同 `RansomTracker`、`ExtensionFamily`），跨文件接口常量用 `EVERBLOOM_`（同 `EVERBLOOM_CAPABILITY_*`），导出函数用 `Everbloom*`（同 `EverbloomKernelComponentsInitialize`）。

行序即安装序，`EverbloomKernelComponentsShutdown` **反向**遍历同一张表，因此注册与回滚不可能失配——此前这是两份手写列表。表中 `required` 的行排在前面，可选加固行排在其后，故平台拒绝可选面时不会白白安装再回滚。

`static_assert` 钉住「一行一个拦截面」的约束：新增行而忘记改头文件会让所有 surface id 静默错位。

### 顺带修复的能力谎报

`query_capabilities` 原先**硬编码**返回全部 8 个能力位，而注册表回调与对象回调是以 `(void)` 调用的（允许失败）。因此驱动会向用户态声明「注册表防护可用」，即使该回调已被平台拒绝。

现在能力位分两类：

- **控制面能力**（无条件）：`SCAN_FILE`、`BEHAVIOR_ANALYZE`、`POLICY_UPDATE`、`PROTECTION_UPDATE`、`EVENT_READ`。设备与 IOCTL ABI 只要驱动加载就存在；`SCAN_FILE` 由 `dispatch_device_control` 提供而非 minifilter，因此保持无条件，`driver_bridge.rs` 的 `is_compatible()` 语义不变。
- **由拦截面派生**：`RAW_DISK_POLICY`（← minifilter）、`REGISTRY_POLICY`（← 注册表回调）、`NETWORK_POLICY`（← WFP）。

这样用户态拿到的能力位与实际安装状态一致，被拒绝的拦截面不会被声明为可用。

**验证状态**：矩阵逻辑已通过编译与镜像校验（x64 / Native / DriverEntry / 导入 FLTMGR + fwpkclnt，0 warning 0 error），但**尚未做运行时验证**——需要可加载驱动的测试机。表遍历与能力派生逻辑本身不依赖内核 API，可以按 `tests_kernel_policy_paths.cpp` 的用户态桩模式补一个测试。

---

## 四之二、已落地的整数推理核心与内核模型

### 整数核心（`include/everbloom_kernel_matrix.h`）

纯整数、无分配、无锁，可安全用于任意已持有自身状态的回调。每层计算：

```
acc[o] = sum_i weights[o][i] * input[i]
y[o]   = clamp(requantize(acc[o]) + bias[o], activation_min, activation_max)
```

三处非显而易见的设计，都是先出错后修正的：

1. **乘数归一化为 Q31，右移上界为 62 而非 31。** 真实 per-tensor 尺度通常接近 1e-2，Q31 归一化后需要约 37 位右移。原先 31 的上界会让乘数只剩约 24 位有效位，静默降低每层精度。
2. **定点取整为「半数远离零」，且不能用「加半个步长再算术右移」实现。** 算术右移是向下取整，会把本可精确表示的值推远一步（`-1000.0` 变成 `-1001`）。改为比较截断余数与半数阈值（gemmlowp `RoundingDivideByPOT` 的形式）：精确值保持精确，真正的半数仍远离零。
3. **末层以 int32 全精度返回**，不窄化为 int8，否则评分只有 256 级，对阈值判定过粗。

形状每次调用都校验而非信任：模型表是构建期产物，畸形表必须 fail-closed，而不是越界读权重。

### 内核侧特征契约（`include/everbloom_kernel_model.h`）

进程创建回调无法解析 PE，也没有文件 I/O 预算，因此 12 个特征**只来自回调已有的上下文**（映像路径、命令行），每项都是对有界字符串的有界计算，取值为 [0,127] 的证据强度。

这套词表**刻意不同于**引擎的 12 个 PE 特征（`coverage`、`section_entropy` 等）：那些描述文件字节，这些描述进程如何被启动。二者互补，训练在一边的模型不能用在另一边，所以导出器必须显式引用本契约。

### 引导模型（`src/kernel_model.cpp`）

该文件**不包含任何内核头文件**，因此驱动实际发布的权重表就是用户态测试所评估的那张表；只有数据的**段位置**是内核相关的（`const` 默认落在非分页段，`PAGE` 段是 opt-in，故不得把这些表移入 `PAGE`）。

当前权重是**未训练的引导值**：把驱动别处已在使用的启发式写成模型形式，让整条链路（特征 → int8 量化 → 定点缩放 → 阈值）真实可跑、可测，而不是留作未经验证的脚手架。训练好的模型由 `tools/` 下的导出器替换本表，无需改动代码。

**输出域必须非负**：核心以负数 `EVERBLOOM_MATRIX_ERR_*` 表示失败，因此只有当评分域排除负数时，调用方才分得清「失败」与「得分」。风险评分本身非负，故末层 `activation_min = 0` 是承重设计而非修饰——若为负，普通已安装程序会得负分并被误判为失败。测试对此有断言。

### 评分如何回传用户态

进程创建回调在驱动防护开启时对每次创建打分，但**只有越过模型自身建议阈值才记录事件**，以免有界事件环被普通进程创建灌满。评分走 `EVERBLOOM_EVENT_KIND_MODEL_SCORE` 这一专用种类，并放在事件的 **`Status` 字段**：

- `Status` 是 `EVERBLOOM_DRIVER_EVENT` 里唯一空闲的数值字段。按 `Kind` 赋予它逐种类的含义，用户态就能直接读到数字，而不必从 `Reason` 里解析散文。这比给结构体加字段更合适：`driver_bridge.rs` 在 Rust 侧用 `#[repr(C)]` 镜像了该结构，为一条**建议性**信号改动 ABI 布局并不划算。
- 已阻断的创建**不再重复打分**，否则一次创建会产生两条事件。
- 该路径**永不否决**。引擎的 `record_kernel_behavior_event` 刻意**不**把评分映射成行为事件——模型只读映像路径与命令行，而这些用户态关联本来就有，把评分回灌等于把本流水线自己的输入伪装成独立证据。
- 无模型链入的构建不声明 `EVERBLOOM_CAPABILITY_KERNEL_MODEL`，用户态因此不会等待永远不来的评分。

**验证状态**：核心 106 项断言全部通过；`.sys` 编译通过且导入表未变（仍为 FLTMGR + fwpkclnt，subsystem Native，入口 `DriverEntry`）；引擎 `cargo check` 无错误（仅剩 `quarantine.rs` 的既有告警）。**尚未做运行时验证**——需要可加载驱动的测试机。

---

## 五、已确认事项与待办

已确认：

1. 拆分边界：接受 `core` / `flt` / `net` 三分（**尚未实施**）。
2. 内核模型的特征来源：允许读取进程/镜像回调上下文。
3. 评分回传方式：新增 `EVERBLOOM_EVENT_KIND_MODEL_SCORE`，评分置于 `Status`（**已实施**）。
4. minifilter altitude：已从错误分组改为 **FSFilter Anti-Virus**（320000–329999），取值 `329671`；`Class` / `ClassGuid` / `LoadOrderGroup` 三者已互相一致，并补上 minifilter 必需的 `Dependencies = FltMgr`。
5. **altitude 不再是落地阻塞项。** `329671` 可直接使用：测试签名或自签名部署都能正常加载与挂载，且不与占用整数位的既有过滤器冲突。Microsoft 分配只在走 WHQL / 认证签名服务时需要，属**分发前的文书步骤，不是功能前提**。

待办：

1. 编写离线导出器（`tools/`），把训练好的模型转成 `EVERBLOOM_MATRIX_MODEL` C 表。
2. 物理拆分 `core` / `flt` / `net` 三个 `.sys`。
3. 在可加载驱动的测试机上完成运行时验证——入口已就绪（见「六」），但本机 `sc.exe` 被命令黑名单拦截、测试签名未开启且需重启，因此**尚未实际加载过**。
4. 拿到 Microsoft 分配的整数后，把 `329671` 换成 `<整数>.<小数>`（无需重新申请）。

---

## 六、运行时验证入口（已落地）

此前「尚未做运行时验证」之所以长期悬着，是因为缺一个**能问出结论**的入口：能力协商只发生在引擎启动流程内部，只能从日志里读，而驱动是否真的在跑、内核模型是否真的链进去了，没有可执行的问题形式。

现在有两级入口。

### 引擎侧探测

```powershell
everbloom_engine.exe --driver-status                                  # 人读
everbloom_engine.exe --driver-status --driver-status-report out.txt   # 机器读
```

它打开 `\\.\EverbloomSecurity`、发 `EVERBLOOM_IOCTL_CAPABILITIES_QUERY`，打印协商结果后**直接退出**，不启动 IPC 服务与任何防护线程。关键字段是 `kernel_model`——它由驱动按「是否真的链入了模型」条件声明，因此这是「内核是否在给进程创建打分」的权威答案。退出码：`0` 兼容、`3` 设备不存在、`4` 驱动在跑但协议不兼容。

**为什么需要 `--driver-status-report`**：引擎二进制是 **Windows GUI 子系统**。PowerShell 不等待这类进程、也不会填 `$LASTEXITCODE`，`println!` 更可能写进一个不存在的控制台。所以脚本化调用必须读文件，不能读退出码——这一条是实测撞出来的，不是设计偏好。

### 开发机生命周期脚本

`tools/dev_driver.ps1 -Action sign|install|uninstall|status|smoke` 把「签名 → 注册 → 启动 → 验证」串成一条可重复路径。两处实现选择同样是被环境逼出来的：

- **不调用 `sc.exe`**（本机被命令黑名单拦截），服务控制全部走 SCM API 的 P/Invoke，并显式以 `SERVICE_KERNEL_DRIVER` 建服务——`New-Service` 表达不了驱动类型。包注册仍用未被拦截的 `pnputil`，它也是创建 minifilter `Instances`/`Altitude` 注册表项的正规途径。
- **开启测试签名绝不隐式执行**：它改启动配置并要求重启，因此只在显式传入 `-EnableTestSigning` 时才做，否则报出缺失项后以退出码 4 停下。

**本机验证到什么程度**：`smoke` 与 `status` 已实跑通过——正确判定 `device: absent`、`service state: not-registered`，并返回文档化的退出码（8 / 0）；`install` 的测试签名守卫也已实跑，返回 4 并给出原因。**未经实跑的是真正的加载路径**（`sign` / `install` 的服务创建与启动），因为它需要先开启测试签名并重启，而那是对宿主机的实质改动。


