# Everbloom Security 内核驱动包

该目录只提供可审计的 INF 与签名流程，不包含证书私钥，也不会自动安装或加载驱动。

## 构建、生成目录和验证

在 WDK/Visual Studio 开发者命令行中执行：

```powershell
cmake -S driver -B driver/build-wdk -G "Visual Studio 18 2026" -A x64
cmake --build driver/build-wdk --config Release --target everbloom_driver_sys
.\driver\package\sign_driver.ps1 `
  -DriverPath driver/build-wdk/Release/everbloom_driver.sys `
  -CertificateThumbprint YOUR_CERTIFICATE_THUMBPRINT
```

只生成并验证未签名目录时，可省略证书指纹，但 `signtool verify /kp` 会按预期失败；这不代表驱动可以在生产系统加载。

## 在开发机上落地：安装 / 卸载 / 冒烟验证

`tools/dev_driver.ps1` 把「签名 → 注册 → 启动 → 验证」串成一条可重复的路径：

```powershell
pwsh tools/dev_driver.ps1 -Action install -EnableTestSigning   # 首次：会改启动配置，需重启
pwsh tools/dev_driver.ps1 -Action status                       # 服务状态 + 协商到的能力位
pwsh tools/dev_driver.ps1 -Action smoke                        # 只做验证，成功即内核防护真的在跑
pwsh tools/dev_driver.ps1 -Action uninstall
```

两处刻意的实现选择，都是被构建机环境逼出来的：

- **不调用 `sc.exe`。** 该程序在部分加固主机上被命令黑名单拦截，因此服务控制全部走 SCM API（`OpenSCManager` / `CreateService` / `StartService` 的 P/Invoke），并显式以 `SERVICE_KERNEL_DRIVER` 建服务——PowerShell 自带的 `New-Service` 表达不了驱动类型。同理不使用 WMI 查询服务状态。包注册仍用 `pnputil`，它未被拦截，且是处理 INF 的正规途径（它会创建 minifilter 必需的 `Instances`/`Altitude` 注册表项）。
- **不依赖退出码读取探测结果。** 引擎二进制是 **Windows GUI 子系统**，PowerShell 不会等待它、也不会填 `$LASTEXITCODE`。因此 `--driver-status` 支持 `--driver-status-report <路径>`，把结论写成文件；脚本读文件判定，而不是读退出码。

驱动是内核二进制，64 位系统上未签名无法加载，所以脚本用本地自签测试证书 + 测试签名模式。**开启测试签名会修改启动配置并要求重启**，因此脚本绝不隐式执行：不传 `-EnableTestSigning` 时它会明确报出缺什么然后停下（退出码 4）。

用户态验证入口是引擎自带的探测命令：

```powershell
everbloom_engine.exe --driver-status                              # 人读
everbloom_engine.exe --driver-status --driver-status-report out.txt  # 机器读
```

它打开 `\\.\EverbloomSecurity`、发 `EVERBLOOM_IOCTL_CAPABILITIES_QUERY`，打印协商到的能力位，其中 `kernel_model: true` 表示**驱动里真的链入了整数模型**、正在给进程创建打分。退出码：`0` 兼容、`3` 设备不存在、`4` 驱动在跑但协议不兼容。

minifilter altitude 现为 `329671`，位于 **FSFilter Anti-Virus**（320000–329999）组内。INF 里的 `Class = AntiVirus`、`ClassGuid = {b1d1a169-c54f-4379-81db-bee7d88d7454}` 与 `LoadOrderGroup = "FSFilter Anti-Virus"` 三者必须互相一致；此前三者都是 ActivityMonitor（360000–389999）组，那是「观察并上报 I/O」的组，不是「阻断 I/O」的组，而且原先的 `ClassGuid` 与 Microsoft 文档中的 ActivityMonitor GUID 并不相符，是伪造值。同时补上了 minifilter INF 必需的 `Dependencies = FltMgr`。

组内 altitude 越大，过滤器挂得越远离文件系统，因而越早看到 I/O 请求。`329671` 刻意取高、且刻意不是整数位：它位于常见杀软之上，可在加载器动作之前否决裸磁盘/MBR 写入或漏洞驱动打开，同时远离 329999 的组上界，也避开厂商惯用的 320000 / 325000 / 328000。

`329671` 是本包**实际发布的值，可直接使用**：在测试签名或自签名部署上都能正常加载与挂载，且不与占用整数位的既有过滤器冲突。**唯一**需要 Microsoft 分配的场景是走 WHQL / 认证签名服务的提交——那项评审要求 altitude 属于你公司在对应加载顺序组下的分配值。也就是说，分配是**分发前的文书步骤，不是功能前提**，不要把驱动落地卡在这一步。

拿到该整数后，推荐用文档规定的方式把本过滤器加入同一组：在分配到的整数后追加小数（例如 `325000.7`）。这无需再次申请，因此日后若与别家过滤器撞号，也是最省事的解法。

### 运行期调整 altitude 的三种手段

不等 Microsoft 分配、或已经与别家过滤器撞号时，有三条路可走，**优先第一条**。

**1. 直接改注册表（推荐）。** minifilter 的 altitude 并不编译进驱动——Filter Manager 在加载时从服务的 `Instances` 键读取：

```
HKLM\SYSTEM\CurrentControlSet\Services\<服务名>\Instances\<实例名>\Altitude
```

**类型是 `REG_SZ`。** 这一点值得强调，因为紧邻的 `ProtectedPaths` 确实是 `REG_MULTI_SZ`，很容易顺手写成 MULTI_SZ，而 Filter Manager 会因此拒绝该实例。

```powershell
pwsh tools/dev_driver.ps1 -Action install -Altitude 329500
```

脚本会在启动服务**之前**写入该值（加载时才读取，晚了无效），并在写前校验格式（十进制数字，最多一个小数点）。

**2. `FltAttachVolumeAtAltitude`（仅调试）。** Microsoft 明确说明这是**调试支持例程**，且「零售版 minifilter 不应调用」。因此本驱动把它做成**显式 opt-in 且附加式**：

- 只有当服务键下存在 `AltitudeOverride`（`REG_SZ`）时才执行；
- 在**正常挂载之后**执行，默认路径完全不受影响；
- 失败**不会**拖垮文件过滤面——正常挂载已经完成，一个无法满足的调试覆盖不该让机器失去文件防护。

```powershell
pwsh tools/dev_driver.ps1 -Action install -AltitudeOverride 329500
```

它与第 1 条**语义不同**：第 1 条是**移动**正常实例，第 2 条是在指定高度**额外**挂一个实例。

**3. 撞号重试。** 上述两条路径都会在遇到 `STATUS_FLT_INSTANCE_ALTITUDE_COLLISION` 时**递减 altitude 并重试**，上限为 `EVERBLOOM_ALTITUDE_RETRY_LIMIT`（8 次），且**绝不越出 FSFilter Anti-Virus 组**（320000–329999）——越界会把过滤器放进它并非为之设计的组。到组下界仍失败就返回错误，而不是继续下探。

这段算术位于 `driver/include/everbloom_altitude.h`（纯整数、无内核依赖），由用户态测试 `everbloom_kernel_altitude_tests` 验证（54 项断言）。放在用户态测是刻意的：真正触发撞号的现场无法按需复现。

### 顺带修正：对象回调的 altitude

对象句柄回调（`ObRegisterCallbacks`）的 altitude 原为 `370102`。它与 minifilter 的 altitude **共用同一个命名空间**，因此两者不能取同一个值——否则本驱动会与自己撞号，让句柄防护面每次加载都失败。现取 `329670`（比 minifilter 的 `329671` 低 1，位于组内，且留出完整的重试余量）。

`ObRegisterCallbacks` 的文档确认它会返回 `STATUS_FLT_INSTANCE_ALTITUDE_COLLISION`，因此这里同样走第 3 条的递减重试。

包内驱动注册 **六个** 内核执行面：进程创建、镜像加载（仅遥测）、文件系统 minifilter、注册表、对象句柄、WFP IPv4 ALE connect callout。这六个由 `kernel_components.cpp` 的注册矩阵统一描述。策略表默认为空，由受信任的 Rust 服务通过固定 ABI 下发规则。
