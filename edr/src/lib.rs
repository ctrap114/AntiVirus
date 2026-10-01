//! EverbloomSecurity 自研 EDR 模块（起点版）
//!
//! 参考方向：
//! - Fibratus（Windows 内核事件追踪：file/process/network/registry）
//! - Sysmon（遥测格式：Event ID、规则映射、进程创建/文件操作/网络连接）
//! - Velociraptor（DFIR 取证查询模式：VQL 风格的行为查询与关联）
//! - Wazuh（HIDS/SIEM 日志合规：规则匹配、告警分类、合规报告）
//!
//! 当前实现：
//! 1. 接收 sandbox_monitor 的遥测数据（ETW / minifilter 事件）
//! 2. 标准化为 EDR 事件格式（兼容 Fibratus / Sysmon 风格）
//! 3. 提供外部分析服务接入接口（CAPE REST API / Detonate FastAPI）
//! 4. 为后续规则引擎（YARA + 行为规则）与合规报告提供数据结构基础

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// EDR 事件类型映射（参考 Sysmon Event ID 风格 + Fibratus 分类 + MITRE ATT&CK 广度特征码）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EdrEventKind {
    // 进程生命周期
    ProcessCreate,
    ProcessTerminate,
    ProcessInjection,
    ProcessHollowing,
    ProcessDoppelganging,
    ProcessHerpaderping,
    
    // 文件系统操作
    FileCreate,
    FileModify,
    FileDelete,
    FileRename,
    FileRead,
    FileCopy,
    
    // 注册表操作
    RegistryCreate,
    RegistryModify,
    RegistryDelete,
    RegistryValueSet,
    
    // 网络活动
    NetworkConnect,
    NetworkListen,
    NetworkAccept,
    NetworkDnsQuery,
    NetworkHttpRequest,
    NetworkSslHandshake,
    
    // 内存操作
    MemoryAllocate,
    MemoryFree,
    MemoryProtect,
    MemoryRwx,
    MemoryRead,
    MemoryWrite,
    
    // 模块/DLL
    ModuleLoad,
    ModuleUnload,
    DllInjection,
    
    // 注册表/持久化
    RegistryRunKey,
    RegistryService,
    ScheduledTask,
    StartupFolder,
    WmiEventSubscription,
    
    // 凭据访问
    CredentialDump,
    TokenManipulation,
    CredentialAccess,
    
    // 权限提升
    TokenElevation,
    BypassUac,
    ServiceInstall,
    DriverLoad,
    
    // 防御规避
    ProcessHollowing,
    ProcessDoppelganging,
    ProcessHerpaderping,
    DllInjection,
    ReflectiveLoading,
    MemoryRwx,
    Timestomp,
    IndicatorRemoval,
    
    // 凭据导出/窃取
    CredentialDump,
    LsassDump,
    SamDump,
    Dcsync,
    
    // 网络/横向移动
    NetworkConnect,
    NetworkScan,
    LateralMovement,
    RemoteServiceCreation,
    PassTheHash,
    PassTheTicket,
    
    // 命令与控制
    C2Heartbeat,
    C2Download,
    C2Upload,
    DnsTunneling,
    HttpTunneling,
    
    // 数据窃取
    DataStaging,
    DataExfiltration,
    ArchiveCollection,
    ClipboardMonitoring,
    
    // 破坏/影响
    DataEncryption,
    DataDestruction,
    SystemShutdown,
    ServiceStop,
    BootRecordModification,
    
    // 沙箱/分析
    SandboxAnalysis,
    
    // 可疑 API 调用
    SuspiciousApiCall,
    
    // 未知/其他
    Unknown,
}

/// 遥测事件标准化结构（兼容 Wazuh/SIEM 日志格式）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrTelemetryEvent {
    pub timestamp: u64,
    pub source: String,
    pub event_kind: EdrEventKind,
    pub target_pid: u32,
    pub target_path: Option<String>,
    pub process_path: Option<String>,
    pub details: String,
    pub severity: String, // "low" | "medium" | "high" | "critical"
    /// MITRE ATT&CK 关联标签（可选，参考 Velociraptor 关联模式）
    pub attack_chain_tags: Vec<String>,
}

impl EdrTelemetryEvent {
    pub fn new(
        event_kind: EdrEventKind,
        target_pid: u32,
        target_path: Option<String>,
    ) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            source: "everbloom_sandbox".to_string(),
            event_kind,
            target_pid,
            target_path,
            process_path: None,
            details: String::new(),
            severity: "medium".to_string(),
            attack_chain_tags: vec![],
        }
    }

    /// 根据事件严重性自动分类（参考 Wazuh 规则匹配 + MITRE ATT&CK 严重度映射）
    pub fn classify_severity(&mut self) {
        match self.event_kind {
            // Critical: 直接导致系统失陷/数据窃取
            EdrEventKind::SandboxAnalysis
            | EdrEventKind::CredentialDump
            | EdrEventKind::LsassDump
            | EdrEventKind::Dcsync
            | EdrEventKind::DataExfiltration
            | EdrEventKind::DataEncryption
            | EdrEventKind::DataDestruction
            | EdrEventKind::SystemShutdown => {
                self.severity = "critical".to_string();
            }
            // High: 高风险行为，易导致失陷
            EdrEventKind::MemoryRwx
            | EdrEventKind::SuspiciousApiCall
            | EdrEventKind::ProcessInjection
            | EdrEventKind::ProcessHollowing
            | EdrEventKind::ProcessDoppelganging
            | EdrEventKind::ProcessHerpaderping
            | EdrEventKind::ProcessInjection
            | EdrEventKind::DllInjection
            | EdrEventKind::ReflectiveLoading
            | EdrEventKind::MemoryRwx
            | EdrEventKind::TokenElevation
            | EdrEventKind::BypassUac
            | EdrEventKind::CredentialDump
            | EdrEventKind::LsassDump
            | EdrEventKind::Dcsync
            | EdrEventKind::TokenManipulation
            | EdrEventKind::CredentialAccess
            | EdrEventKind::TokenElevation
            | EdrEventKind::BypassUac
            | EdrEventKind::ServiceInstall
            | EdrEventKind::DriverLoad
            | EdrEventKind::LateralMovement
            | EdrEventKind::RemoteServiceCreation
            | EdrEventKind::PassTheHash
            | EdrEventKind::PassTheTicket
            | EdrEventKind::DataExfiltration
            | EdrEventKind::DataEncryption
            | EdrEventKind::DataEncryption
            | EdrEventKind::DataDestruction => {
                self.severity = "high".to_string();
            }
            // Medium: 可疑但需上下文判断
            EdrEventKind::ModuleLoad
            | EdrEventKind::DllInjection
            | EdrEventKind::ReflectiveLoading
            | EdrEventKind::ProcessInjection
            | EdrEventKind::ProcessHollowing
            | EdrEventKind::ProcessDoppelganging
            | EdrEventKind::ProcessHerpaderping
            | EdrEventKind::ProcessInjection
            | EdrEventKind::SuspiciousApiCall
            | EdrEventKind::ProcessCreate
            | EdrEventKind::ProcessTerminate
            | EdrEventKind::ProcessInjection
            | EdrEventKind::ProcessHollowing
            | EdrEventKind::ProcessDoppelganging
            | EdrEventKind::ProcessHerpaderping
            | EdrEventKind::FileCreate
            | EdrEventKind::FileModify
            | EdrEventKind::FileDelete
            | EdrEventKind::FileRename
            | EdrEventKind::FileCopy
            | EdrEventKind::RegistryWrite
            | EdrEventKind::RegistryCreate
            | EdrEventKind::RegistryModify
            | EdrEventKind::RegistryDelete
            | EdrEventKind::RegistryValueSet
            | EdrEventKind::RegistryRunKey
            | EdrEventKind::RegistryService
            | EdrEventKind::ScheduledTask
            | EdrEventKind::StartupFolder
            | EdrEventKind::WmiEventSubscription
            | EdrEventKind::NetworkConnect
            | EdrEventKind::NetworkListen
            | EdrEventKind::NetworkAccept
            | EdrEventKind::NetworkDnsQuery
            | EdrEventKind::NetworkHttpRequest
            | EdrEventKind::NetworkSslHandshake
            | EdrEventKind::NetworkScan
            | EdrEventKind::LateralMovement
            | EdrEventKind::RemoteServiceCreation
            | EdrEventKind::PassTheHash
            | EdrEventKind::PassTheTicket
            | EdrEventKind::C2Heartbeat
            | EdrEventKind::C2Download
            | EdrEventKind::C2Upload
            | EdrEventKind::DnsTunneling
            | EdrEventKind::HttpTunneling
            | EdrEventKind::DataStaging
            | EdrEventKind::DataExfiltration
            | EdrEventKind::ArchiveCollection
            | EdrEventKind::ClipboardMonitoring
            | EdrEventKind::DataStaging
            | EdrEventKind::DataExfiltration
            | EdrEventKind::ArchiveCollection
            | EdrEventKind::ClipboardMonitoring
            | EdrEventKind::ModuleLoad
            | EdrEventKind::ModuleUnload
            | EdrEventKind::DllInjection
            | EdrEventKind::ReflectiveLoading
            | EdrEventKind::MemoryAllocate
            | EdrEventKind::MemoryFree
            | EdrEventKind::MemoryProtect
            | EdrEventKind::MemoryRead
            | EdrEventKind::MemoryWrite
            | EdrEventKind::TokenElevation
            | EdrEventKind::BypassUac
            | EdrEventKind::ServiceInstall
            | EdrEventKind::DriverLoad
            | EdrEventKind::TokenManipulation
            | EdrEventKind::CredentialAccess
            | EdrEventKind::TokenElevation
            | EdrEventKind::BypassUac
            | EdrEventKind::ServiceInstall
            | EdrEventKind::DriverLoad
            | EdrEventKind::ProcessInjection
            | EdrEventKind::ProcessHollowing
            | EdrEventKind::ProcessDoppelganging
            | EdrEventKind::ProcessHerpaderping
            | EdrEventKind::ReflectiveLoading
            | EdrEventKind::MemoryRwx
            | EdrEventKind::Timestomp
            | EdrEventKind::IndicatorRemoval
            | EdrEventKind::CredentialDump
            | EdrEventKind::LsassDump
            | EdrEventKind::SamDump
            | EdrEventKind::Dcsync
            | EdrEventKind::DataStaging
            | EdrEventKind::DataExfiltration
            | EdrEventKind::ArchiveCollection
            | EdrEventKind::ClipboardMonitoring
            | EdrEventKind::DataEncryption
            | EdrEventKind::DataDestruction
            | EdrEventKind::SystemShutdown
            | EdrEventKind::ServiceStop
            | EdrEventKind::BootRecordModification
            | EdrEventKind::SandboxAnalysis
            | EdrEventKind::SuspiciousApiCall
            | EdrEventKind::C2Heartbeat
            | EdrEventKind::C2Download
            | EdrEventKind::C2Upload
            | EdrEventKind::DnsTunneling
            | EdrEventKind::HttpTunneling
            | EdrEventKind::DataStaging
            | EdrEventKind::DataExfiltration
            | EdrEventKind::ArchiveCollection
            | EdrEventKind::ClipboardMonitoring
            | EdrEventKind::DataEncryption
            | EdrEventKind::DataDestruction
            | EdrEventKind::SystemShutdown
            | EdrEventKind::ServiceStop
            | EdrEventKind::BootRecordModification
            | EdrEventKind::SandboxAnalysis
            | EdrEventKind::SuspiciousApiCall
            | EdrEventKind::C2Heartbeat
            | EdrEventKind::C2Download
            | EdrEventKind::C2Upload
            | EdrEventKind::DnsTunneling
            | EdrEventKind::HttpTunneling
            | EdrEventKind::DataStaging
            | EdrEventKind::DataExfiltration
            | EdrEventKind::ArchiveCollection
            | EdrEventKind::ClipboardMonitoring
            | EdrEventKind::DataEncryption
            | EdrEventKind::DataDestruction
            | EdrEventKind::SystemShutdown
            | EdrEventKind::ServiceStop
            | EdrEventKind::BootRecordModification => {
                self.severity = "medium".to_string();
            }
            // Low: 常规操作
            _ => {
                self.severity = "low".to_string();
            }
        }
    }
}

/// 外部分析服务接入接口（CAPE / Detonate 风格）
pub fn submit_to_external_service(
    endpoint: &str,
    event: &EdrTelemetryEvent,
) -> Option<String> {
    // 实际实现：使用 reqwest blocking 客户端发送 POST 请求
    // 当前为集成标记点，已在 sandbox_monitor/src/lib.rs 实现实际 HTTP POST
    Some(format!("submitted_to_{}_pid_{}", endpoint, event.target_pid))
}

/// 规则引擎接口（为后续 YARA + 行为规则集成预留）
pub fn match_behavior_rule(event: &EdrTelemetryEvent) -> Vec<String> {
    // 参考现有规则引擎：YARA 规则匹配结果可在此与行为事件关联
    // 当前返回空标签列表，集成时可填入实际匹配标签
    vec![]
}

/// 将驱动层遥测（核心防护、文件防护、自我保护、网络防火墙、实时扫描、AMSI、注册表监控）标准化为 EDR 格式
/// 参考文件：driver/src/core_protection.cpp、self_protection.cpp、file_protection.cpp、network_firewall.cpp、realtime_scan.cpp、amsi.cpp
pub fn normalize_driver_event(
    source: &str,
    pid: u32,
    event_detail: &str,
    severity_hint: Option<&str>,
) -> EdrTelemetryEvent {
    let kind = match source {
        s if s.contains("self_protection") => EdrEventKind::ProcessCreate,
        s if s.contains("core_protection") => EdrEventKind::ModuleLoad,
        s if s.contains("file_protection") => EdrEventKind::FileModify,
        s if s.contains("network_firewall") => EdrEventKind::NetworkConnect,
        s if s.contains("realtime_scan") => EdrEventKind::SuspiciousApiCall,
        s if s.contains("amsi") => EdrEventKind::SuspiciousApiCall,
        s if s.contains("registry_monitor") => EdrEventKind::RegistryWrite,
        s if s.contains("process_monitor") => EdrEventKind::ProcessCreate,
        s if s.contains("network_monitor") => EdrEventKind::NetworkConnect,
        s if s.contains("file_monitor") => EdrEventKind::FileCreate,
        _ => EdrEventKind::Unknown,
    };
    let mut event = EdrTelemetryEvent::new(kind, pid, Some(event_detail.to_string()));
    event.process_path = Some(format!("driver:{}", source));
    event.details = event_detail.to_string();
    event.severity = severity_hint.unwrap_or("medium").to_string();
    // 自动分类严重性
    event.classify_severity();
    // 基于详情内容自动标记 MITRE ATT&CK 标签
    event.enrich_attack_tags();
    event
}

// 驱动模块与 EDR 模块的集成桥接：将核心防护引擎事件映射到遥测格式
// 集成点：engine/src/features/mod.rs（沙箱功能定义）与 driver/src/core_protection.cpp
