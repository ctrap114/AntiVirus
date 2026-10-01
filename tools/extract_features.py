"""EMBER-2025 风格特征提取器（参考 endgameinc/ember 2381 维标准集 + 2025 增强）

核心策略：提取时高维全面（~2671 维），存储时极致压缩（CSR 稀疏 + 特征哈希降维），
坚决不存原始样本（只存特征向量 + 标签 + 元数据）。

特征维度（接近 EMBER 2381 + 2025 增强）：
  - byte_histogram: 256 维（文件前 1024 字节字节直方图）
  - pe_header: 62 维（PE 头关键字段）
  - section_info: 255 维（节区名 hash + 节区大小/熵值/属性）
  - imports: 1280 维（IAT 导入函数名 hash）
  - exports: 128 维（EAT 导出函数名 hash）
  - data_directories: 100 维（数据目录条目）
  - general_file_info: 10 维（文件大小、debug、resource 等）
  - string_features: 200 维（2025 增强：URL/IP/注册表/PowerShell/API 名等敏感关键字）
  - resource_metadata: 90 维（资源段大小、语言代码页、图标 hash）
  总计：~2381 维（对齐 EMBER）+ 290 维 2025 增强 = 2671 维

依赖：pefile（PE 解析）、scipy（稀疏存储）、numpy（数值计算）
"""
from __future__ import annotations

import hashlib
import json
import math
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pefile

# EMBER 风格特征维度常量（与 Rust 端 engine/src/features/mod.rs 保持一致）
PE_STRUCTURE_DIM = 62
SECTION_INFO_DIM = 255
PE_IAT_API_DIM = 1280
PE_EAT_API_DIM = 128
DATA_DIRECTORIES_DIM = 100
GENERAL_FILE_INFO_DIM = 10
STRING_FEATURES_DIM = 200
RESOURCE_METADATA_DIM = 90
BYTE_HISTOGRAM_DIM = 256
EMBER_2025_TOTAL = (
    BYTE_HISTOGRAM_DIM
    + PE_STRUCTURE_DIM
    + SECTION_INFO_DIM
    + PE_IAT_API_DIM
    + PE_EAT_API_DIM
    + DATA_DIRECTORIES_DIM
    + GENERAL_FILE_INFO_DIM
    + STRING_FEATURES_DIM
    + RESOURCE_METADATA_DIM
)

# 2025 增强：可疑字符串关键字（URL/IP/注册表路径/cmd/PowerShell/API）
SUSPICIOUS_KEYWORDS = [
    # URLs 和网络
    'http://', 'https://', 'ftp://', 'tcp://', 'ws://', 'wss://', '.onion', '.bit', '.xyz',
    # IP 地址模式
    '192.168.', '10.0.0.', '172.16.', '127.0.0.1',
    # 注册表路径
    'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'CurrentControlSet\\Services',
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion',
    'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion',
    'AppInit_DLLs', 'LSA', 'Winlogon', 'Notify', 'Image File Execution Options',
    'IFEO', 'Session Manager', 'SubSystems',
    # Shell 和命令
    'cmd.exe', 'cmd /c', 'powershell', 'powershell.exe', 'pwsh', 'wscript', 'cscript',
    'mshta', 'rundll32', 'regsvr32', 'taskkill', 'tasklist', 'net.exe', 'net1',
    'sc.exe', 'schtasks', 'at.exe', 'wmic', 'bitsadmin', 'certutil',
    # 进程注入和反分析
    'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
    'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC',
    'SetWindowsHookEx', 'NtUnmapViewOfSection', 'NtMapViewOfSection',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'OutputDebugString', 'INT 2D', 'INT 3', 'CC', 'PREFIX!',
    # 加密 / 勒索
    'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'BCryptEncrypt',
    'AES', 'RSA', 'vssadmin', 'wbadmin', 'bcdedit', 'recoveryenabled',
    '.onion', '.lock', '.crypt', '.encrypted', '.locked', 'YOUR_FILES',
    # 反弹 Shell / C2
    'reverse_shell', 'bind_shell', 'nc.exe', 'netcat', 'mimikatz',
    'psexec', 'wmiprvse', 'winrs', 'psexesvc',
    # 持久化
    'schtasks /create', 'sc create', 'reg add', 'New-Service',
    'schtasks.exe', 'taskeng.exe', 'taskhostw.exe',
    # 凭证访问
    'mimilib', 'sekurlsa', 'wdigest', 'lsasrv', 'msv1_0', 'kerberos',
    'wdigest.dll', 'lsasrv.dll', 'lsass.exe',
    # 网络发现
    'GetAdaptersInfo', 'GetNetAdapter', 'GetIpNetTable', 'IcmpSendEcho',
    # 防御绕过
    'AMSI', 'AmsiScan', 'AmsiOpenSession', 'EtwEventWrite',
    'NtTraceEvent', 'EventWrite', 'EtwNotificationRegister',
    'VirtualProtect', 'NtUnmapViewOfSection',
    # 进程行为
    'CreateProcess', 'CreateProcessAsUser', 'ShellExecuteEx',
    'WinExec', 'LoadLibrary', 'GetProcAddress', 'GetModuleHandle',
    # 网络通信
    'InternetOpen', 'InternetConnect', 'HttpSendRequest', 'HttpOpenRequest',
    'WSAStartup', 'socket', 'connect', 'send', 'recv', 'bind', 'listen',
    'URLDownloadToFile', 'WinHttpOpen', 'WinHttpConnect',
    'InternetReadFile', 'InternetWriteFile',
    # 浏览器劫持
    'BHO', 'Browser Helper', 'IExtension', 'IObjectWithSite',
    # UAC 绕过
    'autoElevate', 'consent.exe', 'fodhelper', 'eventvwr',
    'computerdefaults', 'sdclt', 'slmgr', 'sysprep',
    # 勒索特征
    'vssadmin delete shadows', 'wbadmin delete', 'bcdedit /set',
    'cipher /w:', 'wevtutil cl', 'fsutil usn',
    # 凭据转储
    'mimikatz', 'wce', 'gsecdump', 'pwdump', 'fgdump',
    # 木马
    'netcat', 'ncat', 'socat', 'telnet', 'rlogin',
    # 持久化后门
    'schtasks', 'at.exe', 'crontab', 'systemd',
    # 信息窃取
    'keylog', 'screenshot', 'GetAsyncKeyState', 'GetKeyState',
    'GetClipboardData', 'BitBlt', 'GetDC', 'CreateCompatibleDC',
    # 加密货币
    'stratum', 'mining.subscribe', 'xmrig', 'cpuminer', 'cryptonight',
    'stratum+tcp', 'mining_pool', 'monero', 'bitcoin', 'ethereum',
    # LOLBins (Living Off The Land Binaries)
    'certutil.exe', 'bitsadmin', 'msiexec', 'wmic', 'regsvr32',
    'msbuild', 'installutil', 'mshta', 'cmstp',
    # 可疑字符串
    'eval', 'exec', 'shell', 'base64', 'AES', 'RC4', 'XOR',
    'CreateFile', 'WriteFile', 'DeleteFile', 'RegSetValue',
    # API 名称（常见的恶意行为）
    'NtUnmapViewOfSection', 'NtCreateSection', 'NtMapViewOfSection',
    'RtlAdjustPrivilege', 'LookupPrivilegeValue', 'AdjustTokenPrivileges',
    'OpenSCManager', 'CreateService', 'StartService', 'OpenService',
    'RegOpenKey', 'RegSetValueEx', 'RegCreateKey', 'RegCloseKey',
    'CreateFileW', 'WriteFileW', 'ReadFileW', 'DeleteFileW',
    'CreateProcessW', 'CreateProcessAsUserW', 'CreateToolhelp32Snapshot',
    'InternetOpenW', 'InternetConnectW', 'HttpOpenRequestW', 'HttpSendRequestW',
    'URLDownloadToFileW', 'URLDownloadToCacheFileW',
    'ShellExecuteExW', 'ShellExecuteW', 'WinExec',
    'Sleep', 'WaitForSingleObject', 'CreateThread', 'CreateRemoteThread',
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualFree', 'VirtualProtect',
    'VirtualProtectEx', 'WriteProcessMemory', 'ReadProcessMemory',
    'OpenProcess', 'TerminateProcess', 'IsDebuggerPresent',
    'OpenSCManagerW', 'CreateServiceW', 'StartServiceW',
    'RegOpenKeyExW', 'RegSetValueExW', 'RegCreateKeyExW',
    'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
    'SetWindowsHookExW', 'UnhookWindowsHookEx', 'CallNextHookEx',
    'InternetOpenUrlA', 'InternetOpenUrlW', 'HttpAddRequestHeadersW',
    'CryptAcquireContextW', 'CryptReleaseContext', 'CryptGenRandom',
    'CryptEncrypt', 'CryptDecrypt', 'CryptHashData',
    'LookupPrivilegeValueW', 'AdjustTokenPrivileges', 'OpenProcessToken',
    'GetTokenInformation', 'SetTokenInformation', 'DuplicateTokenEx',
    'ImpersonateLoggedOnUser', 'RevertToSelf', 'LogonUserW', 'LogonUserA',
    # 编码 / 字符串
    '%s', '%d', '%x', '%u', 'MZ', 'PE', 'This program', 'cannot run',
    'GetSystemDirectory', 'GetWindowsDirectory', 'GetTempPath',
    'GetEnvironmentVariable', 'GetCommandLine', 'WinMain',
    'DllMain', 'DllEntryPoint', 'ServiceMain', 'wmain', 'wWinMain',
]

# 危险 API 列表（用于 IAT/EAT 特征）
DANGEROUS_APIS = [
    'CreateRemoteThread', 'NtCreateThreadEx', 'RtlCreateUserThread',
    'VirtualAllocEx', 'WriteProcessMemory', 'ReadProcessMemory',
    'OpenProcess', 'VirtualProtect', 'VirtualProtectEx', 'CreateProcess',
    'ShellExecute', 'WinExec', 'CreateProcessAsUser', 'InternetOpen',
    'InternetConnect', 'HttpSendRequest', 'URLDownloadToFile',
    'InternetOpenUrl', 'CreateService', 'OpenSCManager', 'RegSetValueEx',
    'RegCreateKeyEx', 'SetWindowsHookEx', 'IsDebuggerPresent',
    'CheckRemoteDebuggerPresent', 'CryptEncrypt', 'CryptDecrypt',
    'GetAsyncKeyState', 'SetThreadContext', 'NtUnmapViewOfSection',
    'AdjustTokenPrivileges', 'LookupPrivilegeValue', 'LogonUser',
    'ImpersonateLoggedOnUser', 'DuplicateTokenEx', 'CreateProcessWithTokenW',
    'NtCreateSection', 'NtMapViewOfSection', 'RtlAdjustPrivilege',
    'MiniDumpWriteDump', 'MiniDumpReadDumpStream', 'WSAStartup',
    'connect', 'send', 'WSASocket', 'GetProcAddress', 'LoadLibrary',
    'GetModuleHandle', 'GetSystemTime', 'GetTickCount',
    'QueueUserAPC', 'NtQueueApcThread', 'Sleep', 'WaitForSingleObject',
    'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
    'Thread32First', 'Thread32Next', 'OpenProcessToken', 'GetTokenInformation',
    'DuplicateToken', 'DuplicateTokenEx', 'SetThreadContext', 'GetThreadContext',
    'NtQueryInformationProcess', 'NtSetInformationProcess',
    'LdrLoadDll', 'LdrGetDllHandle', 'LdrGetProcedureAddress',
    'NtCreateFile', 'NtWriteFile', 'NtReadFile', 'NtDeleteFile',
    'RegOpenKeyEx', 'RegQueryValueEx', 'RegCloseKey', 'RegDeleteValue',
    'CreateMutex', 'CreateEvent', 'CreateSemaphore', 'OpenMutex',
    'OpenEvent', 'OpenSemaphore', 'ReleaseMutex', 'SetEvent', 'ResetEvent',
    'CryptAcquireContext', 'CryptReleaseContext', 'CryptGenRandom',
    'CryptDeriveKey', 'CryptDestroyKey', 'CryptSetKeyParam',
    'CryptGetKeyParam', 'CryptExportKey', 'CryptImportKey',
    'CryptGenKey', 'CryptDestroyKey', 'CryptSetKeyParam',
    'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest',
    'WinHttpSendRequest', 'WinHttpReceiveResponse', 'WinHttpQueryDataAvailable',
    'WinHttpReadData', 'WinHttpCloseHandle',
    'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
    'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW',
    'HttpAddRequestHeadersA', 'HttpAddRequestHeadersW',
    'InternetReadFile', 'InternetWriteFile', 'InternetCloseHandle',
    'InternetQueryDataAvailable', 'InternetQueryOption',
    'InternetSetOption', 'InternetCrackUrl', 'InternetCreateUrl',
    'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
    'ShellExecuteEx', 'CreateProcessA', 'CreateProcessW',
    'CreateProcessAsUserA', 'CreateProcessAsUserW',
    'CreateProcessWithLogonW', 'CreateProcessInternalA', 'CreateProcessInternalW',
    'WriteProcessMemory', 'ReadProcessMemory', 'NtUnmapViewOfSection',
    'NtCreateSection', 'NtMapViewOfSection', 'NtUnmapViewOfSection',
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualFree', 'VirtualFreeEx',
    'VirtualProtect', 'VirtualProtectEx', 'VirtualQuery', 'VirtualQueryEx',
    'HeapAlloc', 'HeapReAlloc', 'HeapFree', 'HeapCreate', 'HeapDestroy',
    'GetProcessHeap', 'RtlAllocateHeap', 'RtlFreeHeap',
    'IsBadReadPtr', 'IsBadWritePtr', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'NtQuerySystemInformation',
    'OpenThread', 'OpenProcess', 'TerminateProcess', 'TerminateThread',
    'SuspendThread', 'ResumeThread', 'GetThreadContext', 'SetThreadContext',
    'CreateRemoteThread', 'CreateRemoteThreadEx', 'CreateThread',
    'ExitThread', 'TerminateThread', 'GetCurrentThread',
    'GetCurrentProcess', 'GetCurrentProcessId', 'GetCurrentThreadId',
    'NtTerminateProcess', 'NtTerminateThread', 'NtSuspendThread', 'NtResumeThread',
    'QueueUserAPC', 'NtQueueApcThread', 'NtSetContextThread',
]

# 节区名列表（用于 section_info 特征）
SECTION_NAMES = [
    '.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.rsrc', '.reloc',
    '.tls', '.bss', '.idata', '.didat', '.edata', '.rdata', '.data',
    '.textbss', '.CRT', '.bss', '.idata', '.tls', '.reloc', '.debug',
    '.upx0', '.upx1', '.upx2', '.aspack', '.nsp0', '.nsp1', '.nsp2',
    '.themida', '.vmp0', '.vmp1', '.vmp2', '.mpress1', '.mpress2',
    '.petite', '.kkrunchy', '.fsg', '.pebundle', '.peprotect',
    '.winupack', '.yoda', '.pe-armor', '.pelock', '.viro',
    '.pklite', '.wwpack32', '.exestealth', '.ht-pack', '.hx',
    'CODE', 'DATA', 'BSS', '.code', '.data', '.bss',
    '.init', '.fini', '.plt', '.got', '.dynamic', '.dynstr',
    '.gnu.hash', '.dynsym', '.rel.dyn', '.rel.plt', '.note', '.comment',
    '.interp', '.dynstr', '.gnu.version', '.gnu.version_d', '.gnu.version_r',
    '.eh_frame', '.eh_frame_hdr', '.gcc_except_table', '.init_array', '.fini_array',
]

# 常见导出函数名（用于 EAT 特征）
EXPORT_FUNCTIONS = [
    'DllMain', 'DllGetClassObject', 'DllCanUnloadNow', 'DllRegisterServer',
    'ServiceMain', 'SvchostPushServiceGlobals', 'OpenSCManagerW', 'CreateServiceW',
    'StartServiceCtrlDispatcher', 'RegisterServiceCtrlHandler', 'SetServiceStatus',
    'OpenServiceW', 'StartServiceW', 'ControlService', 'DeleteService',
    'QueryServiceStatus', 'QueryServiceStatusEx', 'EnumServicesStatus',
    'EnumServicesStatusEx', 'OpenSCManager', 'CreateService', 'OpenService',
    'StartService', 'ControlServiceEx', 'DeleteService', 'RegisterServiceCtrlHandlerEx',
    'GetServiceDisplayNameW', 'GetServiceKeyNameW', 'EnumDependentServicesW',
    'NotifyServiceStatusChangeW', 'SetServiceBits', 'ChangeServiceConfigW',
    'ChangeServiceConfig2W', 'QueryServiceConfig2W', 'QueryServiceConfigW',
    'GetServiceDirectoryW', 'GetServiceDisplayName', 'GetServiceKeyName',
    'EnumDependentServices', 'NotifyServiceStatusChange', 'SetServiceStatus',
    'OpenThreadToken', 'OpenProcessToken', 'GetTokenInformation',
    'SetTokenInformation', 'AdjustTokenPrivileges', 'LookupPrivilegeValue',
    'LookupPrivilegeNameW', 'LookupPrivilegeDisplayNameW', 'AdjustTokenGroups',
    'CheckTokenMembership', 'CheckTokenCapability', 'GetTokenIntegrityLevel',
    'GetCurrentProcessToken', 'OpenThreadTokenEx', 'OpenAsynchronousThreadToken',
    'SetThreadToken', 'PrivilegeCheck', 'ImpersonateLoggedOnUser', 'RevertToSelf',
    'LogonUser', 'LogonUserEx', 'GetUserName', 'GetUserNameW', 'GetUserNameA',
    'GetCurrentThread', 'GetCurrentProcess', 'GetCurrentProcessId',
    'GetCurrentThreadId', 'GetProcessId', 'GetThreadId', 'GetProcessHandle',
    'GetThreadHandle', 'OpenProcess', 'OpenThread', 'TerminateProcess',
    'TerminateThread', 'SuspendThread', 'ResumeThread', 'GetExitCodeProcess',
    'GetExitCodeThread', 'WaitForSingleObject', 'WaitForMultipleObjects',
    'Sleep', 'SleepEx', 'CreateThread', 'CreateRemoteThread',
    'CreateRemoteThreadEx', 'NtCreateThreadEx', 'RtlCreateUserThread',
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualFree', 'VirtualProtect',
    'WriteProcessMemory', 'ReadProcessMemory', 'OpenProcessToken', 'GetTokenInformation',
    'ImpersonateLoggedOnUser', 'RevertToSelf', 'AdjustTokenPrivileges',
    'LookupPrivilegeValue', 'LogonUserW', 'LogonUserExW', 'LsaLogonUser',
    'LsaConnectUntrusted', 'LsaLookupAuthenticationPackage', 'LsaCallAuthenticationPackage',
    'LsaRetrievePrivateData', 'LsaStorePrivateData', 'LsaOpenPolicy', 'LsaOpenPolicyEx',
    'LsaOpenSecret', 'LsaQuerySecret', 'LsaQueryDomainInformationPolicy',
    'LsaQueryForestTrustInformation', 'LsaQueryTrustedDomainInfo', 'LsaQueryTrustedDomainInfoByName',
    'LsaSetSecret', 'LsaSetDomainInformationPolicy', 'LsaSetForestTrustInformation',
    'LsaSetInformationPolicy', 'LsaClearInformationPolicy', 'LsaDeleteObject',
    'LsaDelete', 'LsaClose', 'LsaFreeMemory', 'LsaOpenPolicySce',
    'LsaQueryPolicyRelativeName', 'LsaQueryInformationPolicy', 'LsaQueryDomainInformationPolicy',
    'LsaQueryForestTrustInformation', 'LsaQueryTrustedDomainInfo', 'LsaQueryTrustedDomainInfoByName',
    'LsaSetSecret', 'LsaSetDomainInformationPolicy', 'LsaSetForestTrustInformation',
    'LsaSetInformationPolicy', 'LsaClearInformationPolicy', 'LsaDeleteObject',
]

# PE 头特征（用于 pe_header 特征）
PE_HEADER_FIELDS = [
    'Machine', 'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable',
    'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics',
    'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
    'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint',
    'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment',
    'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
    'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
    'MinorSubsystemVersion', 'Win32VersionValue', 'SizeOfImage', 'SizeOfHeaders',
    'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve',
    'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags',
    'NumberOfRvaAndSizes', 'ExportTableRVA', 'ExportTableSize',
    'ImportTableRVA', 'ImportTableSize', 'ResourceTableRVA', 'ResourceTableSize',
    'ExceptionTableRVA', 'ExceptionTableSize', 'CertificateTableRVA',
    'CertificateTableSize', 'BaseRelocationTableRVA', 'BaseRelocationTableSize',
    'DebugRVA', 'DebugSize', 'ArchitectureRVA', 'ArchitectureSize',
    'GlobalPtrRVA', 'GlobalPtrSize', 'TLSTableRVA', 'TLSTableSize',
    'LoadConfigTableRVA', 'LoadConfigTableSize', 'BoundImportRVA',
    'BoundImportSize', 'IATRVA', 'IATSize', 'DelayImportDescriptorRVA',
    'DelayImportDescriptorSize', 'CLRRuntimeHeaderRVA', 'CLRRuntimeHeaderSize',
    'ReservedRVA', 'ReservedSize',
]

# 数据目录名
DATA_DIRECTORY_NAMES = [
    'EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'SECURITY', 'BASERELOC',
    'DEBUG', 'ARCHITECTURE', 'GLOBALPTR', 'TLS', 'LOAD_CONFIG',
    'BOUND_IMPORT', 'IAT', 'DELAY_IMPORT_DESCRIPTOR', 'CLR_RUNTIME_HEADER',
    'RESERVED',
]


def safe_hash32(s: str) -> int:
    """使用 SHA-256 取前 4 字节作为 32 位特征索引（EMBER 风格）"""
    h = hashlib.sha256(s.encode('utf-8', errors='replace')).digest()
    return int.from_bytes(h[:4], 'big')


def safe_hash16(s: str) -> int:
    """使用 SHA-256 取前 2 字节作为 16 位特征索引"""
    h = hashlib.sha256(s.encode('utf-8', errors='replace')).digest()
    return int.from_bytes(h[:2], 'big')


def extract_byte_histogram(pe_bytes: bytes) -> np.ndarray:
    """特征组 1: 字节直方图 (256 维) - 文件前 1024 字节字节直方图"""
    hist = np.zeros(BYTE_HISTOGRAM_DIM, dtype=np.float32)
    data = pe_bytes[:1024]
    for byte in data:
        hist[byte] += 1.0
    if len(data) > 0:
        hist /= len(data)
    return hist


def extract_pe_header(pe: pefile.PE) -> np.ndarray:
    """特征组 2: PE 头 (62 维) - PE 头关键字段数值化"""
    features = np.zeros(PE_STRUCTURE_DIM, dtype=np.float32)
    if not pe.FILE_HEADER:
        return features
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    try:
        features[0] = float(fh.Machine)
        features[1] = float(fh.NumberOfSections)
        features[2] = float(fh.TimeDateStamp & 0xFFFFFFFF)
        features[3] = float(fh.SizeOfOptionalHeader)
        features[4] = float(fh.Characteristics & 0xFFFF)
        if oh:
            features[5] = float(oh.Magic)
            features[6] = float(oh.MajorLinkerVersion)
            features[7] = float(oh.MinorLinkerVersion)
            features[8] = float(oh.SizeOfCode)
            features[9] = float(oh.SizeOfInitializedData)
            features[10] = float(oh.SizeOfUninitializedData)
            features[11] = float(oh.AddressOfEntryPoint)
            features[12] = float(oh.BaseOfCode)
            features[13] = float(oh.ImageBase & 0xFFFFFFFF)
            features[14] = float(oh.SectionAlignment)
            features[15] = float(oh.FileAlignment)
            features[16] = float(oh.MajorOperatingSystemVersion)
            features[17] = float(oh.MinorOperatingSystemVersion)
            features[18] = float(oh.MajorImageVersion)
            features[19] = float(oh.MinorImageVersion)
            features[20] = float(oh.MajorSubsystemVersion)
            features[21] = float(oh.MinorSubsystemVersion)
            features[22] = float(oh.SizeOfImage)
            features[23] = float(oh.SizeOfHeaders)
            features[24] = float(oh.CheckSum)
            features[25] = float(oh.Subsystem)
            features[26] = float(oh.DllCharacteristics)
            features[27] = float(oh.SizeOfStackReserve)
            features[28] = float(oh.SizeOfStackCommit)
            features[29] = float(oh.SizeOfHeapReserve)
            features[30] = float(oh.SizeOfHeapCommit)
            features[31] = float(oh.LoaderFlags)
            features[32] = float(oh.NumberOfRvaAndSizes)
            # 数据目录（16 个，标准 PE 数据目录）
            for i, dd in enumerate(oh.DATA_DIRECTORY):
                if i >= 16:
                    break
                features[33 + i * 2] = float(dd.VirtualAddress & 0xFFFFFFFF)
                features[34 + i * 2] = float(dd.Size & 0xFFFFFFFF)
    except Exception:
        pass
    return features


def extract_section_info(pe: pefile.PE, file_bytes: bytes) -> np.ndarray:
    """特征组 3: 节区信息 (255 维) - 节区名 hash + 大小/熵值/属性"""
    features = np.zeros(SECTION_INFO_DIM, dtype=np.float32)
    if not pe.sections:
        return features
    try:
        # 统计信息（前 32 维）
        features[0] = float(len(pe.sections))
        total_raw = 0
        total_virtual = 0
        for section in pe.sections:
            total_raw += section.SizeOfRawData
            total_virtual += section.Misc_VirtualSize
        features[1] = float(total_raw)
        features[2] = float(total_virtual)
        # 节区名 hash（前 32 个 hash）
        for i, section in enumerate(pe.sections[:32]):
            name_hash = safe_hash32(section.Name.decode('utf-8', errors='replace').rstrip('\x00'))
            features[3 + (name_hash % 32)] += 1.0
        # 节区详细信息（前 10 个节区）
        for i, section in enumerate(pe.sections[:10]):
            if i >= 10:
                break
            base = 10 + i * 22
            try:
                features[base] = float(section.SizeOfRawData)
                features[base + 1] = float(section.Misc_VirtualSize)
                features[base + 2] = float(section.VirtualAddress)
                features[base + 3] = float(section.PointerToRawData)
                features[base + 4] = float(section.Characteristics)
                # 计算节区熵值
                section_data = section.get_data()
                if section_data:
                    entropy = 0
                    if len(section_data) > 0:
                        byte_counts = [0] * 256
                        for byte in section_data:
                            byte_counts[byte] += 1
                        total = len(section_data)
                        for count in byte_counts:
                            if count > 0:
                                p = count / total
                                entropy -= p * math.log2(p)
                    features[base + 5] = entropy
                else:
                    features[base + 5] = 0.0
                # 计算节区名 hash
                name_hash = safe_hash32(section.Name.decode('utf-8', errors='replace').rstrip('\x00'))
                features[base + 6] = float(name_hash & 0xFFFF)
                features[base + 7] = float(name_hash >> 16)
                # 节区名 hash 在固定桶中的位置
                bucket = name_hash % (SECTION_INFO_DIM - 230)
                features[230 + bucket] += 1.0
            except Exception:
                pass
    except Exception:
        pass
    return features


def extract_imports(pe: pefile.PE) -> np.ndarray:
    """特征组 4: 导入表 (1280 维) - IAT 导入函数名 hash"""
    features = np.zeros(PE_IAT_API_DIM, dtype=np.float32)
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') or pe.DIRECTORY_ENTRY_IMPORT is None:
        return features
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name is None:
                    continue
                name = imp.name.decode('utf-8', errors='replace')
                # EMBER 风格：函数名 hash 模 1280 作为桶索引
                bucket = safe_hash32(name) % PE_IAT_API_DIM
                features[bucket] += 1.0
                # 同时记录危险 API 标记
                for api in DANGEROUS_APIS:
                    if api.lower() in name.lower():
                        # 危险 API 单独占一个特征位（最后 100 维）
                        danger_bucket = 1180 + (safe_hash32(name) % 100)
                        features[danger_bucket] += 1.0
                        break
    except Exception:
        pass
    return features


def extract_exports(pe: pefile.PE) -> np.ndarray:
    """特征组 5: 导出表 (128 维) - EAT 导出函数名 hash"""
    features = np.zeros(PE_EAT_API_DIM, dtype=np.float32)
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') or pe.DIRECTORY_ENTRY_EXPORT is None:
        return features
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name is None:
                continue
            name = exp.name.decode('utf-8', errors='replace')
            bucket = safe_hash32(name) % PE_EAT_API_DIM
            features[bucket] += 1.0
    except Exception:
        pass
    return features


def extract_data_directories(pe: pefile.PE) -> np.ndarray:
    """特征组 6: 数据目录 (100 维) - 数据目录条目信息"""
    features = np.zeros(DATA_DIRECTORIES_DIM, dtype=np.float32)
    if not pe.OPTIONAL_HEADER:
        return features
    try:
        for i, dd in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if i >= 16:
                break
            # 名称 hash
            name = DATA_DIRECTORY_NAMES[i] if i < len(DATA_DIRECTORY_NAMES) else f"DIR_{i}"
            name_hash = safe_hash32(name) % (DATA_DIRECTORIES_DIM - 16)
            features[name_hash] += 1.0
            # RVA 和 Size（前 16 个）
            features[84 + i] = float((dd.VirtualAddress & 0xFFFFFFFF) > 0) * 1.0
            features[84 + i] += float((dd.Size & 0xFFFFFFFF) > 0) * 1.0
    except Exception:
        pass
    return features


def extract_general_file_info(file_bytes: bytes) -> np.ndarray:
    """特征组 7: 通用文件信息 (10 维)"""
    features = np.zeros(GENERAL_FILE_INFO_DIM, dtype=np.float32)
    try:
        features[0] = float(len(file_bytes))
        # 检查 debug 区段
        if b'.debug' in file_bytes or b'RSDS' in file_bytes:
            features[1] = 1.0
        # 检查 resource 区段
        if b'.rsrc' in file_bytes:
            features[2] = 1.0
        # 检查 digital signature
        if b'PKCS7' in file_bytes or b'WIN_CERTIFICATE' in file_bytes:
            features[3] = 1.0
        # 检查 overlay
        pe_offset = struct.unpack('<I', file_bytes[0x3c:0x40])[0]
        if pe_offset + 0x18 < len(file_bytes):
            pe_size_offset = pe_offset + 0x50
            if pe_size_offset + 4 < len(file_bytes):
                pe_size = struct.unpack('<I', file_bytes[pe_size_offset:pe_size_offset + 4])[0]
                if pe_size + pe_offset < len(file_bytes):
                    features[4] = float(len(file_bytes) - (pe_size + pe_offset))
        # MZ 头检查
        if file_bytes[:2] == b'MZ':
            features[5] = 1.0
        # PE 头检查
        if len(file_bytes) > 0x3c + 4:
            pe_offset = struct.unpack('<I', file_bytes[0x3c:0x40])[0]
            if pe_offset + 4 < len(file_bytes) and file_bytes[pe_offset:pe_offset + 4] == b'PE\x00\x00':
                features[6] = 1.0
        # 文件扩展名（从 MZ 头后推断）
        if len(file_bytes) > 2:
            ext_guess = file_bytes[:2]
            features[7] = float(safe_hash32(ext_guess.decode('utf-8', errors='replace')) & 0xFF)
    except Exception:
        pass
    return features


def extract_string_features(file_bytes: bytes) -> np.ndarray:
    """特征组 8: 字符串特征 (200 维) - 2025 增强：URL/IP/注册表/PowerShell/API 名等敏感关键字"""
    features = np.zeros(STRING_FEATURES_DIM, dtype=np.float32)
    try:
        # 提取所有可打印字符串（ASCII 至少 4 字符 / Unicode 至少 3 字符）
        strings = []
        # ASCII 字符串
        i = 0
        while i < len(file_bytes) - 3:
            if 32 <= file_bytes[i] < 127:
                j = i
                while j < len(file_bytes) and 32 <= file_bytes[j] < 127:
                    j += 1
                if j - i >= 4:
                    strings.append(file_bytes[i:j].decode('ascii', errors='replace').lower())
                i = j
            else:
                i += 1
        # Unicode 字符串（UTF-16LE）
        i = 0
        while i < len(file_bytes) - 6:
            if 32 <= file_bytes[i] < 127 and file_bytes[i + 1] == 0:
                j = i
                while j < len(file_bytes) - 1 and 32 <= file_bytes[j] < 127 and file_bytes[j + 1] == 0:
                    j += 2
                if (j - i) // 2 >= 3:
                    try:
                        s = file_bytes[i:j].decode('utf-16-le', errors='replace').lower()
                        strings.append(s)
                    except Exception:
                        pass
                i = j
            else:
                i += 1
        # 统计每个敏感关键字的命中次数
        for keyword in SUSPICIOUS_KEYWORDS:
            count = sum(1 for s in strings if keyword.lower() in s)
            if count > 0:
                bucket = safe_hash32(keyword) % (STRING_FEATURES_DIM - 50)
                features[bucket] += float(min(count, 10))
        # 字符串总数和平均长度（前 10 维）
        features[150] = float(len(strings))
        if strings:
            features[151] = float(sum(len(s) for s in strings) / len(strings))
        # URL/IP/Email 数量
        url_count = sum(1 for s in strings if 'http://' in s or 'https://' in s)
        ip_count = sum(1 for s in strings if any(p in s for p in ['192.168.', '10.0.0.', '172.16.']))
        email_count = sum(1 for s in strings if '@' in s and '.' in s.split('@')[-1])
        features[152] = float(url_count)
        features[153] = float(ip_count)
        features[154] = float(email_count)
        # PowerShell / cmd 关键字
        ps_count = sum(1 for s in strings if 'powershell' in s)
        cmd_count = sum(1 for s in strings if 'cmd' in s or 'exec' in s)
        features[155] = float(ps_count)
        features[156] = float(cmd_count)
        # Base64 编码字符串（启发式）
        b64_count = sum(1 for s in strings if len(s) > 20 and len(s) % 4 == 0 and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789+/=' for c in s))
        features[157] = float(b64_count)
        # 注册表路径
        reg_count = sum(1 for s in strings if 'Software\\Microsoft' in s or 'CurrentControlSet' in s)
        features[158] = float(reg_count)
        # 加密 API
        crypto_count = sum(1 for s in strings if any(api in s for api in ['Crypt', 'AES', 'RSA', 'TLS']))
        features[159] = float(crypto_count)
    except Exception:
        pass
    return features


def extract_resource_metadata(pe: pefile.PE) -> np.ndarray:
    """特征组 9: 资源元数据 (90 维) - 资源段大小、语言代码页、图标 hash"""
    features = np.zeros(RESOURCE_METADATA_DIM, dtype=np.float32)
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') or pe.DIRECTORY_ENTRY_RESOURCE is None:
        return features
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            # 资源段总大小
            features[0] = float(pe.DIRECTORY_ENTRY_RESOURCE.struct.Size)
            features[1] = float(pe.DIRECTORY_ENTRY_RESOURCE.struct.NumberOfNamedEntries)
            features[2] = float(pe.DIRECTORY_ENTRY_RESOURCE.struct.NumberOfIdEntries)
        # 图标 hash（RT_ICON, RT_GROUP_ICON）
        if hasattr(pe, 'get_icon_w'):
            for icon in pe.get_icon_w():
                if icon:
                    icon_hash = safe_hash32(icon[:32].hex())
                    features[3 + (icon_hash % 30)] += 1.0
                    features[33 + (icon_hash % 30)] += 1.0
        # 语言代码页 hash
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and pe.DIRECTORY_ENTRY_RESOURCE is not None:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, 'data'):
                    lang_hash = entry.data.struct.Language & 0xFFFF
                    features[63 + (lang_hash % 20)] += 1.0
        # 资源类型 hash
        resource_types = [
            'RT_CURSOR', 'RT_BITMAP', 'RT_ICON', 'RT_MENU', 'RT_DIALOG',
            'RT_STRING', 'RT_FONTDIR', 'RT_FONT', 'RT_ACCELERATOR',
            'RT_RCDATA', 'RT_MESSAGETABLE', 'RT_GROUP_CURSOR', 'RT_GROUP_ICON',
            'RT_VERSION', 'RT_DLGINCLUDE', 'RT_PLUGPLAY', 'RT_VXD',
            'RT_ANICURSOR', 'RT_ANIICON', 'RT_HTML', 'RT_MANIFEST',
        ]
        for rt in resource_types:
            bucket = safe_hash32(rt) % 10
            features[80 + bucket] += 1.0
    except Exception:
        pass
    return features


def compute_sha256(file_bytes: bytes) -> str:
    """计算文件 SHA-256（用于追溯，但不存原始样本）"""
    return hashlib.sha256(file_bytes).hexdigest()


def extract_features_from_file(file_path: str) -> Optional[Dict]:
    """从 PE 文件提取 EMBER-2025 风格特征。

    返回：
    - features: 2671 维特征向量
    - sha256: 文件 SHA-256
    - file_size: 文件大小
    - timestamp: 提取时间戳
    """
    try:
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
    except Exception as e:
        print(f"Failed to read {file_path}: {e}", file=sys.stderr)
        return None

    if len(file_bytes) < 1024 or not file_bytes[:2] == b'MZ':
        return None

    sha256 = compute_sha256(file_bytes)

    try:
        pe = pefile.PE(data=file_bytes, fast_load=False)
    except pefile.PEFormatError:
        return None

    try:
        # 提取所有特征组
        byte_hist = extract_byte_histogram(file_bytes)
        pe_header = extract_pe_header(pe)
        section_info = extract_section_info(pe, file_bytes)
        imports = extract_imports(pe)
        exports = extract_exports(pe)
        data_dirs = extract_data_directories(pe)
        general_info = extract_general_file_info(file_bytes)
        string_features = extract_string_features(file_bytes)
        resource_meta = extract_resource_metadata(pe)

        # 拼接所有特征
        features = np.concatenate([
            byte_hist,        # 256
            pe_header,         # 62
            section_info,      # 255
            imports,            # 1280
            exports,            # 128
            data_dirs,          # 100
            general_info,       # 10
            string_features,   # 200
            resource_meta,      # 90
        ])

        # 验证维度
        assert features.shape[0] == EMBER_2025_TOTAL, \
            f"Expected {EMBER_2025_TOTAL} features, got {features.shape[0]}"

        return {
            'features': features.astype(np.float32),
            'sha256': sha256,
            'file_size': len(file_bytes),
            'timestamp': int(time.time()),
            'file_path': str(file_path),
        }
    except Exception as e:
        print(f"Failed to extract features from {file_path}: {e}", file=sys.stderr)
        return None
    finally:
        try:
            pe.close()
        except Exception:
            pass


def extract_features_batch(file_paths: List[str], label: int = 0, family: str = '') -> Tuple[np.ndarray, List[Dict]]:
    """批量提取特征。

    返回：
    - feature_matrix: (N, 2671) 稀疏矩阵（密集矩阵；后续转换为 CSR）
    - metadata: 元数据列表
    """
    features_list = []
    metadata = []
    for i, fp in enumerate(file_paths):
        if (i + 1) % 100 == 0:
            print(f"  [{i + 1}/{len(file_paths)}] extracting...", file=sys.stderr)
        result = extract_features_from_file(fp)
        if result is None:
            continue
        features_list.append(result['features'])
        meta = {
            'sha256': result['sha256'],
            'label': label,
            'family': family,
            'file_size': result['file_size'],
            'timestamp': result['timestamp'],
            'file_path': result['file_path'],
        }
        metadata.append(meta)
    if not features_list:
        return np.zeros((0, EMBER_2025_TOTAL), dtype=np.float32), []
    return np.stack(features_list, axis=0), metadata


def save_features_sparse(features: np.ndarray, metadata: List[Dict], output_path: str):
    """保存特征为稀疏 CSR 格式（不存原始样本，只存特征向量 + 标签 + 元数据）。"""
    try:
        from scipy import sparse
        from scipy.sparse import csr_matrix
    except ImportError:
        print("scipy required for sparse storage. Install with: pip install scipy", file=sys.stderr)
        return False

    # 转换为 CSR 稀疏矩阵
    feature_csr = csr_matrix(features.astype(np.float32))
    # 分离元数据为 JSON
    meta_path = output_path.replace('.npz', '.meta.json')
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump({
            'feature_dim': EMBER_2025_TOTAL,
            'sample_count': len(metadata),
            'metadata': metadata,
        }, f, indent=2)

    # 保存稀疏矩阵
    sparse.save_npz(output_path, feature_csr)
    return True


def load_features_sparse(npz_path: str) -> Tuple[sparse.csr_matrix, Dict]:
    """加载稀疏特征。"""
    try:
        from scipy import sparse
    except ImportError:
        raise
    feature_csr = sparse.load_npz(npz_path)
    meta_path = npz_path.replace('.npz', '.meta.json')
    metadata = {}
    if os.path.exists(meta_path):
        with open(meta_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
    return feature_csr, metadata


if __name__ == '__main__':
    # 简单自测：从 test.txt 提取（即使是普通文本，也能验证特征维度正确性）
    import os
    test_path = 'E:\\test.txt'
    if os.path.exists(test_path):
        result = extract_features_from_file(test_path)
        if result:
            print(f"特征维度: {result['features'].shape}")
            print(f"  byte_histogram: {BYTE_HISTOGRAM_DIM}")
            print(f"  pe_header: {PE_STRUCTURE_DIM}")
            print(f"  section_info: {SECTION_INFO_DIM}")
            print(f"  imports: {PE_IAT_API_DIM}")
            print(f"  exports: {PE_EAT_API_DIM}")
            print(f"  data_dirs: {DATA_DIRECTORIES_DIM}")
            print(f"  general: {GENERAL_FILE_INFO_DIM}")
            print(f"  strings: {STRING_FEATURES_DIM}")
            print(f"  resources: {RESOURCE_METADATA_DIM}")
            print(f"  总计: {EMBER_2025_TOTAL}")
        else:
            print("Failed to extract features (expected for non-PE file)")
    else:
        print(f"Test file not found: {test_path}")
    print(f"\nEMBER-2025 总特征维度: {EMBER_2025_TOTAL}")
    print(f"  - 静态特征 (PE + 字符串 + 资源): ~{BYTE_HISTOGRAM_DIM + PE_STRUCTURE_DIM + SECTION_INFO_DIM + PE_IAT_API_DIM + PE_EAT_API_DIM + DATA_DIRECTORIES_DIM + GENERAL_FILE_INFO_DIM + STRING_FEATURES_DIM + RESOURCE_METADATA_DIM}")
