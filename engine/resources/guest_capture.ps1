param(
    [Parameter(Mandatory=$true)][string]$SamplePath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [int]$TimeoutMs = 600000
)

$ErrorActionPreference = 'SilentlyContinue'
$nativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class EverbloomGuestMemory {
    [StructLayout(LayoutKind.Sequential)]
    public struct Mbi {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public sealed class Candidate {
        public ulong region_base { get; set; }
        public uint header_offset { get; set; }
        public ulong image_base { get; set; }
        public uint image_size { get; set; }
        public uint entry_point_rva { get; set; }
        public ulong entry_point_address { get; set; }
        public ulong? observed_execution_address { get; set; }
        public bool reconstruction_verified { get; set; }
        public string source { get; set; }
        public byte confidence { get; set; }
    }

    public sealed class Snapshot {
        public uint RegionsScanned { get; set; }
        public uint ExecutableRegions { get; set; }
        public ulong BytesCaptured { get; set; }
        public uint ObservedExecutionPoints { get; set; }
        public bool Truncated { get; set; }
        public List<Candidate> Candidates { get; } = new List<Candidate>();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ThreadEntry {
        public uint Size;
        public uint Usage;
        public uint ThreadId;
        public uint OwnerProcessId;
        public int BasePriority;
        public int DeltaPriority;
        public uint Flags;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(
        IntPtr process, IntPtr address, out Mbi info, UIntPtr length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(
        IntPtr process, IntPtr address, [Out] byte[] buffer, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(
        uint flags, uint processId);
    [DllImport("kernel32.dll")] static extern bool Thread32First(
        IntPtr snapshot, ref ThreadEntry entry);
    [DllImport("kernel32.dll")] static extern bool Thread32Next(
        IntPtr snapshot, ref ThreadEntry entry);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenThread(
        uint access, bool inherit, uint threadId);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetThreadContext(
        IntPtr thread, IntPtr context);

    const uint QueryRead = 0x0410;
    const uint Commit = 0x1000;
    const uint Private = 0x20000;
    const uint Image = 0x1000000;
    const uint Execute = 0x10;
    const uint ExecuteRead = 0x20;
    const uint ExecuteReadWrite = 0x40;
    const uint ExecuteWriteCopy = 0x80;
    const uint Guard = 0x100;
    const uint SnapshotThreads = 0x00000004;
    const uint ThreadGetContext = 0x0008;
    const uint ThreadQueryInformation = 0x0040;
    const int ContextFlagsOffset = 0x30;
    const int InstructionPointerOffset = 0xf8;
    const int ContextFull = 0x10000b;
    const int ContextSize = 1232;
    const uint MaxCapture = 32 * 1024 * 1024;
    const uint MaxRegion = 4 * 1024 * 1024;
    const uint MaxExecutableRegions = 96;
    const uint MaxQueries = 32768;

    static ushort U16(byte[] b, int o) { return BitConverter.ToUInt16(b, o); }
    static uint U32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
    static ulong U64(byte[] b, int o) { return BitConverter.ToUInt64(b, o); }
    static bool IsExecutable(uint protect) {
        uint p = protect & 0xff;
        return (protect & Guard) == 0 && (p == Execute || p == ExecuteRead
            || p == ExecuteReadWrite || p == ExecuteWriteCopy);
    }
    static bool IsWritableExecutable(uint protect) {
        uint p = protect & 0xff;
        return (protect & Guard) == 0 && (p == ExecuteReadWrite || p == ExecuteWriteCopy);
    }

    static List<ulong> ThreadInstructionPointers(uint pid) {
        var result = new List<ulong>();
        IntPtr snapshot = CreateToolhelp32Snapshot(SnapshotThreads, 0);
        if (snapshot == IntPtr.Zero || snapshot.ToInt64() == -1) return result;
        try {
            ThreadEntry entry = new ThreadEntry { Size = (uint)Marshal.SizeOf(typeof(ThreadEntry)) };
            if (!Thread32First(snapshot, ref entry)) return result;
            do {
                if (entry.OwnerProcessId != pid) continue;
                IntPtr thread = OpenThread(ThreadGetContext | ThreadQueryInformation, false, entry.ThreadId);
                if (thread == IntPtr.Zero) continue;
                IntPtr context = Marshal.AllocHGlobal(ContextSize);
                try {
                    Marshal.WriteInt32(context, ContextFlagsOffset, ContextFull);
                    if (GetThreadContext(thread, context)) {
                        long ip = Marshal.ReadInt64(context, InstructionPointerOffset);
                        if (ip != 0) result.Add(unchecked((ulong)ip));
                    }
                } finally {
                    Marshal.FreeHGlobal(context);
                    CloseHandle(thread);
                }
            } while (Thread32Next(snapshot, ref entry));
        } finally { CloseHandle(snapshot); }
        return result;
    }

    static Candidate Parse(byte[] b, int offset, ulong regionBase, bool imageRegion) {
        try {
            if (offset + 0x40 > b.Length || b[offset] != 0x4d || b[offset + 1] != 0x5a) return null;
            int pe = checked(offset + (int)U32(b, offset + 0x3c));
            if (pe + 24 > b.Length || b[pe] != 0x50 || b[pe + 1] != 0x45
                || b[pe + 2] != 0 || b[pe + 3] != 0) return null;
            ushort sectionCount = U16(b, pe + 6);
            ushort optionalSize = U16(b, pe + 20);
            int optional = checked(pe + 24);
            if (sectionCount < 1 || sectionCount > 96 || optionalSize < 64
                || optional + optionalSize > b.Length) return null;
            ushort magic = U16(b, optional);
            if (magic != 0x10b && magic != 0x20b) return null;
            ulong imageBase = magic == 0x10b ? U32(b, optional + 28) : U64(b, optional + 24);
            uint entryRva = U32(b, optional + 16);
            uint imageSize = U32(b, optional + 56);
            uint headersSize = U32(b, optional + 60);
            if (imageSize == 0 || imageSize > 512 * 1024 * 1024 || entryRva >= imageSize
                || headersSize == 0 || headersSize > imageSize
                || (ulong)offset + headersSize > (ulong)b.Length) return null;
            int sectionTable = checked(optional + optionalSize);
            bool reconstructed = imageSize <= 16 * 1024 * 1024;
            for (int i = 0; i < sectionCount; i++) {
                int section = checked(sectionTable + i * 40);
                if (section + 40 > b.Length) return null;
                uint virtualSize = Math.Max(1u, U32(b, section + 8));
                uint virtualAddress = U32(b, section + 12);
                if (virtualAddress >= imageSize || virtualAddress + virtualSize > imageSize) return null;
                if ((ulong)offset + virtualAddress + virtualSize > (ulong)b.Length) reconstructed = false;
            }
            ulong mappedBase = checked(regionBase + (ulong)offset);
            return new Candidate {
                region_base = regionBase,
                header_offset = (uint)offset,
                image_base = imageBase,
                image_size = imageSize,
                entry_point_rva = entryRva,
                entry_point_address = checked(mappedBase + entryRva),
                observed_execution_address = null,
                reconstruction_verified = reconstructed,
                source = imageRegion ? "mapped_rwx" : "private_executable_memory",
                confidence = (byte)(imageRegion ? 82 : 74)
            };
        } catch { return null; }
    }

    public static Snapshot Capture(uint pid) {
        var result = new Snapshot();
        IntPtr process = OpenProcess(QueryRead, false, pid);
        if (process == IntPtr.Zero) return result;
        try {
            IntPtr address = IntPtr.Zero;
            while (result.RegionsScanned < MaxQueries
                && result.ExecutableRegions < MaxExecutableRegions
                && result.BytesCaptured < MaxCapture) {
                Mbi info;
                UIntPtr queried = VirtualQueryEx(process, address, out info,
                    (UIntPtr)Marshal.SizeOf(typeof(Mbi)));
                if (queried == UIntPtr.Zero || info.RegionSize == UIntPtr.Zero) break;
                result.RegionsScanned++;
                long next = info.BaseAddress.ToInt64() + (long)info.RegionSize.ToUInt64();
                if (next <= address.ToInt64()) break;
                address = new IntPtr(next);
                bool imageRegion = info.Type == Image;
                bool suspiciousImage = imageRegion && IsWritableExecutable(info.Protect);
                if (info.State != Commit || !IsExecutable(info.Protect)
                    || (info.Type != Private && !suspiciousImage)) continue;
                result.ExecutableRegions++;
                ulong remaining = MaxCapture - result.BytesCaptured;
                int length = (int)Math.Min(Math.Min(info.RegionSize.ToUInt64(), MaxRegion), remaining);
                if (length <= 0) { result.Truncated = true; break; }
                byte[] buffer = new byte[length];
                UIntPtr read;
                if (!ReadProcessMemory(process, info.BaseAddress, buffer, (UIntPtr)length, out read)
                    || read.ToUInt64() < 0x40) continue;
                int actual = (int)read.ToUInt64();
                result.BytesCaptured += (ulong)actual;
                for (int i = 0; i + 0x40 <= actual && result.Candidates.Count < 32; i++) {
                    if (buffer[i] != 0x4d || buffer[i + 1] != 0x5a) continue;
                    Candidate candidate = Parse(buffer, i, (ulong)info.BaseAddress.ToInt64(), imageRegion);
                    if (candidate == null) continue;
                    bool duplicate = result.Candidates.Exists(existing =>
                        existing.region_base == candidate.region_base
                        && existing.entry_point_address == candidate.entry_point_address);
                    if (!duplicate) result.Candidates.Add(candidate);
                }
                if (info.RegionSize.ToUInt64() > (ulong)length) {
                    result.Truncated = true;
                    break;
                }
            }
            foreach (ulong instructionPointer in ThreadInstructionPointers(pid)) {
                foreach (Candidate candidate in result.Candidates) {
                    ulong end = candidate.entry_point_address + Math.Max(1u, candidate.image_size);
                    if (instructionPointer >= candidate.entry_point_address && instructionPointer < end) {
                        if (!candidate.observed_execution_address.HasValue) {
                            candidate.observed_execution_address = instructionPointer;
                            result.ObservedExecutionPoints++;
                        }
                    }
                }
            }
            if (result.RegionsScanned >= MaxQueries || result.ExecutableRegions >= MaxExecutableRegions
                || result.BytesCaptured >= MaxCapture) result.Truncated = true;
        } finally { CloseHandle(process); }
        return result;
    }
}
'@
try { Add-Type -TypeDefinition $nativeSource -Language CSharp } catch {}

$extension = [IO.Path]::GetExtension($SamplePath).ToLowerInvariant()
switch ($extension) {
    '.cmd' { $child = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d','/s','/c',('call "' + $SamplePath + '"')) -WindowStyle Hidden -PassThru }
    '.bat' { $child = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d','/s','/c',('call "' + $SamplePath + '"')) -WindowStyle Hidden -PassThru }
    '.ps1' { $child = Start-Process -FilePath ($env:SystemRoot + '\System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$SamplePath) -WindowStyle Hidden -PassThru }
    '.msi' { $child = Start-Process -FilePath ($env:SystemRoot + '\System32\msiexec.exe') -ArgumentList @('/i',$SamplePath,'/qn','/norestart') -WindowStyle Hidden -PassThru }
    default { $child = Start-Process -FilePath $SamplePath -WindowStyle Hidden -PassThru }
}

$started = Get-Date
$rounds = 0
$triggered = 0
$allCandidates = @()
$bytes = [uint64]0
$regions = [uint32]0
$execRegions = [uint32]0
$observedExecutionPoints = [uint32]0
$truncated = $false
while ($child -and -not $child.HasExited -and ((Get-Date) - $started).TotalMilliseconds -lt $TimeoutMs) {
    $snapshot = [EverbloomGuestMemory]::Capture([uint32]$child.Id)
    $rounds++
    $bytes += [uint64]$snapshot.BytesCaptured
    $regions = [Math]::Max($regions, [uint32]$snapshot.RegionsScanned)
    $execRegions = [Math]::Max($execRegions, [uint32]$snapshot.ExecutableRegions)
    $observedExecutionPoints = [Math]::Max($observedExecutionPoints, [uint32]$snapshot.ObservedExecutionPoints)
    $event_triggered = $snapshot.Candidates.Count -gt 0 -or $snapshot.ObservedExecutionPoints -gt 0
    if ($event_triggered) { $triggered++; $allCandidates += $snapshot.Candidates }
    if ($snapshot.Truncated) { $truncated = $true }
    Start-Sleep -Milliseconds $(if ($event_triggered) { 35 } else { 180 })
}
try { $child.WaitForExit(1500) } catch {}
$unique = @()
foreach ($candidate in $allCandidates) {
    $duplicate = $unique | Where-Object { $_.region_base -eq $candidate.region_base -and $_.entry_point_address -eq $candidate.entry_point_address }
    if (-not $duplicate) { $unique += $candidate }
}
$recovered = @($unique | Where-Object { $_.reconstruction_verified }).Count
$status = if ($recovered -gt 0) { 'recovered_candidate' } elseif ($unique.Count -gt 0) { 'candidate' } else { 'no_candidate' }
$notes = @('guest_memory_agent','guest_thread_ip_tracked;entry_point_correlation_bounded')
if ($unique.Count -eq 0) { $notes += 'no_structurally_valid_pe_in_guest_executable_memory' }
if ($truncated) { $notes += 'guest_capture_budget_reached' }
$maxConfidence = if ($unique.Count -gt 0) { (($unique | Measure-Object confidence -Maximum).Maximum / 100.0) } else { 0.0 }
$report = [ordered]@{
    status = $status
    regions_scanned = $regions
    executable_regions = $execRegions
    candidate_images = [uint32]$unique.Count
    recovered_entry_points = [uint32]$recovered
    observed_execution_points = $observedExecutionPoints
    snapshot_rounds = [uint32]$rounds
    triggered_snapshots = [uint32]$triggered
    adaptive_timeout_ms = [uint64]$TimeoutMs
    bytes_captured = $bytes
    truncated = $truncated
    confidence = [double]$maxConfidence
    candidates = @($unique)
    notes = @($notes)
}
$json = $report | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText($OutputPath, $json, (New-Object Text.UTF8Encoding($false)))
exit $(if ($child) { $child.ExitCode } else { 1 })
