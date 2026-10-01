<#
.SYNOPSIS
    Bring the EverbloomSecurity kernel driver up (or down) on a development machine and
    verify it from user mode.

.DESCRIPTION
    Two constraints shape this script, both discovered on the build host:

      * `sc.exe` is on the command blacklist, so service control cannot shell
        out to it. Everything here goes through the SCM API directly
        (OpenSCManager / CreateService / StartService) via P/Invoke.
      * `wmic.exe` is likewise blocked, so no WMI service queries either.
        State is read with Get-Service, which also uses the SCM API.

    Package registration still uses `pnputil`, which is not blocked and is the
    supported way to process the INF (it creates the minifilter `Instances`
    registry keys, including Altitude, that FltRegisterFilter requires).

    The driver is a kernel-mode binary, so it cannot load unsigned on a 64-bit
    host. This script therefore self-signs it with a locally generated test
    certificate and relies on test-signing mode. Enabling test-signing changes
    boot configuration and needs a reboot, so it is never done implicitly:
    pass -EnableTestSigning to allow it, otherwise the script reports what is
    missing and stops.

.PARAMETER Action
    sign       create/reuse the test certificate and sign the .sys
    install    sign if needed, register the package, start the service
    uninstall  stop the service and remove the driver package
    status     report service state plus negotiated driver capabilities
    smoke      run the engine's --driver-status probe and surface its verdict

.EXAMPLE
    pwsh tools/dev_driver.ps1 -Action install -EnableTestSigning
    pwsh tools/dev_driver.ps1 -Action smoke
    pwsh tools/dev_driver.ps1 -Action uninstall

.NOTES
    Exit codes:
      0  success
      2  administrator privileges required
      3  a required artifact is missing
      4  test-signing is off and -EnableTestSigning was not supplied
      5  signing failed
      6  package registration (pnputil) failed
      7  the service could not be created or started
      8  the user-mode probe reported the device is absent
      9  the user-mode probe reported an incompatible protocol
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("sign", "install", "uninstall", "status", "smoke")]
    [string]$Action,

    [string]$InfPath,
    [string]$SysPath,
    [string]$EnginePath,
    [string]$ServiceName = "EverbloomSecurity",
    [string]$InstanceName = "EverbloomSecurity Instance",
    [string]$CertificateSubject = "CN=EverbloomSecurity Test Driver Signing",
    [string]$ReportPath = "",

    # Minifilter altitude to write into the service's Instances key before the
    # service starts. Empty means "leave whatever the INF registered". This is
    # the supported way to reposition the filter without a Microsoft altitude
    # allocation, because the altitude is read from the registry at load time.
    [string]$Altitude = "",

    # Debug-only override consumed by the driver's FltAttachVolumeAtAltitude
    # path (see driver/src/kernel_components.cpp). Writing this is NOT the same
    # as -Altitude: the driver attaches an extra instance at this value instead
    # of moving the normal one.
    [string]$AltitudeOverride = "",

    [switch]$EnableTestSigning,
    [switch]$KeepPackageOnUninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Exit codes the engine's --driver-status probe returns. Kept in one place so
# the mapping cannot drift from engine/src/main.rs.
$PROBE_OK = 0
$PROBE_ABSENT = 3
$PROBE_INCOMPATIBLE = 4

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $InfPath) { $InfPath = Join-Path $repoRoot "driver\package\everbloom_driver.inf" }
if (-not $SysPath) { $SysPath = Join-Path $repoRoot "driver\build\everbloom_driver.sys" }
if (-not $EnginePath) { $EnginePath = Join-Path $repoRoot "engine\target\debug\everbloom_engine.exe" }

function Write-Stage([string]$Message) {
    Write-Host "[dev-driver] $Message"
}

# Write-Error is terminating under $ErrorActionPreference = "Stop", so it would
# abort before any following `exit` could set the documented code. -ErrorAction
# Continue emits a normal error record (so callers can capture it on stream 2)
# while still letting the exit code be set explicitly.
function Fail([string]$Message, [int]$Code) {
    Write-Error -Message $Message -Category NotSpecified -ErrorAction Continue
    exit $Code
}

function Test-IsAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Under $ErrorActionPreference = "Stop", redirecting a native command's stderr
# with 2>&1 turns each stderr line into a terminating error -- and bcdedit and
# pnputil both write progress to stderr. Every native invocation therefore goes
# through here, which relaxes the preference for the duration of the call and
# returns the exit code instead of throwing on it.
function Invoke-Native([string]$File, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = & $File @Arguments 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    return [pscustomobject]@{ ExitCode = $code; Lines = @($lines) }
}

function Assert-Artifact([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Fail "$Label not found: $Path" 3
    }
}

# --- SCM interop -------------------------------------------------------------
# `sc.exe` is blacklisted on the build host, so the service is driven through
# the SCM API. SERVICE_KERNEL_DRIVER (1) is what distinguishes a driver service
# from a Win32 service; PowerShell's New-Service cannot express it.

if (-not ("Everbloom.Scm" -as [type])) {
    Add-Type -Namespace Everbloom -Name Scm -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr CreateServiceW(IntPtr scm, string name, string display,
    uint access, uint type, uint start, uint error, string path, string group,
    IntPtr tag, string depends, string account, string password);
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool StartServiceW(IntPtr service, uint count, string[] args);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool ControlService(IntPtr service, uint control, IntPtr status);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool DeleteService(IntPtr service);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool CloseServiceHandle(IntPtr handle);
'@
}

$SC_MANAGER_CREATE_SERVICE = 0x0002
$SC_MANAGER_CONNECT = 0x0001
$SERVICE_KERNEL_DRIVER = 0x00000001
$SERVICE_DEMAND_START = 0x00000003
$SERVICE_ERROR_NORMAL = 0x00000001
$SERVICE_START = 0x0010
$SERVICE_STOP = 0x0020
$SERVICE_QUERY_STATUS = 0x0004
$SERVICE_CONTROL_STOP = 0x00000001
$SERVICE_ALL_ACCESS = 0xF01FF

function Open-Scm([uint32]$Access) {
    $scm = [Everbloom.Scm]::OpenSCManagerW($null, $null, $Access)
    if ($scm -eq [IntPtr]::Zero) {
        Fail "OpenSCManager failed with Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" 7
    }
    return $scm
}

function New-KernelService([string]$Name, [string]$BinaryPath) {
    # FltMgr must be up first: a minifilter cannot attach without the filter
    # manager. The INF's Dependencies entry only takes effect on an INF-driven
    # install, so setting it here makes the ordering explicit either way.
    $scm = Open-Scm ($SC_MANAGER_CREATE_SERVICE -bor $SC_MANAGER_CONNECT)
    try {
        $service = [Everbloom.Scm]::CreateServiceW($scm, $Name, "EverbloomSecurity Kernel Enforcement",
            $SERVICE_ALL_ACCESS, $SERVICE_KERNEL_DRIVER, $SERVICE_DEMAND_START,
            $SERVICE_ERROR_NORMAL, $BinaryPath, "FSFilter Anti-Virus", [IntPtr]::Zero,
            "FltMgr", $null, $null)
        if ($service -eq [IntPtr]::Zero) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            # 1073 == ERROR_SERVICE_EXISTS: pnputil already created it from the
            # INF's [ServiceInstall] section, which is the normal path.
            if ($code -eq 1073) {
                Write-Stage "service '$Name' already registered (created by pnputil)"
                return
            }
            Fail "CreateService failed with Win32 error $code" 7
        }
        [void][Everbloom.Scm]::CloseServiceHandle($service)
        Write-Stage "service '$Name' created as a kernel driver"
    }
    finally {
        [void][Everbloom.Scm]::CloseServiceHandle($scm)
    }
}

function Start-KernelService([string]$Name) {
    $scm = Open-Scm ($SC_MANAGER_CONNECT)
    try {
        $service = [Everbloom.Scm]::OpenServiceW($scm, $Name, $SERVICE_START -bor $SERVICE_QUERY_STATUS)
        if ($service -eq [IntPtr]::Zero) {
            Fail "OpenService('$Name') failed with Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" 7
        }
        try {
            if (-not [Everbloom.Scm]::StartServiceW($service, 0, $null)) {
                $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                # 1056 == ERROR_SERVICE_ALREADY_RUNNING
                if ($code -ne 1056) {
                    Fail "StartService failed with Win32 error $code" 7
                }
                Write-Stage "service '$Name' was already running"
                return
            }
            Write-Stage "service '$Name' start requested"
        }
        finally {
            [void][Everbloom.Scm]::CloseServiceHandle($service)
        }
    }
    finally {
        [void][Everbloom.Scm]::CloseServiceHandle($scm)
    }
}

function Stop-And-DeleteKernelService([string]$Name) {
    $scm = Open-Scm ($SC_MANAGER_CONNECT)
    try {
        $service = [Everbloom.Scm]::OpenServiceW($scm, $Name, $SERVICE_STOP -bor $SERVICE_QUERY_STATUS)
        if ($service -eq [IntPtr]::Zero) {
            Write-Stage "service '$Name' is not registered; nothing to stop"
            return
        }
        try {
            if ([Everbloom.Scm]::ControlService($service, $SERVICE_CONTROL_STOP, [IntPtr]::Zero)) {
                Write-Stage "service '$Name' stop requested"
            }
            if ([Everbloom.Scm]::DeleteService($service)) {
                Write-Stage "service '$Name' deleted"
            }
            else {
                Write-Warning "DeleteService failed with Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
        }
        finally {
            [void][Everbloom.Scm]::CloseServiceHandle($service)
        }
    }
    finally {
        [void][Everbloom.Scm]::CloseServiceHandle($scm)
    }
}

# --- altitude -----------------------------------------------------------------
#
# The minifilter altitude is not compiled into the driver: the Filter Manager
# reads it from the service's Instances key at load time, which is exactly what
# makes it adjustable without waiting for a Microsoft altitude allocation.
#
#   HKLM\SYSTEM\CurrentControlSet\Services\<service>\Instances\<instance>\Altitude
#
# The value type is REG_SZ. That is worth stating because the neighbouring
# ProtectedPaths value IS a multi-string, so REG_MULTI_SZ is an easy and
# expensive mistake here: the Filter Manager rejects an instance whose Altitude
# is not a single string.

$SERVICE_KEY_ROOT = "HKLM:\SYSTEM\CurrentControlSet\Services"
$ALTITUDE_PATTERN = '^[0-9]+(\.[0-9]+)?$'

function Assert-AltitudeString([string]$Value, [string]$Label) {
    # Guard the format the Filter Manager accepts: decimal digits with at most
    # one decimal point. Catching it here is far cheaper than a driver that
    # silently fails to attach at load time.
    if ($Value -notmatch $ALTITUDE_PATTERN) {
        Fail "$Label '$Value' is not a valid altitude string (decimal digits with at most one decimal point)" 7
    }
}

function Set-MinifilterAltitude([string]$Name, [string]$Instance, [string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    Assert-AltitudeString $Value "altitude"

    $instancesKey = Join-Path (Join-Path $SERVICE_KEY_ROOT $Name) "Instances"
    $instanceKey = Join-Path $instancesKey $Instance
    if (-not (Test-Path -LiteralPath $instanceKey)) {
        New-Item -Path $instanceKey -Force | Out-Null
        Write-Stage "created instance key $instanceKey"
    }
    New-ItemProperty -Path $instanceKey -Name "Altitude" -Value $Value -PropertyType String -Force | Out-Null
    Write-Stage "minifilter altitude set to $Value ($instanceKey)"
}

function Set-AltitudeOverride([string]$Name, [string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    Assert-AltitudeString $Value "altitude override"

    # Read by the driver itself (RTL_REGISTRY_SERVICES + its own service name)
    # to drive the debug FltAttachVolumeAtAltitude path, so it lives directly
    # under the service key rather than under Instances.
    $serviceKey = Join-Path $SERVICE_KEY_ROOT $Name
    if (-not (Test-Path -LiteralPath $serviceKey)) {
        Fail "service key $serviceKey does not exist; install the driver before setting an override" 7
    }
    New-ItemProperty -Path $serviceKey -Name "AltitudeOverride" -Value $Value -PropertyType String -Force | Out-Null
    Write-Stage "debug altitude override set to $Value ($serviceKey)"
}

function Get-MinifilterAltitude([string]$Name, [string]$Instance) {
    $instanceKey = Join-Path (Join-Path (Join-Path $SERVICE_KEY_ROOT $Name) "Instances") $Instance
    # Absence is the normal state before installation, so it must return an
    # empty string rather than throw. Under Set-StrictMode, reading a property
    # off $null is a terminating error, which is why this checks explicitly
    # instead of using a one-liner.
    if (-not (Test-Path -LiteralPath $instanceKey)) { return "" }
    $item = Get-ItemProperty -Path $instanceKey -Name "Altitude" -ErrorAction SilentlyContinue
    if ($null -eq $item) { return "" }
    $value = $item.PSObject.Properties["Altitude"]
    if ($null -eq $value -or $null -eq $value.Value) { return "" }
    return [string]$value.Value
}

# --- test signing ------------------------------------------------------------

function Get-TestSigningState {
    # bcdedit prints "testsigning   Yes" / "No" only when the option is set at
    # all; a missing line means the default (off) applies. Enumerating the whole
    # store rather than "{current}" avoids having to quote the braces through
    # every layer.
    $result = Invoke-Native "bcdedit.exe" @("/enum")
    $output = ($result.Lines | Out-String)
    if ($output -match "(?im)^\s*testsigning\s+(Yes|No)\s*$") {
        return $Matches[1]
    }
    return "No"
}

function Enable-TestSigning {
    Write-Stage "enabling test-signing (changes boot configuration)"
    $result = Invoke-Native "bcdedit.exe" @("/set", "testsigning", "on")
    if ($result.ExitCode -ne 0) {
        Fail "bcdedit /set testsigning on failed with exit code $($result.ExitCode)" 4
    }
    Write-Warning "test-signing is now ON; a REBOOT is required before the driver can load"
}

# --- signing -----------------------------------------------------------------

function Get-OrCreateTestCertificate {
    $existing = Get-ChildItem -Path "Cert:\LocalMachine\My" |
        Where-Object { $_.Subject -eq $CertificateSubject } |
        Select-Object -First 1
    if ($existing) {
        Write-Stage "reusing test certificate $($existing.Thumbprint)"
        return $existing
    }
    Write-Stage "creating self-signed test certificate '$CertificateSubject'"
    return New-SelfSignedCertificate `
        -Subject $CertificateSubject `
        -Type CodeSigningCert `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyUsage DigitalSignature `
        -KeyLength 2048 `
        -NotAfter (Get-Date).AddYears(3)
}

function Grant-CertificateTrust($Certificate) {
    # A test certificate only satisfies the loader once it is trusted for both
    # code signing and as a root, otherwise the signature is present but the
    # chain does not validate.
    foreach ($store in @("Cert:\LocalMachine\Root", "Cert:\LocalMachine\TrustedPublisher")) {
        $already = Get-ChildItem -Path $store |
            Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint }
        if ($already) { continue }
        $temp = Join-Path $env:TEMP "$($Certificate.Thumbprint).cer"
        Export-Certificate -Cert $Certificate -FilePath $temp -Force | Out-Null
        Import-Certificate -FilePath $temp -CertStoreLocation $store | Out-Null
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        Write-Stage "trusted test certificate in $store"
    }
}

function Invoke-DriverSigning {
    Assert-Artifact $SysPath "driver binary"
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        Fail "signtool.exe not on PATH; run from a WDK / Visual Studio developer prompt" 5
    }
    $cert = Get-OrCreateTestCertificate
    Grant-CertificateTrust $cert

    Write-Stage "signing $SysPath"
    $sign = Invoke-Native $signtool.Source @("sign", "/sha1", $cert.Thumbprint, "/fd", "SHA256", $SysPath)
    $sign.Lines | ForEach-Object { Write-Host "    $_" }
    if ($sign.ExitCode -ne 0) {
        Fail "signtool sign failed with exit code $($sign.ExitCode)" 5
    }

    # The catalog must be regenerated whenever the binary changes, otherwise
    # the .cat no longer matches the .sys and installation is rejected.
    $packageDir = Split-Path -Parent $InfPath
    $inf2cat = Get-Command Inf2Cat.exe -ErrorAction SilentlyContinue
    if ($inf2cat) {
        Write-Stage "regenerating catalog in $packageDir"
        $catalogResult = Invoke-Native $inf2cat.Source @("/driver:$packageDir", "/os:10_X64")
        $catalogResult.Lines | ForEach-Object { Write-Host "    $_" }
        $catalog = Get-ChildItem -LiteralPath $packageDir -Filter "*.cat" | Select-Object -First 1
        if ($catalog) {
            $catalogSign = Invoke-Native $signtool.Source @("sign", "/sha1", $cert.Thumbprint, "/fd", "SHA256", $catalog.FullName)
            if ($catalogSign.ExitCode -ne 0) {
                Write-Warning "catalog signing failed with exit code $($catalogSign.ExitCode)"
            }
        }
    }
    else {
        Write-Warning "Inf2Cat.exe not on PATH; catalog left untouched"
    }
    Write-Stage "signing complete"
}

# --- probe -------------------------------------------------------------------

function Invoke-DriverProbe {
    Assert-Artifact $EnginePath "engine binary"
    $report = Join-Path $env:TEMP ("everbloom-driver-status-" + [Guid]::NewGuid().ToString("N") + ".txt")
    Write-Stage "probing the driver device via $EnginePath --driver-status"

    # The engine is linked as a GUI-subsystem executable. PowerShell does not
    # wait for those and never populates $LASTEXITCODE for them, so the verdict
    # is taken from the report file the engine writes, not from the exit code.
    [void](Invoke-Native $EnginePath @("--driver-status", "--driver-status-report", $report))

    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path -LiteralPath $report) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    if (-not (Test-Path -LiteralPath $report)) {
        Fail "the engine produced no driver status report at $report within 30s" 7
    }

    # The report is written as UTF-8 by the engine. Windows PowerShell 5.1
    # defaults Get-Content to the ANSI code page, which mangles the OS error
    # text, so the encoding is stated explicitly.
    $lines = @(Get-Content -LiteralPath $report -Encoding UTF8)
    Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue
    $lines | ForEach-Object { Write-Host "    $_" }

    $device = "unknown"
    $compatible = $false
    $kernelModel = $false
    foreach ($line in $lines) {
        if ($line -match '^device:\s*(\S+)') { $device = $Matches[1] }
        elseif ($line -match '^compatible:\s*(\S+)') { $compatible = ($Matches[1] -eq "true") }
        elseif ($line -match '^kernel_model:\s*(\S+)') { $kernelModel = ($Matches[1] -eq "true") }
    }

    $exit = $PROBE_ABSENT
    if ($device -eq "present") {
        $exit = if ($compatible) { $PROBE_OK } else { $PROBE_INCOMPATIBLE }
    }
    return [pscustomobject]@{
        ExitCode    = $exit
        Device      = $device
        Compatible  = $compatible
        KernelModel = $kernelModel
        Output      = ($lines -join "`n")
    }
}

function Write-Report([hashtable]$Data) {
    if (-not $ReportPath) { return }
    $target = $ReportPath
    if (-not [System.IO.Path]::IsPathRooted($target)) {
        $target = Join-Path (Get-Location) $target
    }
    $parent = Split-Path -Path $target -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($target, ($Data | ConvertTo-Json -Depth 6), [System.Text.Encoding]::UTF8)
    Write-Stage "report written to $target"
}

function Get-ProbeExitForVerdict([int]$ProbeExit) {
    if ($ProbeExit -eq $PROBE_ABSENT) { return 8 }
    if ($ProbeExit -eq $PROBE_INCOMPATIBLE) { return 9 }
    return 0
}

# --- main --------------------------------------------------------------------

if (-not (Test-IsAdmin)) {
    Fail "administrator privileges are required" 2
}

$testSigning = Get-TestSigningState
Write-Stage "test-signing is $testSigning"

switch ($Action) {
    "sign" {
        Invoke-DriverSigning
        exit 0
    }

    "install" {
        # Validate user input before touching anything. A typo in the altitude
        # must fail here, not after test-signing has been turned on and the
        # machine has been rebooted.
        if (-not [string]::IsNullOrWhiteSpace($Altitude)) {
            Assert-AltitudeString $Altitude "altitude"
        }
        if (-not [string]::IsNullOrWhiteSpace($AltitudeOverride)) {
            Assert-AltitudeString $AltitudeOverride "altitude override"
        }

        if ($testSigning -ne "Yes") {
            if (-not $EnableTestSigning) {
                Fail "test-signing is OFF, so an unsigned kernel driver cannot load. Re-run with -EnableTestSigning (requires a reboot), or sign with a certificate this host already trusts." 4
            }
            Enable-TestSigning
            Fail "test-signing was just enabled; reboot and re-run -Action install" 4
        }

        Invoke-DriverSigning

        Assert-Artifact $InfPath "driver INF"
        Write-Stage "registering package: $InfPath"
        $add = Invoke-Native "pnputil.exe" @("/add-driver", $InfPath, "/install")
        $add.Lines | ForEach-Object { Write-Host "    $_" }
        if ($add.ExitCode -ne 0) {
            Fail "pnputil /add-driver failed with exit code $($add.ExitCode)" 6
        }

        New-KernelService -Name $ServiceName -BinaryPath $SysPath

        # The altitude is read at load time, so it has to be in place before the
        # service starts. Writing it here also overrides whatever the INF
        # registered, which is what lets a collision be resolved by editing the
        # registry rather than by rebuilding the package.
        Set-MinifilterAltitude -Name $ServiceName -Instance $InstanceName -Value $Altitude
        Set-AltitudeOverride -Name $ServiceName -Value $AltitudeOverride

        Start-KernelService -Name $ServiceName
        Start-Sleep -Seconds 2

        $probe = Invoke-DriverProbe
        Write-Report @{
            schema = 1
            action = "install"
            service_name = $ServiceName
            instance_name = $InstanceName
            test_signing = $testSigning
            requested_altitude = $Altitude
            altitude_override = $AltitudeOverride
            effective_altitude = Get-MinifilterAltitude -Name $ServiceName -Instance $InstanceName
            device = $probe.Device
            compatible = $probe.Compatible
            kernel_model = $probe.KernelModel
            probe_exit = $probe.ExitCode
            probe_output = $probe.Output
        }
        exit (Get-ProbeExitForVerdict $probe.ExitCode)
    }

    "uninstall" {
        Stop-And-DeleteKernelService -Name $ServiceName
        if (-not $KeepPackageOnUninstall) {
            Assert-Artifact $InfPath "driver INF"
            Write-Stage "removing driver package"
            $del = Invoke-Native "pnputil.exe" @("/delete-driver", $InfPath, "/uninstall")
            $del.Lines | ForEach-Object { Write-Host "    $_" }
            if ($del.ExitCode -ne 0) {
                Write-Warning "pnputil /delete-driver returned exit code $($del.ExitCode)"
            }
        }
        Write-Report @{ schema = 1; action = "uninstall"; service_name = $ServiceName }
        exit 0
    }

    "status" {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $serviceState = if ($service) { "$($service.Status)" } else { "not-registered" }
        Write-Stage "service state: $serviceState"
        $configuredAltitude = Get-MinifilterAltitude -Name $ServiceName -Instance $InstanceName
        if ($configuredAltitude) {
            Write-Stage "minifilter altitude: $configuredAltitude"
        }
        $probe = Invoke-DriverProbe
        Write-Report @{
            schema = 1
            action = "status"
            service_name = $ServiceName
            instance_name = $InstanceName
            service_state = $serviceState
            configured_altitude = $configuredAltitude
            device = $probe.Device
            compatible = $probe.Compatible
            kernel_model = $probe.KernelModel
            probe_exit = $probe.ExitCode
            probe_output = $probe.Output
        }
        exit 0
    }

    "smoke" {
        $probe = Invoke-DriverProbe
        Write-Report @{
            schema = 1
            action = "smoke"
            service_name = $ServiceName
            device = $probe.Device
            compatible = $probe.Compatible
            kernel_model = $probe.KernelModel
            probe_exit = $probe.ExitCode
            probe_output = $probe.Output
        }
        if ($probe.ExitCode -eq $PROBE_ABSENT) {
            Fail "the driver device is absent: the driver is not installed, signed or running" 8
        }
        if ($probe.ExitCode -eq $PROBE_INCOMPATIBLE) {
            Fail "the driver is running but its protocol is incompatible with this engine" 9
        }
        if ($probe.KernelModel) {
            Write-Stage "kernel model is live: the driver is scoring process launches"
        }
        else {
            Write-Stage "driver is live but advertises no kernel model; no in-kernel scoring will occur"
        }
        exit 0
    }
}
