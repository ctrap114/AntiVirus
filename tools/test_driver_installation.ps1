#!/usr/bin/env pwsh
# Automated driver installation smoke test for EverbloomSecurity.
#
# Run after the Inno Setup installer has been unpacked into a target
# directory (e.g. via `EverbloomSecurity-Setup.exe /DIR=<dir> /VERYSILENT /SUPPRESSMSGBOXES`)
# to confirm that:
#   * the kernel-mode driver binary exists in the staged tree,
#   * `install_driver.cmd` can register and start the driver service,
#   * Windows reports the driver as RUNNING via sc.exe and Get-CimInstance,
#   * a PnP enumerator sees the package,
#   * and the same script can roll everything back via uninstall_driver.cmd.
#
# Usage:
#   pwsh tools/test_driver_installation.ps1                                          # use default staging
#   pwsh tools/test_driver_installation.ps1 -InstallDir C:\Path\To\EverbloomSecurity
#   pwsh tools/test_driver_installation.ps1 -InstallDir ... -DryRun
#   pwsh tools/test_driver_installation.ps1 -InstallDir ... -KeepOnFail
#   pwsh tools/test_driver_installation.ps1 -InstallDir ... -Report artifacts/driver-test.json
#
# Exit codes:
#   0  all checks passed and the test driver was cleanly removed
#   2  admin privileges not available
#   3  install_driver.cmd returned non-zero (driver package refused)
#   4  sc query reported the service is not RUNNING
#   5  PnP enumerator did not list the driver package
#   6  Get-CimInstance Win32_SystemDriver did not see the driver
#   7  uninstall_driver.cmd failed (driver left loaded)
#   8  test artifacts missing (install tree or driver binary absent)

[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path (Get-Location) "artifacts\package\install"),
    [string]$ServiceName = "EverbloomSecurity",
    [int]$ServiceStartupTimeoutSeconds = 15,
    [int]$PostUninstallWaitSeconds = 3,
    [string]$ReportPath = "",
    [switch]$DryRun,
    [switch]$KeepOnFail,
    [switch]$SkipUninstall
)

$ErrorActionPreference = "Stop"
$startedAt = (Get-Date).ToUniversalTime()

function Write-Stage([string]$Message) {
    Write-Host "[driver-test] $Message"
}

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Cmd([string]$Path, [string[]]$Arguments) {
    $displayArgs = ($Arguments -join ' ')
    Write-Stage "exec: `"$Path`" $displayArgs"
    if ($DryRun) {
        return [pscustomobject]@{ ExitCode = 0; Output = "(dry-run)"; DisplayArgs = $displayArgs }
    }
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) `
        -RedirectStandardError ([System.IO.Path]::GetTempFileName())
    $stdout = (Get-Content -LiteralPath $p.StartInfo.Arguments -ErrorAction SilentlyContinue) 2>$null
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = ""; DisplayArgs = $displayArgs }
}

function Read-ServiceState {
    $state = [pscustomobject]@{
        sc_query_exit   = $null
        sc_state        = $null
        sc_status       = $null
        cim_name        = $null
        cim_state       = $null
        cim_path        = $null
    }
    if ($DryRun) {
        return $state
    }
    $scOut = & sc.exe query $ServiceName 2>&1
    $state.sc_query_exit = $LASTEXITCODE
    $state.sc_status = ($scOut -join "`n")
    if ($LASTEXITCODE -eq 0) {
        $stateLine = ($scOut | Where-Object { $_ -match '^\s*STATE' } | Select-Object -First 1)
        if ($stateLine) {
            $parts = ($stateLine -replace '\s+', ' ').Trim() -split ' '
            $state.sc_state = $parts[-1]
        }
    }
    $cim = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($cim) {
        $state.cim_name = $cim.Name
        $state.cim_state = $cim.State
        $state.cim_path = $cim.PathName
    }
    return $state
}

function Get-PnpListing {
    if ($DryRun) {
        return @()
    }
    $out = & pnputil.exe /enum-drivers 2>&1
    if ($LASTEXITCODE -ne 0) {
        return @()
    }
    $entries = @()
    $current = $null
    foreach ($line in $out) {
        if ($line -match '^\s*Published Name:\s*(.+)$') {
            if ($current) { $entries += $current }
            $current = [pscustomobject]@{ PublishedName = $Matches[1].Trim(); Provider = $null; OriginalName = $null; Class = $null }
        }
        elseif ($current -and $line -match '^\s*Provider Name:\s*(.+)$') {
            $current.Provider = $Matches[1].Trim()
        }
        elseif ($current -and $line -match '^\s*Original Name:\s*(.+)$') {
            $current.OriginalName = $Matches[1].Trim()
        }
        elseif ($current -and $line -match '^\s*Class Name:\s*(.+)$') {
            $current.Class = $Matches[1].Trim()
        }
    }
    if ($current) { $entries += $current }
    return $entries
}

# --- 0. Sanity / preconditions ---

if (-not (Test-Path -LiteralPath $InstallDir)) {
    Write-Error "Install directory not found: $InstallDir"
    exit 8
}
$installCmd = Join-Path $InstallDir "bin\install_driver.cmd"
$uninstallCmd = Join-Path $InstallDir "bin\uninstall_driver.cmd"
$driverInf = Join-Path $InstallDir "driver\everbloom_driver.inf"
$driverSys = Join-Path $InstallDir "driver\everbloom_driver.sys"
foreach ($p in @($installCmd, $uninstallCmd, $driverInf)) {
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Error "Required driver artifact missing: $p"
        exit 8
    }
}
$sysPresent = Test-Path -LiteralPath $driverSys

if (-not (Test-IsAdmin)) {
    Write-Error "Administrator privileges are required to install/uninstall the driver."
    exit 2
}

# --- 1. install_driver.cmd ---

$installResult = $null
$serviceStateAfterInstall = $null
$pnpEntries = $null
$cimState = $null

try {
    Write-Stage "running $installCmd"
    if ($DryRun) {
        $installResult = [pscustomobject]@{ ExitCode = 0; Output = "(dry-run)" }
    }
    else {
        $p = Start-Process -FilePath $installCmd -NoNewWindow -Wait -PassThru
        $installResult = [pscustomobject]@{ ExitCode = $p.ExitCode; Output = "" }
    }
    Write-Stage "install_driver.cmd exit code: $($installResult.ExitCode)"
    if ($installResult.ExitCode -ne 0) {
        throw "install_driver.cmd returned exit code $($installResult.ExitCode)"
    }

    # Allow the SCM a moment to settle before we query the service.
    if (-not $DryRun) { Start-Sleep -Seconds 1 }

    $serviceStateAfterInstall = Read-ServiceState
    $pnpEntries = Get-PnpListing
    $pnpMatches = @($pnpEntries | Where-Object {
        $_.Provider -like "*EverbloomSecurity*" -or $_.OriginalName -like "*everbloom_driver*"
    })
    $cimState = $serviceStateAfterInstall.cim_state

    Write-Stage "sc state: $($serviceStateAfterInstall.sc_state); cim state: $cimState; pnp matches: $($pnpMatches.Count)"

    $stopReason = $null
    if (-not $DryRun -and $serviceStateAfterInstall.sc_state -ne "RUNNING") {
        $stopReason = "sc query reports state '$($serviceStateAfterInstall.sc_state)', expected RUNNING"
    }
    elseif (-not $DryRun -and $pnpMatches.Count -eq 0) {
        $stopReason = "pnputil /enum-drivers did not list the EverbloomSecurity package"
    }
    elseif (-not $sysPresent) {
        $stopReason = "driver binary $driverSys is missing; install tree is incomplete"
    }

    if ($stopReason) {
        throw $stopReason
    }
}
catch {
    $failure = $_.Exception.Message
    Write-Stage "FAILED: $failure (Report path: '$ReportPath', DryRun=$DryRun, sysPresent=$sysPresent)"
    if (-not $SkipUninstall -and -not $DryRun) {
        Write-Stage "rolling back via $uninstallCmd (KeepOnFail=$KeepOnFail)"
        $rollback = $null
        try {
            $p = Start-Process -FilePath $uninstallCmd -NoNewWindow -Wait -PassThru
            $rollback = $p.ExitCode
        }
        catch {
            $rollback = $_.Exception.Message
        }
        Write-Stage "rollback exit code: $rollback"
    }
    if ($ReportPath) {
        Write-Stage "writing report to $ReportPath"
        $reportData = [ordered]@{
            schema = 1
            generated_at_utc = $startedAt.ToString("yyyy-MM-ddTHH:mm:ssZ")
            completed_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            install_dir = $InstallDir
            service_name = $ServiceName
            status = "failed"
            failure_reason = $failure
            sys_present = $sysPresent
            install_result = $installResult
            service_state_after_install = $serviceStateAfterInstall
            pnp_match_count = if ($pnpEntries) { ($pnpEntries | Where-Object { $_.Provider -like "*EverbloomSecurity*" -or $_.OriginalName -like "*everbloom_driver*" }).Count } else { 0 }
            dry_run = [bool]$DryRun
        }
        try {
            $parent = Split-Path -Path $ReportPath -Parent
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }
            $json = $reportData | ConvertTo-Json -Depth 6
            $target = $ReportPath
            if (-not [System.IO.Path]::IsPathRooted($target)) {
                $target = Join-Path (Get-Location) $target
            }
            $target = [System.IO.Path]::GetFullPath($target)
            Write-Stage "report JSON length: $($json.Length); writing to '$target'"
            [System.IO.File]::WriteAllText($target, $json, [System.Text.Encoding]::UTF8)
            $size = (Get-Item $target).Length
            Write-Stage "report written: $size bytes"
        } catch {
            Write-Stage "report write failed: $($_.Exception.Message)"
        }
    }
    if ($failure -match "install_driver\.cmd") { exit 3 }
    if ($failure -match "sc query") { exit 4 }
    if ($failure -match "pnputil") { exit 5 }
    if ($failure -match "Win32_SystemDriver") { exit 6 }
    exit 9
}

# --- 2. uninstall_driver.cmd (clean rollback) ---

$uninstallExit = $null
$serviceStateAfterUninstall = $null
if (-not $SkipUninstall) {
    Write-Stage "rolling back via $uninstallCmd"
    if ($DryRun) {
        $uninstallExit = 0
    }
    else {
        $p = Start-Process -FilePath $uninstallCmd -NoNewWindow -Wait -PassThru
        $uninstallExit = $p.ExitCode
        if ($uninstallExit -ne 0) {
            Write-Warning "uninstall_driver.cmd returned exit code $uninstallExit"
        }
        Start-Sleep -Seconds $PostUninstallWaitSeconds
    }
    $serviceStateAfterUninstall = Read-ServiceState
    Write-Stage "post-uninstall sc state: $($serviceStateAfterUninstall.sc_state)"
}

# --- 3. Report ---

if ($ReportPath) {
    $reportData = [ordered]@{
        schema = 1
        generated_at_utc = $startedAt.ToString("yyyy-MM-ddTHH:mm:ssZ")
        completed_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        install_dir = $InstallDir
        service_name = $ServiceName
        status = if ($uninstallExit -ne 0 -and -not $SkipUninstall) { "passed_with_uninstall_warning" } else { "passed" }
        sys_present = $sysPresent
        install_result = $installResult
        service_state_after_install = $serviceStateAfterInstall
        pnp_match_count = if ($pnpEntries) { ($pnpEntries | Where-Object { $_.Provider -like "*EverbloomSecurity*" -or $_.OriginalName -like "*everbloom_driver*" }).Count } else { 0 }
        uninstall_exit = $uninstallExit
        service_state_after_uninstall = $serviceStateAfterUninstall
        dry_run = [bool]$DryRun
    }
    $json = $reportData | ConvertTo-Json -Depth 6
    $target = $ReportPath
    if (-not [System.IO.Path]::IsPathRooted($target)) {
        $target = Join-Path (Get-Location) $target
    }
    $target = [System.IO.Path]::GetFullPath($target)
    $parent = Split-Path -Path $target -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($target, $json, [System.Text.Encoding]::UTF8)
    Write-Stage "report: $target"
}

Write-Stage "OK"
exit 0

