#!/usr/bin/env pwsh
# Full EverbloomSecurity installer pipeline:
#   1. (optional) sign the kernel driver package via driver\package\sign_driver.ps1
#   2. stage the freshly signed INF/CAT/SYS into artifacts\package\install\driver
#   3. build the Inno Setup installer (tools\build_installer.ps1)
#
# Driver signing is skipped automatically when:
#   * -SkipDriverSigning is supplied, or
#   * the .sys file does not exist yet, or
#   * -CertificateThumbprint is empty AND no -CertificatePath is supplied.
#
# When signing is requested, the resulting CAT must be present so that the
# install_driver.cmd helper (called by the installer at run time) can load
# the driver on Windows machines that enforce kernel-mode signature checks.

[CmdletBinding()]
param(
    [string]$AppVersion = "0.1.0",
    [string]$IsccPath = "D:\Inno Setup 6\ISCC.exe",
    [string]$SourceDir = "artifacts\package\install",
    [string]$OutputDir = "artifacts\package\output",
    [string]$DriverSys = "",
    [string]$DriverPackageDir = "driver\package",
    [string]$StagedDriverDir = "artifacts\package\install\driver",
    [string]$CertificateThumbprint = "",
    [string]$CertificatePath = "",
    [string]$CertificatePassword = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$SkipDriverSigning,
    [switch]$VerifySignatureOnly,
    [switch]$SkipLanguageBootstrap
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

function Resolve-Absolute([string]$Relative) {
    if ([string]::IsNullOrWhiteSpace($Relative)) { return $null }
    $full = Join-Path $root $Relative
    $resolved = Resolve-Path -LiteralPath $full -ErrorAction SilentlyContinue
    if ($null -eq $resolved) { return $null }
    return $resolved.Path
}

# The driver build output is layout-dependent and the previous default
# ("driver\build\Release\...") did not match the single-config Ninja layout
# this repository actually produces ("driver\build\everbloom_driver.sys").
# Auto-detect instead of hard-coding one of them, so a bare `-Action install`
# does not silently skip signing and then stage a missing .sys.
#
# Resolution order:
#   1. an explicit -DriverSys value (always wins; a typo is reported, not ignored)
#   2. driver\build\...            - Ninja / single-config generator (current default)
#   3. driver\build\Release\...    - MSVC multi-config generator
#   4. driver\build\Debug\...      - MSVC multi-config, debug
#   5. artifacts\driver\bin\...    - legacy artifact drop used by older docs
$DRIVER_SYS_CANDIDATES = @(
    "driver\build\everbloom_driver.sys",
    "driver\build\Release\everbloom_driver.sys",
    "driver\build\Debug\everbloom_driver.sys",
    "artifacts\driver\bin\everbloom_driver.sys"
)

function Resolve-DriverSys([string]$Explicit) {
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        $resolved = Resolve-Absolute $Explicit
        if ($null -eq $resolved) {
            Write-Warning "-DriverSys '$Explicit' does not exist; driver signing will be skipped"
        }
        return $resolved
    }
    foreach ($candidate in $DRIVER_SYS_CANDIDATES) {
        $resolved = Resolve-Absolute $candidate
        if ($null -ne $resolved) { return $resolved }
    }
    return $null
}

# The .iss file references up to 12 .isl files. Inno Setup 6 ships with 9 of
# them pre-installed; ChineseSimplified, ChineseTraditional, and Korean are
# downloaded on demand from the official jrsoftware/issrc repository so the
# installer build does not fail when the operator has a clean Inno Setup
# install. Skip with -SkipLanguageBootstrap when the operator already has
# the .isl files in place (e.g. CI caches) or is offline.
$INNO_LANG_DOWNLOADS = @(
    @{ Name = "ChineseSimplified"; File = "ChineseSimplified.isl" }
    @{ Name = "ChineseTraditional"; File = "ChineseTraditional.isl" }
    @{ Name = "Korean"; File = "Korean.isl" }
)
$INNO_LANG_REPO = "https://raw.githubusercontent.com/jrsoftware/issrc/refs/heads/main/Files/Languages"

function Ensure-InnoSetupLanguages {
    [CmdletBinding()]
    param(
        [string]$IsccPath,
        [hashtable[]]$Downloads,
        [string]$RepoBase
    )
    $innoRoot = Split-Path -Path $IsccPath -Parent
    $langDir = Join-Path $innoRoot "Languages"
    if (-not (Test-Path -LiteralPath $langDir)) {
        New-Item -ItemType Directory -Path $langDir -Force | Out-Null
    }
    $results = @()
    foreach ($entry in $Downloads) {
        $dest = Join-Path $langDir $entry.File
        if (Test-Path -LiteralPath $dest) {
            $results += [pscustomobject]@{ Name = $entry.Name; Status = "present"; Path = $dest }
            continue
        }
        $url = "$RepoBase/$($entry.File)"
        try {
            Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            $size = (Get-Item $dest).Length
            $results += [pscustomobject]@{ Name = $entry.Name; Status = "downloaded"; Path = $dest; Bytes = $size }
        }
        catch {
            $results += [pscustomobject]@{ Name = $entry.Name; Status = "failed"; Error = $_.Exception.Message }
        }
    }
    return $results
}

$resolvedSys = Resolve-DriverSys $DriverSys
$resolvedPkg = Resolve-Absolute $DriverPackageDir
$resolvedStage = Resolve-Absolute $StagedDriverDir

if (-not (Test-Path -LiteralPath $resolvedStage)) {
    New-Item -ItemType Directory -Path $resolvedStage -Force | Out-Null
}

$signingAttempted = $false
$signingSucceeded = $false
$signingMessage = "driver signing skipped"

if ($SkipDriverSigning) {
    $signingMessage = "driver signing skipped (-SkipDriverSigning)"
}
elseif ([string]::IsNullOrEmpty($resolvedSys) -or -not (Test-Path -LiteralPath $resolvedSys)) {
    $signingMessage = "driver signing skipped (no driver .sys found in any of: $($DRIVER_SYS_CANDIDATES -join ', '); build the driver first)"
}
elseif ([string]::IsNullOrWhiteSpace($CertificateThumbprint) -and [string]::IsNullOrWhiteSpace($CertificatePath)) {
    $signingMessage = "driver signing skipped (no certificate thumbprint or path supplied; only Inf2Cat catalog was generated)"
}
else {
    $signingAttempted = $true
    $signScript = Join-Path $root "driver\package\sign_driver.ps1"
    $signArgs = @{
        DriverPath       = $resolvedSys
        PackageDirectory = $resolvedPkg
        TimestampUrl     = $TimestampUrl
        VerifyOnly       = [bool]$VerifySignatureOnly
    }
    if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        $signArgs.CertificateThumbprint = $CertificateThumbprint
    }

    Write-Host "Signing driver package via $signScript"
    & $signScript @signArgs
    if ($LASTEXITCODE -eq 0) {
        $signingSucceeded = $true
        $signingMessage = "driver signed and verified"
    }
    else {
        throw "sign_driver.ps1 failed with exit code $LASTEXITCODE"
    }
}

# Stage the signed catalog + binary into the install tree, otherwise the
# installer will ship an unsigned driver. Always copy the INF, then the
# CAT/SYS if they exist in the driver package directory.
$infSrc = Join-Path $resolvedPkg "everbloom_driver.inf"
$catSrc = Get-ChildItem -LiteralPath $resolvedPkg -Filter "*.cat" -ErrorAction SilentlyContinue | Select-Object -First 1
$sysSrc = $resolvedSys

if (-not [string]::IsNullOrEmpty($infSrc) -and (Test-Path -LiteralPath $infSrc)) {
    Copy-Item -Force $infSrc (Join-Path $resolvedStage "everbloom_driver.inf")
}
if ($catSrc) {
    Copy-Item -Force $catSrc.FullName (Join-Path $resolvedStage $catSrc.Name)
}
if (-not [string]::IsNullOrEmpty($sysSrc) -and (Test-Path -LiteralPath $sysSrc)) {
    Copy-Item -Force $sysSrc (Join-Path $resolvedStage "everbloom_driver.sys")
}
Write-Host "Driver stage: $resolvedStage"
Get-ChildItem -LiteralPath $resolvedStage | ForEach-Object { "  - $($_.Name) ($($_.Length) bytes)" }

# Make sure the .isl files referenced by the .iss are present.
$languageStatus = $null
if ($SkipLanguageBootstrap) {
    $languageStatus = @(@{ skipped = $true })
}
else {
    Write-Host "Bootstrapping Inno Setup language files (skip with -SkipLanguageBootstrap)..."
    $languageStatus = Ensure-InnoSetupLanguages -IsccPath $IsccPath -Downloads $INNO_LANG_DOWNLOADS -RepoBase $INNO_LANG_REPO
    foreach ($entry in $languageStatus) {
        $name = $entry.Name
        $status = $entry.Status
        $extra = ""
        if ($entry.Bytes) { $extra = " ($($entry.Bytes) bytes)" }
        if ($entry.Error) { $extra = " - error: $($entry.Error)" }
        Write-Host ("  language {0}: {1}{2}" -f $name, $status, $extra)
    }
    if ($languageStatus | Where-Object { $_.Status -eq "failed" }) {
        throw "Failed to download one or more Inno Setup language files; rerun with -SkipLanguageBootstrap if you are offline."
    }
}

# Build the installer.
$installerScript = Join-Path $PSScriptRoot "build_installer.ps1"
$installerArgs = @{
    AppVersion = $AppVersion
    IsccPath   = $IsccPath
    SourceDir  = $SourceDir
    OutputDir  = $OutputDir
}
& $installerScript @installerArgs
if ($LASTEXITCODE -ne 0) {
    throw "build_installer.ps1 failed with exit code $LASTEXITCODE"
}

$installerPath = Join-Path (Join-Path $root $OutputDir) "EverbloomSecurity-$AppVersion-Windows-Setup.exe"
$reportPath = Join-Path (Join-Path $root $OutputDir) "build-report.json"

$report = [ordered]@{
    schema          = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    app_version     = $AppVersion
    installer       = $installerPath
    driver_signing  = [ordered]@{
        attempted = $signingAttempted
        succeeded = $signingSucceeded
        message   = $signingMessage
        certificate_thumbprint = $CertificateThumbprint
        certificate_path       = $CertificatePath
        timestamp_url          = $TimestampUrl
        driver_sys             = $resolvedSys
        driver_sys_candidates  = $DRIVER_SYS_CANDIDATES
    }
    languages       = $languageStatus
}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Host "Build report: $reportPath"
