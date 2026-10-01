#!/usr/bin/env pwsh
# Build the EverbloomSecurity Windows installer via the local Inno Setup 6 (ISCC.exe).
#
# Usage:
#   pwsh tools/build_installer.ps1                      # default version + dirs
#   pwsh tools/build_installer.ps1 -AppVersion 0.1.0
#   pwsh tools/build_installer.ps1 -IsccPath "D:\Inno Setup 6\ISCC.exe"
#
# This script intentionally:
#   1. Validates the install/ staging tree exists and is non-empty.
#   2. Removes the orphan everbloom_engine.exe that earlier ZIPs accumulated at
#      install/ root (so the installer does not copy it into {pf}\EverbloomSecurity\).
#   3. Refreshes install/doc/ from the canonical README.md and
#      docs/SANDBOX_SECURITY.md, because installer.iss packages doc\* with
#      recursesubdirs and cmake --install never writes that directory.
#   4. Refuses to build when any staged file still contains the pre-rename
#      product name (case-insensitive, raw-byte scan - ONNX metadata hides it
#      behind protobuf length prefixes and plain text search misses it).
#   5. Invokes ISCC.exe with AppVersion / SourceDir / OutputDir overrides so
#      the same .iss can be reused from CI without rewriting the file.
#   6. Prints the produced installer path + size for the calling script.

[CmdletBinding()]
param(
    [string]$AppVersion = "0.1.0",
    [string]$IsccPath = "D:\Inno Setup 6\ISCC.exe",
    [string]$SourceDir = "artifacts\package\install",
    [string]$OutputDir = "artifacts\package\output"
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

$sourcePath = Join-Path $root $SourceDir
$outputPath = Join-Path $root $OutputDir
if (-not (Test-Path -LiteralPath $sourcePath)) {
    throw "Source staging tree not found: $sourcePath (run the package build first)"
}
if (-not (Test-Path -LiteralPath $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

# Drop the orphan everbloom_engine.exe that ended up at install/ root from
# earlier ad-hoc packaging runs. Anything bin\ is left alone.
$orphan = Join-Path $sourcePath "everbloom_engine.exe"
if (Test-Path -LiteralPath $orphan) {
    Write-Host "Removing orphan installer payload: $orphan"
    Remove-Item -LiteralPath $orphan -Force
}

# installer.iss packages "{SourceDir}\doc\*" with recursesubdirs, and ISCC
# fails the compile outright when that pattern matches nothing. The directory
# is NOT produced by `cmake --install` - the CMake rule at CMakeLists.txt
# installs documentation to CMAKE_INSTALL_DOCDIR (share\doc\EverbloomSecurity\)
# instead - so install\doc\ only ever existed because an earlier layout put it
# there. Left alone it silently goes stale: the 2026-10-01 rename produced an
# installer that would have shipped an 2026-08-29 README still headed
# "# HeliosAV". Refresh it from the same canonical files CMake installs, so the
# two documentation locations can never disagree again.
$docDir = Join-Path $sourcePath "doc"
$docSources = @{
    (Join-Path $root "README.md")                  = (Join-Path $docDir "README.md")
    (Join-Path $root "docs\SANDBOX_SECURITY.md")   = (Join-Path $docDir "SANDBOX_SECURITY.md")
}
if (-not (Test-Path -LiteralPath $docDir)) {
    New-Item -ItemType Directory -Path $docDir -Force | Out-Null
}
foreach ($entry in $docSources.GetEnumerator()) {
    $from = $entry.Key
    $to = $entry.Value
    if (-not (Test-Path -LiteralPath $from)) {
        throw "Documentation source missing: $from"
    }
    Copy-Item -LiteralPath $from -Destination $to -Force
    Write-Host "Synced documentation: $(Split-Path -Leaf $to)"
}

# Gate on pre-rename residue. The rename rewrote the source tree, but binaries
# and generated documentation carry the old product name in *metadata* rather
# than in their file names, so a file-name check is not enough. Model metadata
# in particular hides the old name behind protobuf length prefixes, which is
# why a plain text search can miss it entirely. Scan raw bytes, case
# insensitively, and refuse to build an installer that would ship it.
# Remediation for models: tools/sanitize_onnx_metadata.py.
$residuePattern = "helios"
$latin1 = [System.Text.Encoding]::GetEncoding(28591)
$residue = @()
foreach ($file in Get-ChildItem -LiteralPath $sourcePath -Recurse -File -ErrorAction SilentlyContinue) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    }
    catch {
        continue
    }
    if ($latin1.GetString($bytes).IndexOf($residuePattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $residue += $file.FullName.Substring($sourcePath.Length).TrimStart('\')
    }
}
if ($residue.Count -gt 0) {
    Write-Host ""
    Write-Host "Refusing to build: $($residue.Count) staged file(s) still carry the pre-rename name '$residuePattern'."
    foreach ($item in $residue) { Write-Host "  - $item" }
    Write-Host "Models can be fixed with: python tools\sanitize_onnx_metadata.py <path>"
    throw "pre-rename residue in the installer staging tree"
}
Write-Host "Residue gate: no '$residuePattern' found under $SourceDir"

# The staging tree is now validated and normalised; only now do we require the
# compiler. Keeping this check last means the hygiene steps above still run
# (and still fail loudly) on a machine without Inno Setup installed.
if (-not (Test-Path -LiteralPath $IsccPath)) {
    throw "ISCC.exe not found: $IsccPath (point -IsccPath at the local Inno Setup 6 install)"
}

$issPath = Join-Path $PSScriptRoot "installer.iss"
$expectedName = "EverbloomSecurity-$AppVersion-Windows-Setup.exe"
$expectedPath = Join-Path $outputPath $expectedName

Write-Host "Compiling Inno Setup installer: $issPath"
Write-Host "  Source: $sourcePath"
Write-Host "  Output: $expectedPath"

# /Q = quiet (no GUI). /O- = mirror console output. Use double-quoted args so
# paths with spaces (e.g. "D:\Inno Setup 6\ISCC.exe") survive PowerShell's
# argument parsing.
$isccArgs = @(
    "/Q"
    "/DAppVersion=$AppVersion"
    "/DSourceDir=$SourceDir"
    "/DOutputDir=$OutputDir"
    "`"$issPath`""
)
& $IsccPath @isccArgs
if ($LASTEXITCODE -ne 0) {
    throw "ISCC.exe exited with code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $expectedPath)) {
    throw "ISCC reported success but $expectedPath was not produced"
}

$file = Get-Item $expectedPath
Write-Host ""
Write-Host "Installer built: $($file.FullName) ($([math]::Round($file.Length / 1MB, 2)) MB)"
