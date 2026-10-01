[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DriverPath,

    [string]$PackageDirectory = $PSScriptRoot,

    [string]$CertificateThumbprint,

    [string]$TimestampUrl = "http://timestamp.digicert.com",

    [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-Tool([string]$Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "Tool not found: $Name. Run this script from a WDK/Visual Studio developer command prompt."
    }
    return $command.Source
}

$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$driver = (Resolve-Path -LiteralPath $DriverPath).Path
$inf = Join-Path $package "everbloom_driver.inf"
$stagedDriver = Join-Path $package "everbloom_driver.sys"

if (-not (Test-Path -LiteralPath $inf)) {
    throw "INF not found: $inf"
}

if ($driver -ne $stagedDriver) {
    Copy-Item -LiteralPath $driver -Destination $stagedDriver -Force
}

$inf2cat = Resolve-Tool "Inf2Cat.exe"
$signtool = Resolve-Tool "signtool.exe"

if (-not $VerifyOnly) {
    & $inf2cat "/driver:$package" "/os:10_X64"
    if ($LASTEXITCODE -ne 0) {
        throw "Inf2Cat failed with exit code $LASTEXITCODE"
    }

    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        Write-Warning "No certificate thumbprint supplied; CAT was generated but not signed."
    }
    else {
        $catalog = Get-ChildItem -LiteralPath $package -Filter "*.cat" |
            Select-Object -First 1
        if ($null -eq $catalog) {
            throw "Inf2Cat did not generate a CAT file."
        }
        & $signtool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $catalog.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "signtool sign failed with exit code $LASTEXITCODE"
        }
    }
}

$catalog = Get-ChildItem -LiteralPath $package -Filter "*.cat" |
    Select-Object -First 1
if ($null -eq $catalog) {
    throw "CAT file not found; cannot verify the driver package."
}

& $signtool verify /kp /c $catalog.FullName $stagedDriver
if ($LASTEXITCODE -ne 0) {
    throw "Kernel-mode signature verification failed with exit code $LASTEXITCODE"
}

Write-Host "Driver package verification passed: $package"
