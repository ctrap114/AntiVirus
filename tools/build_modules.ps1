[CmdletBinding()]
param(
    [string[]]$Modules = @("all"),
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$RustTarget = "x86_64-pc-windows-msvc",
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot "artifacts"
} else {
    $OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
}

$allModules = @("engine", "libeverbloom_rs", "sandbox_monitor", "gui", "driver")
if ($Modules -contains "all") {
    $Modules = $allModules
}
$unknown = @($Modules | Where-Object { $_ -notin $allModules })
if ($unknown.Count -gt 0) {
    throw "Unknown module(s): $($unknown -join ', '). Valid modules: $($allModules -join ', ')."
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

function Invoke-Tool {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    Write-Host "[$(Split-Path $WorkingDirectory -Leaf)] $FilePath $($ArgumentList -join ' ')"
    Push-Location $WorkingDirectory
    try {
        & $FilePath @ArgumentList
        if ($LASTEXITCODE -ne 0) {
            throw "$FilePath failed with exit code $LASTEXITCODE."
        }
    } finally {
        Pop-Location
    }
}

function Copy-ModuleFiles {
    param(
        [Parameter(Mandatory = $true)][string]$SearchRoot,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][scriptblock]$Filter
    )

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $files = @(Get-ChildItem -LiteralPath $SearchRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object $Filter)
    foreach ($file in $files) {
        Copy-Item -LiteralPath $file.FullName -Destination $Destination -Force
    }
    return $files.Count
}

$manifest = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    configuration = $Configuration
    rust_target = $RustTarget
    output_root = $OutputRoot
    modules = [ordered]@{}
}

$script:MsvcEnvironmentReady = $false

function Initialize-MsvcEnvironment {
    if ($script:MsvcEnvironmentReady) {
        return $true
    }

    $clPath = (Get-Command cl.exe -ErrorAction SilentlyContinue).Source
    if ([string]::IsNullOrWhiteSpace($clPath)) {
        $vcRoots = @(
            $env:VCToolsInstallDir,
            "F:\insiders\VC\Tools\MSVC",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC"
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }

        foreach ($vcRoot in $vcRoots) {
            $candidate = Get-ChildItem -LiteralPath $vcRoot -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending |
                ForEach-Object { Join-Path $_.FullName "bin\HostX64\x64\cl.exe" } |
                Where-Object { Test-Path $_ } |
                Select-Object -First 1
            if ($candidate) {
                $clPath = $candidate
                break
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($clPath)) {
        Write-Warning "MSVC cl.exe was not found; CMake will use its default compiler discovery."
        return $false
    }

    $clBin = Split-Path $clPath -Parent
    $vcRoot = Split-Path (Split-Path (Split-Path $clBin -Parent) -Parent) -Parent
    $sdkRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10",
        "${env:ProgramFiles}\Windows Kits\10"
    ) | Where-Object { Test-Path $_ }
    $sdkRoot = $sdkRoots | Select-Object -First 1
    $sdkVersion = $null
    if ($sdkRoot) {
        $sdkVersion = Get-ChildItem (Join-Path $sdkRoot "Include") -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^10\.\d' } |
            Sort-Object Name -Descending |
            Where-Object { Test-Path (Join-Path $sdkRoot "bin\$($_.Name)\x64\rc.exe") } |
            Select-Object -First 1 -ExpandProperty Name
    }

    if (-not $sdkRoot -or -not $sdkVersion) {
        Write-Warning "Windows SDK was not found; compiler environment is only partially initialized."
        return $false
    }

    $sdkBin = Join-Path $sdkRoot "bin\$sdkVersion\x64"
    $env:PATH = "$clBin;$sdkBin;$env:PATH"
    $env:WindowsSdkDir = "$sdkRoot\"
    $env:WindowsSDKVersion = "$sdkVersion\"
    $env:INCLUDE = "$(Join-Path $vcRoot 'include');$(Join-Path $sdkRoot "Include\$sdkVersion\ucrt");$(Join-Path $sdkRoot "Include\$sdkVersion\shared");$(Join-Path $sdkRoot "Include\$sdkVersion\um")"
    $env:LIB = "$(Join-Path $vcRoot 'lib\x64');$(Join-Path $sdkRoot "Lib\$sdkVersion\ucrt\x64");$(Join-Path $sdkRoot "Lib\$sdkVersion\um\x64")"
    $script:MsvcEnvironmentReady = $true
    Write-Host "MSVC environment: $vcRoot; Windows SDK: $sdkVersion"
    return $true
}

function Get-CMakeGeneratorArguments {
    $ready = Initialize-MsvcEnvironment
    if ($ready -and (Get-Command ninja.exe -ErrorAction SilentlyContinue)) {
        return @("-G", "Ninja", "-DCMAKE_CXX_COMPILER=cl.exe")
    }
    return @()
}

if ($Modules -contains "engine") {
    $moduleRoot = Join-Path $OutputRoot "engine"
    $targetDir = Join-Path $moduleRoot "target"
    $binDir = Join-Path $moduleRoot "bin"
    New-Item -ItemType Directory -Force -Path $moduleRoot, $binDir | Out-Null
    try {
        Invoke-Tool "cargo" @(
            "build", "--manifest-path", (Join-Path $repoRoot "engine\Cargo.toml"),
            "--target-dir", $targetDir, "--target", $RustTarget, "--release"
        ) $repoRoot
        $releaseDir = Join-Path $targetDir "$RustTarget\release"
        $count = Copy-ModuleFiles $releaseDir $binDir {
            $_.Name -in @("everbloom_engine.exe", "everbloom_engine.pdb")
        }
        $manifest.modules.engine = [ordered]@{ status = "success"; target = $targetDir; bin = $binDir; files_copied = $count }
    } catch {
        $manifest.modules.engine = [ordered]@{ status = "failed"; target = $targetDir; bin = $binDir; error = $_.Exception.Message }
        Write-Warning "Module engine failed: $($_.Exception.Message)"
    }
}

if ($Modules -contains "libeverbloom_rs") {
    $moduleRoot = Join-Path $OutputRoot "libeverbloom_rs"
    $targetDir = Join-Path $moduleRoot "target"
    $binDir = Join-Path $moduleRoot "bin"
    New-Item -ItemType Directory -Force -Path $moduleRoot, $binDir | Out-Null
    try {
        Invoke-Tool "cargo" @(
            "build", "--manifest-path", (Join-Path $repoRoot "libeverbloom_rs\Cargo.toml"),
            "--target-dir", $targetDir, "--target", $RustTarget, "--release"
        ) $repoRoot
        $releaseDir = Join-Path $targetDir "$RustTarget\release"
        $count = Copy-ModuleFiles $releaseDir $binDir {
            $_.Name -match "^libeverbloom_rs\.(dll|pdb)$|^libeverbloom_rs\.dll\.(lib|exp)$"
        }
        $manifest.modules.libeverbloom_rs = [ordered]@{ status = "success"; target = $targetDir; bin = $binDir; files_copied = $count }
    } catch {
        $manifest.modules.libeverbloom_rs = [ordered]@{ status = "failed"; target = $targetDir; bin = $binDir; error = $_.Exception.Message }
        Write-Warning "Module libeverbloom_rs failed: $($_.Exception.Message)"
    }
}

if ($Modules -contains "sandbox_monitor") {
    $moduleRoot = Join-Path $OutputRoot "sandbox_monitor"
    $targetDir = Join-Path $moduleRoot "target"
    $binDir = Join-Path $moduleRoot "bin"
    New-Item -ItemType Directory -Force -Path $moduleRoot, $binDir | Out-Null
    try {
        Invoke-Tool "cargo" @(
            "build", "--manifest-path", (Join-Path $repoRoot "sandbox_monitor\Cargo.toml"),
            "--target-dir", $targetDir, "--target", $RustTarget, "--release"
        ) $repoRoot
        $releaseDir = Join-Path $targetDir "$RustTarget\release"
        $count = Copy-ModuleFiles $releaseDir $binDir {
            $_.Name -match "^libsandbox_monitor\.(rlib|rmeta|lib|dll|pdb)$"
        }
        $manifest.modules.sandbox_monitor = [ordered]@{ status = "success"; target = $targetDir; bin = $binDir; files_copied = $count }
    } catch {
        $manifest.modules.sandbox_monitor = [ordered]@{ status = "failed"; target = $targetDir; bin = $binDir; error = $_.Exception.Message }
        Write-Warning "Module sandbox_monitor failed: $($_.Exception.Message)"
    }
}

if ($Modules -contains "gui") {
    $moduleRoot = Join-Path $OutputRoot "gui"
    $buildDir = Join-Path $moduleRoot "cmake-ninja"
    $installDir = Join-Path $moduleRoot "install"
    $binDir = Join-Path $moduleRoot "bin"
    New-Item -ItemType Directory -Force -Path $moduleRoot, $binDir | Out-Null
    try {
        $configureArgs = @(
            "-S", (Join-Path $repoRoot "gui"), "-B", $buildDir
        ) + (Get-CMakeGeneratorArguments) + @(
            "-DEVERBLOOM_VCPKG_TRIPLET=x64-windows",
            "-DEVERBLOOM_GUI_FORCE_STUB=OFF",
            "-DCMAKE_BUILD_TYPE=$Configuration",
            "-DCMAKE_INSTALL_PREFIX=$installDir"
        )
        Invoke-Tool "cmake" $configureArgs $repoRoot
        Invoke-Tool "cmake" @(
            "--build", $buildDir, "--config", $Configuration, "--target", "everbloom_gui"
        ) $repoRoot
        Invoke-Tool "cmake" @(
            "--install", $buildDir, "--config", $Configuration, "--prefix", $installDir
        ) $repoRoot
        $count = Copy-ModuleFiles $buildDir $binDir {
            $_.Name -in @(
                "everbloom_gui.exe",
                "everbloom_gui.pdb",
                "Microsoft.WindowsAppRuntime.Bootstrap.dll"
            )
        }
        $manifest.modules.gui = [ordered]@{ status = "success"; build = $buildDir; install = $installDir; bin = $binDir; files_copied = $count }
    } catch {
        $manifest.modules.gui = [ordered]@{ status = "failed"; build = $buildDir; install = $installDir; bin = $binDir; error = $_.Exception.Message }
        Write-Warning "Module gui failed: $($_.Exception.Message)"
    }
}

if ($Modules -contains "driver") {
    $moduleRoot = Join-Path $OutputRoot "driver"
    $buildDir = Join-Path $moduleRoot "cmake-ninja"
    $binDir = Join-Path $moduleRoot "bin"
    New-Item -ItemType Directory -Force -Path $moduleRoot, $binDir | Out-Null
    try {
        $configureArgs = @(
            "-S", (Join-Path $repoRoot "driver"), "-B", $buildDir
        ) + (Get-CMakeGeneratorArguments) + @(
            "-DCMAKE_BUILD_TYPE=$Configuration",
            "-DBUILD_EVERBLOOM_DRIVER_SYS=ON"
        )
        Invoke-Tool "cmake" $configureArgs $repoRoot
        Invoke-Tool "cmake" @(
            "--build", $buildDir, "--config", $Configuration
        ) $repoRoot
        $count = Copy-ModuleFiles $buildDir $binDir {
            $_.Name -in @("everbloom_driver.sys", "everbloom_driver.pdb", "everbloom_driver_stub.exe", "everbloom_driver_core.lib")
        }
        $manifest.modules.driver = [ordered]@{ status = "success"; build = $buildDir; bin = $binDir; files_copied = $count }
    } catch {
        $manifest.modules.driver = [ordered]@{ status = "failed"; build = $buildDir; bin = $binDir; error = $_.Exception.Message }
        Write-Warning "Module driver failed: $($_.Exception.Message)"
    }
}

$manifestPath = Join-Path $OutputRoot "build-manifest.json"
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "Module build outputs are isolated under: $OutputRoot"
Write-Host "Manifest: $manifestPath"
