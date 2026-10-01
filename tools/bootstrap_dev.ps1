[CmdletBinding()]
param(
    [switch]$InstallRuntimeRequirements
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$venvPath = Join-Path $repoRoot '.venv'

function Invoke-Python {
    param([string[]]$Arguments)
    & $script:pythonCommand @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE"
    }
}

$pythonCommand = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCommand = 'py'
    $pythonPrefix = @('-3')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCommand = 'python'
    $pythonPrefix = @()
} else {
    throw 'Python 3.10 or newer was not found in PATH.'
}

Push-Location $repoRoot
try {
    Write-Host "Recreating $venvPath"
    Invoke-Python ($pythonPrefix + @('-m', 'venv', '--clear', '--copies', '.venv'))

    $venvPython = Join-Path $venvPath 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "The virtual environment was not created: $venvPython"
    }

    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to upgrade pip. Check network access or install pip from the local Python distribution.'
    }
    & $venvPython -m pip install -e '.[test]'
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to install the minimal test environment.'
    }

    if ($InstallRuntimeRequirements) {
        & $venvPython -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to install the optional runtime/training requirements.'
        }
    }

    & $venvPython -m pytest -q
    if ($LASTEXITCODE -ne 0) {
        throw 'Python tests failed.'
    }
} finally {
    Pop-Location
}
