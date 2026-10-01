# Build script for native Python extension using maturin
# Run this from a Developer PowerShell where `cl` and cargo are available.

param(
    [switch] $Release = $true,
    [string] $Features = "with_yara"
)

if ($Release) {
    $args = "develop --release --cargo-extra-args=\"--features $Features\""
} else {
    $args = "develop --cargo-extra-args=\"--features $Features\""
}

python -m maturin $args
