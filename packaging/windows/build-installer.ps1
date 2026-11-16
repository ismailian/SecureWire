# Builds dist\securewire-v<version>-windows-x86_64-setup.exe with Inno Setup 6.
# Run from anywhere after: cargo build --release -p securewire
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."
$version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$iscc = @(
    (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source,
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 (ISCC.exe) not found' }
if (-not (Test-Path "$root\target\release\securewire.exe")) { throw 'build first: cargo build --release -p securewire' }
& $iscc /Q "/DAppVersion=$version" "$PSScriptRoot\securewire.iss"
if ($LASTEXITCODE) { throw "ISCC failed ($LASTEXITCODE)" }
Get-Item "$root\dist\securewire-v$version-windows-x86_64-setup.exe"
