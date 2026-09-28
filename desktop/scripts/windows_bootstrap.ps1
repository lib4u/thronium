<#
.SYNOPSIS
Prepare a Windows machine to build and test Thronium.

.DESCRIPTION
Installs exactly what the application, its core and the checks need, and nothing
else: the MSVC Rust toolchain and Build Tools for the application, Go for the
core (built without cgo), Node, Python, Git, the WebView2 runtime the window renders in,
and the drivers the native suites drive the window with. Run it in an elevated
PowerShell; it is safe to run again, each step is skipped when already present.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File windows_bootstrap.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipBuildTools,
    [switch]$SkipDrivers
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Have($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Install-Winget($id, $probe, $extra = @()) {
    if ($probe -and (Have $probe)) { Write-Host "= $id already present"; return }
    Write-Host "+ installing $id"
    winget install --id $id --exact --silent --accept-package-agreements `
        --accept-source-agreements --disable-interactivity @extra
}

if (-not (Test-Admin)) { throw 'Run this in an elevated PowerShell.' }
if (-not (Have 'winget')) { throw 'winget is required: install App Installer from the Microsoft Store.' }

# The application: Rust (MSVC), its linker, Node and Git.
Install-Winget 'Rustlang.Rustup' 'rustup'
Install-Winget 'OpenJS.NodeJS.LTS' 'node'
Install-Winget 'Git.Git' 'git'
Install-Winget 'Python.Python.3.12' 'python'
# The core: Go. It is built without cgo, so no C compiler is needed for it.
Install-Winget 'GoLang.Go' 'go'
if (-not $SkipBuildTools) {
    # MSVC linker and the Windows SDK the Rust target links against.
    Install-Winget 'Microsoft.VisualStudio.2022.BuildTools' $null @(
        '--override',
        '--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended')
}
# The window: Thronium renders in WebView2, evergreen on Server 2019.
$webview = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
if (-not (Test-Path $webview)) {
    Write-Host '+ installing the WebView2 runtime'
    $installer = Join-Path $env:TEMP 'MicrosoftEdgeWebview2Setup.exe'
    Invoke-WebRequest 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $installer
    & $installer /silent /install | Out-Null
} else { Write-Host '= WebView2 runtime already present' }

if (Have 'rustup') {
    rustup default stable-x86_64-pc-windows-msvc
    rustup component add clippy rustfmt
}
if (-not $SkipDrivers -and (Have 'cargo')) {
    # The native suites drive the window through tauri-driver and msedgedriver.
    if (-not (Have 'tauri-driver')) { cargo install tauri-driver --locked }
}

Write-Host ''
Write-Host 'Installed versions:'
foreach ($tool in 'rustc', 'cargo', 'node', 'npm', 'go', 'python', 'git') {
    if (Have $tool) { Write-Host ("  {0,-24} {1}" -f $tool, (& $tool --version 2>&1 | Select-Object -First 1)) }
    else { Write-Host ("  {0,-24} MISSING" -f $tool) }
}
Write-Host ''
Write-Host 'Next: clone the repository, then'
Write-Host '  npm ci --prefix desktop'
Write-Host '  python3 desktop/scripts/build_core.py      # ThroniumCore sidecar'
Write-Host '  npm run --prefix desktop desktop:build     # the application'
