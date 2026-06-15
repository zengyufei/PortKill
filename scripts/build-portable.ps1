$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$srcTauri = Join-Path $root 'src-tauri'
$dist = Join-Path $root 'dist'
$portable = Join-Path $dist 'portKill-portable'
$zip = Join-Path $dist 'portKill-windows-x64-portable.zip'
$vcvars = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat'

if (!(Test-Path $vcvars)) {
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat'
}

if (!(Test-Path $vcvars)) {
    throw '未找到 vcvars64.bat。请安装 Visual Studio Build Tools 或在 Developer PowerShell 中运行。'
}

powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'generate-icon.ps1')

Push-Location $srcTauri
try {
    $hasTauri = $false
    cmd /c "`"$vcvars`" && cargo tauri --version"
    if ($LASTEXITCODE -eq 0) {
        $hasTauri = $true
    }

    cmd /c "`"$vcvars`" && cargo test"
    if ($LASTEXITCODE -ne 0) { throw 'cargo test failed' }

    cmd /c "`"$vcvars`" && cargo build --release --bin portKill-cli"
    if ($LASTEXITCODE -ne 0) { throw 'CLI build failed' }

    if ($hasTauri) {
        cmd /c "`"$vcvars`" && cargo tauri build --no-bundle"
        if ($LASTEXITCODE -ne 0) { throw 'Tauri build failed' }
    }
    else {
        Write-Host 'cargo-tauri 不可用，改用 cargo build --release --bin portKill 生成便携 GUI exe。'
        cmd /c "`"$vcvars`" && cargo build --release --bin portKill"
        if ($LASTEXITCODE -ne 0) { throw 'GUI build failed' }
    }
}
finally {
    Pop-Location
}

New-Item -ItemType Directory -Force -Path $portable | Out-Null
Copy-Item -LiteralPath (Join-Path $srcTauri 'target\release\portKill.exe') -Destination (Join-Path $portable 'portKill.exe') -Force
Copy-Item -LiteralPath (Join-Path $srcTauri 'target\release\portKill-cli.exe') -Destination (Join-Path $portable 'portKill-cli.exe') -Force

@'
portKill portable package

Files:
- portKill.exe: GUI version.
- portKill-cli.exe: command line version.

CLI:
  portKill-cli list [--json] [--protocol tcp|udp|all] [--state LISTENING] [--query text] [--listeners-only]
  portKill-cli find --port <port> [--json]
  portKill-cli kill --pid <pid> [--yes]

Safety:
- This tool does not run in the background.
- This tool does not touch firewall rules.
- This tool does not auto-kill processes.
- PID 0, PID 4, and portKill itself are protected.
'@ | Set-Content -LiteralPath (Join-Path $portable 'README.txt') -Encoding UTF8

if (Test-Path $zip) {
    Remove-Item -LiteralPath $zip -Force
}
$portableFiles = Get-ChildItem -LiteralPath $portable -Force
Compress-Archive -LiteralPath $portableFiles.FullName -DestinationPath $zip -Force

Write-Host "Portable package: $zip"
