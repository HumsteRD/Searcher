# Сборка установщика Threat Scanner:
#   powershell -ExecutionPolicy Bypass -File tools/package.ps1
# Собирает Release, раскладывает нужные файлы в dist/ThreatScanner
# (без тестовых утилит и .pdb) и собирает установщик в release/.

$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build/Release'
$dist  = Join-Path $root 'dist/ThreatScanner'

# CMake: из PATH, иначе тот, что идёт с Visual Studio или Build Tools
# (путь зависит от версии и редакции — спрашиваем у vswhere).
$cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
if (-not $cmake) {
    $vswhere = "${env:ProgramFiles(x86)}/Microsoft Visual Studio/Installer/vswhere.exe"
    if (Test-Path $vswhere) {
        $vs = & $vswhere -latest -products * -property installationPath
        $candidate = Join-Path $vs 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
        if (Test-Path $candidate) { $cmake = $candidate }
    }
}
if (-not $cmake) { throw 'CMake is not found: install Visual Studio (or Build Tools) with the C++ workload' }

$iscc = @("$env:LOCALAPPDATA/Programs/Inno Setup 6/ISCC.exe",
          "${env:ProgramFiles(x86)}/Inno Setup 6/ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 is not installed' }

# Версия задаётся в одном месте — в CMakeLists.txt.
$match = Select-String -Path (Join-Path $root 'CMakeLists.txt') -Pattern 'project\(ThreatScanner VERSION ([0-9.]+)'
$version = $match.Matches[0].Groups[1].Value
Write-Host "Version $version"

& $cmake --build (Join-Path $root 'build') --config Release --target ThreatScanner ThreatHelper ThreatService ThreatAgent
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Force $dist | Out-Null

$programs = @('ThreatScanner.exe', 'ThreatHelper.exe', 'ThreatService.exe', 'ThreatAgent.exe')
foreach ($f in $programs) { Copy-Item (Join-Path $build $f) $dist }

# Библиотеки Qt, OpenSSL и зависимости, которые сборка кладёт рядом с exe.
Get-ChildItem $build -Filter '*.dll' | ForEach-Object { Copy-Item $_.FullName $dist }

# Плагины Qt: окно, https, SVG.
$plugins = @{
    'platforms'    = @('qwindows.dll')
    'tls'          = @('qschannelbackend.dll', 'qopensslbackend.dll', 'qcertonlybackend.dll')
    'imageformats' = @('qsvg.dll', 'qico.dll')
    'iconengines'  = @('qsvgicon.dll')
}
foreach ($dir in $plugins.Keys) {
    $target = Join-Path $dist $dir
    New-Item -ItemType Directory -Force $target | Out-Null
    foreach ($f in $plugins[$dir]) { Copy-Item (Join-Path (Join-Path $build $dir) $f) $target }
}

# Базы сигнатур.
Copy-Item (Join-Path $root 'res/signatures') (Join-Path $dist 'signatures') -Recurse

& $iscc "/DAppVersion=$version" (Join-Path $root 'installer/ThreatScanner.iss')
if ($LASTEXITCODE -ne 0) { throw 'installer build failed' }

$setup = Join-Path $root "release/ThreatScanner-Setup-$version.exe"
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
$size = [math]::Round((Get-Item $setup).Length / 1MB, 1)
Write-Host "Installer: $setup ($size MB)"
Write-Host "SHA-256: $hash"
Set-Content -Path "$setup.sha256" -Value "$hash  ThreatScanner-Setup-$version.exe" -Encoding ascii
