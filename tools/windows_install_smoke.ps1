# Runs on a disposable GitHub-hosted Windows runner, under the current user.
# Validates actual silent installation, the packaged binary, and uninstallation.
# Never launches a network scan or modifies the real per-user BLOODSKY database.
$ErrorActionPreference = 'Stop'
$setup = (Resolve-Path 'installer\output\BLOODSKY-NET-Setup-0.9.0-rc1.exe').Path
$dir = Join-Path $env:TEMP 'BLOODSKY-NET-Install-Smoke'
$exe = Join-Path $dir 'BLOODSKY-NET.exe'
$uninstaller = Join-Path $dir 'unins000.exe'
$dataDir = Join-Path $env:LOCALAPPDATA 'BLOODSKY-NET'
$sentinel = Join-Path $dataDir 'ci-uninstall-preserve.txt'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runValue = 'BLOODSKY NET'
$unrelatedName = 'BLOODSKY-NET-CI-Unrelated'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
if (Test-Path $sentinel) { throw 'Unexpected existing smoke sentinel' }
Set-Content -Path $sentinel -Value 'keep user data after uninstall' -Encoding ascii
try {
    $install = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=$dir") -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw "Installer exit: $($install.ExitCode)" }
    if (-not (Test-Path $exe)) { throw 'Installed EXE missing' }
    if (-not (Test-Path $uninstaller)) { throw 'Uninstaller missing' }

    # The --self-check mode checks imports and local SQLite without a GUI.
    $check = Start-Process -FilePath $exe -ArgumentList @('--self-check') -Wait -PassThru
    if ($check.ExitCode -ne 0) { throw "Installed EXE self-check exit: $($check.ExitCode)" }

    # Simulate an opt-in autostart entry; the uninstall must clean *only ours*.
    New-Item -Path $runKey -Force | Out-Null
    New-ItemProperty -Path $runKey -Name $runValue -PropertyType String -Value "`"$exe`" --minimized" -Force | Out-Null
    New-ItemProperty -Path $runKey -Name $unrelatedName -PropertyType String -Value 'keep-other-entry' -Force | Out-Null
    $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -Wait -PassThru
    if ($uninstall.ExitCode -ne 0) { throw "Uninstaller exit: $($uninstall.ExitCode)" }
    if (Test-Path $exe) { throw 'Uninstalled EXE still exists' }
    $registry = Get-ItemProperty -Path $runKey
    if ($registry.PSObject.Properties.Name -contains $runValue) { throw 'Owned autostart entry not removed' }
    if ($registry.$unrelatedName -ne 'keep-other-entry') { throw 'Unrelated autostart entry changed' }
    if (-not (Test-Path $sentinel)) { throw 'User-data sentinel removed by uninstaller' }
    Write-Host 'Windows install/EXE self-check/uninstall smoke PASSED'
} finally {
    if (Test-Path $sentinel) { Remove-Item -Force $sentinel }
    if (Test-Path $runKey) { Remove-ItemProperty -Path $runKey -Name $unrelatedName -ErrorAction SilentlyContinue }
    # Clean up our own test entry if failure occurred before uninstall.
    if (Test-Path $runKey) { Remove-ItemProperty -Path $runKey -Name $runValue -ErrorAction SilentlyContinue }
}
