# Cyber Hashira - Automated Windows Installer Script
# Installs Cyber Hashira into %LOCALAPPDATA%\Programs\Cyber-Hashira, creates Desktop and Start Menu shortcuts,
# and registers the command in the User PATH.

$ErrorActionPreference = "Stop"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "CYBER HASHIRA - Windows System Installer" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Cyan

$SourceDir = Split-Path -Parent $PSScriptRoot
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Cyber-Hashira"
$DesktopDir = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$StartMenuDir = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Programs)) "Cyber Hashira"

Write-Host "[*] Source Repository : $SourceDir" -ForegroundColor Yellow
Write-Host "[*] Target Directory  : $InstallDir" -ForegroundColor Yellow

# 1. Check or locate binary
$SourceExe = Join-Path $SourceDir "cyber-hashira.exe"
if (-not (Test-Path $SourceExe)) {
    Write-Host "[*] Standalone executable not found in root. Looking in dist..." -ForegroundColor Yellow
    $DistExe = Join-Path $SourceDir "dist\cyber-hashira.exe"
    if (Test-Path $DistExe) {
        Copy-Item -Path $DistExe -Destination $SourceExe -Force
    } else {
        Write-Error "cyber-hashira.exe not found! Please build it first via PyInstaller."
    }
}

# 2. Create Target Directory
Write-Host "[+] Preparing installation directory: $InstallDir" -ForegroundColor Cyan
if (-not (Test-Path $InstallDir)) {
    New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
}

# 3. Copy Core Executable and Directories
Write-Host "[*] Copying core application binary..." -ForegroundColor Gray
Copy-Item -Path $SourceExe -Destination (Join-Path $InstallDir "cyber-hashira.exe") -Force

Write-Host "[*] Copying module registry and definitions..." -ForegroundColor Gray
Copy-Item -Path (Join-Path $SourceDir "registry") -Destination $InstallDir -Recurse -Force

Write-Host "[*] Copying 260 certified attack and defense modules..." -ForegroundColor Gray
Copy-Item -Path (Join-Path $SourceDir "modules") -Destination $InstallDir -Recurse -Force

Write-Host "[*] Copying web dashboards and assets..." -ForegroundColor Gray
Copy-Item -Path (Join-Path $SourceDir "ui") -Destination $InstallDir -Recurse -Force

Write-Host "[*] Copying documentation and references..." -ForegroundColor Gray
if (Test-Path (Join-Path $SourceDir "docs")) {
    Copy-Item -Path (Join-Path $SourceDir "docs") -Destination $InstallDir -Recurse -Force
}
if (Test-Path (Join-Path $SourceDir "README.md")) {
    Copy-Item -Path (Join-Path $SourceDir "README.md") -Destination $InstallDir -Force
}
if (Test-Path (Join-Path $SourceDir "README.fa.md")) {
    Copy-Item -Path (Join-Path $SourceDir "README.fa.md") -Destination $InstallDir -Force
}

# 4. Create local state folders
$StateFolders = @("evidence_vault", "reports", "logs")
foreach ($folder in $StateFolders) {
    $targetFolder = Join-Path $InstallDir $folder
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
    }
}

# 5. Create Desktop Shortcut
Write-Host "[+] Creating Desktop Shortcut..." -ForegroundColor Cyan
$WshShell = New-Object -ComObject WScript.Shell
$DesktopShortcutPath = Join-Path $DesktopDir "Cyber Hashira.lnk"
$Shortcut = $WshShell.CreateShortcut($DesktopShortcutPath)
$Shortcut.TargetPath = Join-Path $InstallDir "cyber-hashira.exe"
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.Description = "Cyber Hashira - Modular Cybersecurity Workstation"
$Shortcut.Save()
Write-Host "    -> $DesktopShortcutPath" -ForegroundColor Green

# 6. Create Start Menu Shortcut
Write-Host "[+] Creating Start Menu Shortcut..." -ForegroundColor Cyan
if (-not (Test-Path $StartMenuDir)) {
    New-Item -Path $StartMenuDir -ItemType Directory -Force | Out-Null
}
$StartMenuShortcutPath = Join-Path $StartMenuDir "Cyber Hashira.lnk"
$StartShortcut = $WshShell.CreateShortcut($StartMenuShortcutPath)
$StartShortcut.TargetPath = Join-Path $InstallDir "cyber-hashira.exe"
$StartShortcut.WorkingDirectory = $InstallDir
$StartShortcut.Description = "Cyber Hashira - Modular Cybersecurity Workstation"
$StartShortcut.Save()
Write-Host "    -> $StartMenuShortcutPath" -ForegroundColor Green

# 7. Add to User PATH
Write-Host "[+] Configuring User Environment PATH..." -ForegroundColor Cyan
try {
    $UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        $NewUserPath = if ([string]::IsNullOrEmpty($UserPath)) { $InstallDir } else { "$UserPath;$InstallDir" }
        [System.Environment]::SetEnvironmentVariable("PATH", $NewUserPath, "User")
        $env:PATH += ";$InstallDir"
        Write-Host "    -> Successfully added $InstallDir to User PATH." -ForegroundColor Green
    } else {
        Write-Host "    -> $InstallDir is already present in User PATH." -ForegroundColor Gray
    }
} catch {
    Write-Host "[!] Warning: Unable to update User PATH: $_" -ForegroundColor Yellow
}

# 8. Copy Uninstaller
$UninstallScript = Join-Path $InstallDir "uninstall.ps1"
if (Test-Path (Join-Path $PSScriptRoot "uninstall_windows.ps1")) {
    Copy-Item -Path (Join-Path $PSScriptRoot "uninstall_windows.ps1") -Destination $UninstallScript -Force
}

Write-Host "========================================================================" -ForegroundColor Green
Write-Host "INSTALLATION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "Desktop Icon   : Cyber Hashira" -ForegroundColor White
Write-Host "Start Menu     : Start > Cyber Hashira" -ForegroundColor White
Write-Host "Terminal CLI   : cyber-hashira.exe --help" -ForegroundColor White
Write-Host "Installed Path : $InstallDir" -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Green
