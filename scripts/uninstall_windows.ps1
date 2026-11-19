# Cyber Hashira - Windows Uninstaller Script
# Removes shortcuts, clears PATH, and removes %LOCALAPPDATA%\Programs\Cyber-Hashira

$ErrorActionPreference = "SilentlyContinue"

Write-Host "========================================================================" -ForegroundColor Yellow
Write-Host "CYBER HASHIRA - Windows System Uninstaller" -ForegroundColor Yellow
Write-Host "========================================================================" -ForegroundColor Yellow

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Cyber-Hashira"
$DesktopShortcut = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)) "Cyber Hashira.lnk"
$StartMenuDir = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Programs)) "Cyber Hashira"

# 1. Remove Desktop Shortcut
if (Test-Path $DesktopShortcut) {
    Remove-Item -Path $DesktopShortcut -Force
    Write-Host "[+] Removed Desktop shortcut." -ForegroundColor Green
}

# 2. Remove Start Menu Shortcut
if (Test-Path $StartMenuDir) {
    Remove-Item -Path $StartMenuDir -Recurse -Force
    Write-Host "[+] Removed Start Menu shortcut." -ForegroundColor Green
}

# 3. Remove from User PATH
try {
    $UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -like "*$InstallDir*") {
        $CleanedPath = ($UserPath.Split(';') | Where-Object { $_ -ne $InstallDir -and $_ -ne "" }) -join ';'
        [System.Environment]::SetEnvironmentVariable("PATH", $CleanedPath, "User")
        Write-Host "[+] Removed $InstallDir from User PATH." -ForegroundColor Green
    }
} catch {
    Write-Host "[!] Could not update User PATH." -ForegroundColor Yellow
}

# 4. Remove Files
if (Test-Path $InstallDir) {
    Write-Host "[*] Removing installation files from $InstallDir..." -ForegroundColor Gray
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "[+] Installation files removed." -ForegroundColor Green
}

Write-Host "========================================================================" -ForegroundColor Green
Write-Host "Cyber Hashira uninstalled successfully from Windows." -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
