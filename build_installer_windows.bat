@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist "dist\BLOODSKY-NET.exe" call build_exe_windows.bat
if not exist "dist\BLOODSKY-NET.exe" exit /b 1
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
  echo Inno Setup 6 не установлен. Установите его и повторите сборку.
  exit /b 1
)
"%ISCC%" "installer\BLOODSKY-NET.iss"
if errorlevel 1 exit /b 1
echo Installer: installer\output\BLOODSKY-NET-Setup-0.8.0-dev.exe
