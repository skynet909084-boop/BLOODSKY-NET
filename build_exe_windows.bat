@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 exit /b 1
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt "pyinstaller>=6,<7"
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --collect-all pysnmp --collect-all Cryptodome --collect-all pystray --collect-all PIL --name BLOODSKY-NET app.py
if errorlevel 1 (
  echo Ошибка сборки
  pause
  exit /b 1
)
echo ГОТОВО: dist\BLOODSKY-NET.exe
pause
