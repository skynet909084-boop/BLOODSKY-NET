@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 (
    echo Установите Python 3.11+ для Windows с python.org
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" -c "import psutil" >nul 2>&1
if errorlevel 1 (
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 (
    echo Ошибка установки зависимостей
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" app.py
if errorlevel 1 pause
