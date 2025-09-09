@echo off
setlocal enabledelayedexpansion

rem Ensure UTF-8 in console
chcp 65001 > nul

rem Change to script directory
cd /d "%~dp0"

rem Pick Python launcher
set PY=py
%PY% -V >nul 2>&1 || set PY=python

echo Checking Python...
%PY% -V >nul 2>&1
if errorlevel 1 (
  echo Python is not installed or not in PATH.
  echo Please install Python 3.9+ from https://www.python.org/downloads/ and try again.
  pause
  exit /b 1
)

rem Determine if requirements are missing
echo Verifying dependencies...
%PY% -c "import sys, pkgutil; reqs=['aiohttp','brotli','imageio','PIL','cryptography']; missing=[r for r in reqs if pkgutil.find_loader(r) is None]; print(','.join(missing)); sys.exit(1 if missing else 0)" > deps_missing.txt 2>nul

set INSTALL=0
if errorlevel 1 (
  set /p MISSING=<deps_missing.txt
  if not "%MISSING%"=="" (
    echo Missing packages: %MISSING%
    set INSTALL=1
  )
)
del /q deps_missing.txt 2>nul

if %INSTALL%==1 (
  if exist requirements.txt (
    echo Installing/upgrading pip and project requirements...
    %PY% -m pip install --upgrade pip
    if errorlevel 1 goto pip_fail
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 goto pip_fail
  ) else (
    echo requirements.txt not found. Installing detected missing packages individually...
    %PY% -m pip install aiohttp brotli imageio Pillow cryptography
    if errorlevel 1 goto pip_fail
  )
)

echo Starting GhostKeeper...
%PY% ghostkeeper.py
goto :eof

:pip_fail
echo Failed to install dependencies. Please check your internet connection and try again.
pause
exit /b 1


