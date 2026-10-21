@echo off
rem MaskCode one-click installer and launcher for Windows.
rem Double-click this file. The first run installs MaskCode for your user
rem account (about a minute); later runs open the app straight away.
setlocal
title MaskCode
set "HERE=%~dp0"
set "VENV=%LOCALAPPDATA%\MaskCode\venv"
set "PYTHONPATH="
set "PYTHONHOME="

if exist "%VENV%\Scripts\maskcode.exe" goto run

echo Setting up MaskCode for the first time...
where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
if errorlevel 1 (
  echo.
  echo MaskCode needs Python 3.10 or newer.
  echo Opening the Python download page. Install it, tick "Add python.exe to PATH",
  echo then double-click this file again.
  start "" https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
%PY% -m venv "%VENV%" || goto fail
"%VENV%\Scripts\python.exe" -m pip install --disable-pip-version-check -q --upgrade pip || goto fail
"%VENV%\Scripts\python.exe" -m pip install --disable-pip-version-check -q "%HERE%." || goto fail
echo Done.

:run
echo Opening MaskCode in your browser. Keep this window open while you use it.
"%VENV%\Scripts\maskcode.exe" app
exit /b %errorlevel%

:fail
echo.
echo Setup did not finish. Check your internet connection and try again.
pause
exit /b 1
