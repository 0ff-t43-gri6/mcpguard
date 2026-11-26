@echo off
rem Double-click to open the mcpguard dashboard in your browser.
rem Keep this window open while you use the dashboard; close it to stop.
cd /d "%~dp0"
py -m mcpguard -c "%~dp0mcpguard.toml" open
if errorlevel 1 (
  echo.
  echo Something went wrong. If it says the config is not trusted, run:  py -m mcpguard trust
  pause
)
