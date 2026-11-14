@echo off
cd /d "%~dp0"
py -3 log_analyzer.py sample_security.log --report Demo_Report.txt
if errorlevel 1 (
  echo Demo failed. Please check that Python is installed.
) else (
  echo.
  echo Report saved in Demo_Report.txt
  type Demo_Report.txt
)
pause
