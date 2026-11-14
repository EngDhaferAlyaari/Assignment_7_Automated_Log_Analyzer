@echo off
cd /d "%~dp0"
if not exist Log_Analyzer.exe (
  echo Log_Analyzer.exe is not here yet.
  echo Build it using GitHub Actions first.
  pause
  exit /b 1
)
Log_Analyzer.exe sample_security.log --report EXE_Report.txt
if errorlevel 1 (
  echo EXE run failed.
) else (
  echo.
  echo Report saved in EXE_Report.txt
  type EXE_Report.txt
)
pause
