@echo off
cd /d "%~dp0"
py -3 -m unittest -v test_log_analyzer
pause
