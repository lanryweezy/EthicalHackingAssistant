@echo off
title Ethical Hacking Assistant
color 0a
cls

echo Installing dependencies...
python -m pip install -r requirements.txt

echo.
echo Starting Ethical Hacking Assistant...
echo.
python main.py

echo.
echo Press any key to exit...
pause >nul
