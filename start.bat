@echo off
SETLOCAL
cls
echo ==================================================
echo   MAGI: CYBER GHIDRA WEBUI BOOT LOADER
echo ==================================================
echo [Detected Environment Selection]
echo 1. AMD Radeon Mode (Current: 7900XT)
echo 2. NVIDIA GeForce Mode (Compatibility)
echo 3. CPU Only Mode (Emergency)
echo 4. Exit
echo --------------------------------------------------
set /p choice="Select Mode (1-4): "

if "%choice%"=="1" goto AMD
if "%choice%"=="2" goto NVIDIA
if "%choice%"=="3" goto CPU
if "%choice%"=="4" exit
goto exit

:AMD
echo Starting in AMD Radeon Mode...
docker-compose -f docker-compose.yml -f docker-compose.amd.yml up -d
goto END

:NVIDIA
echo Starting in NVIDIA GeForce Mode...
echo [Notice] Ensure nvidia-container-runtime is installed.
docker-compose up -d
goto END

:CPU
echo Starting in CPU Only Mode...
docker-compose up -d
goto END

:END
echo.
echo Dashboard is starting at http://localhost:3000
echo Backend API is at http://localhost:8000
pause