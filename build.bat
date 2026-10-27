@echo off
setlocal EnableExtensions

rem ===========================================================================
rem  ghidradec-idafree - build script
rem
rem  1. Loads the Visual Studio 2022 Developer Command Prompt (x64)
rem  2. Checks IDASDK (path to the IDA SDK) and GHIDRA_DIR (the Ghidra
rem     installation whose decompiler sources are compiled in)
rem  3. Configures (CMake + Ninja) and builds the plugin into .\bin (static CRT)
rem
rem  Usage:  set IDASDK=C:\path\to\ida-sdk
rem          set GHIDRA_DIR=C:\path\to\ghidra_12.1.4_PUBLIC
rem          build.bat            incremental build
rem          build.bat clean      wipe the build directory first
rem ===========================================================================

set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

if not defined IDASDK (
    echo [!] IDASDK is not set. Point it to your IDA SDK, e.g.:
    echo       set IDASDK=C:\path\to\ida-sdk
    exit /b 1
)
if not exist "%IDASDK%\src\cmake\idasdk_init.cmake" (
    echo [!] IDASDK=%IDASDK% does not look like an IDA SDK ^(src\cmake\idasdk_init.cmake not found^).
    exit /b 1
)
if not defined GHIDRA_DIR (
    echo [!] GHIDRA_DIR is not set. Point it to your Ghidra installation, e.g.:
    echo       set GHIDRA_DIR=C:\path\to\ghidra_12.1.4_PUBLIC
    exit /b 1
)

rem --- locate Visual Studio 2022 ----------------------------------------------
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
if not exist "%VSDEVCMD%" (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
        for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -version [17.0^,18.0^) -latest -property installationPath`) do (
            set "VSDEVCMD=%%i\Common7\Tools\VsDevCmd.bat"
        )
    )
)
if not exist "%VSDEVCMD%" (
    echo [!] Visual Studio 2022 Developer Command Prompt not found.
    exit /b 1
)

echo [*] Loading Visual Studio 2022 Developer Command Prompt...
rem VsDevCmd.bat relies on vswhere.exe being reachable through PATH
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo [!] Failed to initialize the Visual Studio environment ^(cl.exe not found^).
    exit /b 1
)

cd /d "%PROJECT_DIR%"
echo [*] IDASDK=%IDASDK%
echo [*] GHIDRA_DIR=%GHIDRA_DIR%

if not exist "%GHIDRA_DIR%\Ghidra\Features\Decompiler\src\decompile\cpp\sleigh.cc" (
    echo [!] Ghidra decompiler sources not found under GHIDRA_DIR.
    exit /b 1
)

if /i "%~1"=="clean" (
    echo [*] Cleaning build directory...
    if exist build rmdir /s /q build
    if exist bin rmdir /s /q bin
)

echo [*] Configuring...
rem GD_STATIC_CRT: link the CRT statically (/MT) so the plugin does not depend
rem on the VC++ redistributable
cmake -S . -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release -DGD_STATIC_CRT=ON "-DGHIDRA_DIR=%GHIDRA_DIR%"
if errorlevel 1 (
    echo [!] CMake configuration failed.
    exit /b 1
)

echo [*] Building...
cmake --build build
if errorlevel 1 (
    echo [!] Build failed.
    exit /b 1
)

echo.
echo [+] Build OK: %PROJECT_DIR%\bin\ghidradec.dll
echo     Copy it to your IDA plugins folder, e.g.:
echo       copy "%PROJECT_DIR%\bin\ghidradec.dll" "C:\Program Files\IDA Free 9.4\plugins\"
echo     or  %%APPDATA%%\Hex-Rays\IDA Pro\plugins\
endlocal
exit /b 0
