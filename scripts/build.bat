@echo off
setlocal

set "ROOT=%~dp0.."
set "BUILD=%ROOT%\build"
set "RES=%ROOT%\resources"
set "SRC=%ROOT%\src\CppModernWinPcapSniffer.cpp"
set "OUT=%BUILD%\CppModernWinPcapSniffer.exe"

if not exist "%BUILD%" mkdir "%BUILD%"

where windres >nul 2>nul
if errorlevel 1 (
    echo [ERROR] windres not found. Add MinGW-w64 bin to PATH.
    exit /b 1
)

where g++ >nul 2>nul
if errorlevel 1 (
    echo [ERROR] g++ not found. Add MinGW-w64 bin to PATH.
    exit /b 1
)

echo [1/2] Compiling resources...
pushd "%RES%"
windres -c 65001 app.rc -O coff -o "%BUILD%\app.res.o"
if errorlevel 1 (
    popd
    exit /b 1
)
popd

echo [2/2] Compiling and linking...
g++ -std=c++17 -O2 -municode -mwindows "%SRC%" "%BUILD%\app.res.o" -o "%OUT%" -lgdi32 -lcomctl32 -lws2_32 -luxtheme
if errorlevel 1 exit /b 1

echo Build OK: %OUT%
endlocal
