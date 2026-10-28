@echo off
setlocal
set "VS=D:\Program Files\Microsoft Visual Studio\2022\Community"
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] vcvars64.bat failed
    exit /b 1
)
set "CMAKE=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"

echo === configure ===
"%CMAKE%" -S . -B build-msvc -G Ninja -DCMAKE_MAKE_PROGRAM="%NINJA%" -DCMAKE_BUILD_TYPE=Release "-DCMAKE_CXX_FLAGS=/utf-8 /EHsc"
if errorlevel 1 exit /b 1

echo === build ===
"%CMAKE%" --build build-msvc
if errorlevel 1 exit /b 1

echo === done ===
dir /b build-msvc\*.exe
