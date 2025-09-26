@echo off
setlocal
echo === Ninja build (VS2019 x64 Debug /W4) ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d %~dp0..\build\x64-Debug
echo --- Running ninja ---
ninja > ..\..\build_build_w4.log 2>&1
echo Ninja exit code: %ERRORLEVEL%
endlocal
