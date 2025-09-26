@echo off
setlocal
echo === Ninja host-only warn triage build (/W4) ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d C:\Users\mishih\Workspace\openenclave\build\x64-HostWarn
echo --- Running ninja ---
ninja > ..\..\hostwarn_build.log 2>&1
echo Ninja exit code: %ERRORLEVEL%
endlocal
