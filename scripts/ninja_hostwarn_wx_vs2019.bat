@echo off
setlocal
echo === Building host-only warn verification build (/W4, /WX ON) ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
set REPO_ROOT=C:\Users\mishih\Workspace\openenclave
cd /d %REPO_ROOT%\build\x64-HostWarnWx
echo --- Running ninja ---
ninja > ..\..\hostwarn_wx_build.log 2>&1
echo Ninja exit code: %ERRORLEVEL%
endlocal
