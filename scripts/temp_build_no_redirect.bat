@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d C:\Users\mishih\Workspace\openenclave\build\x64-HostWarnWx
echo --- Running ninja (no redirection) ---
ninja
echo Ninja exit code: %ERRORLEVEL%
