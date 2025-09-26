@echo off
setlocal
echo === Ninja warn triage build (/W4, warnings not errors except mandated ones) ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d C:\Users\mishih\Workspace\openenclave\build\x64-WarnTriage
echo --- Running ninja ---
ninja > ..\..\warn_build.log 2>&1
echo Ninja exit code: %ERRORLEVEL%
endlocal
