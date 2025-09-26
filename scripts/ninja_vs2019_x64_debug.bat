@echo off
setlocal
echo === Ninja build (VS2019 x64 Debug) ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d C:\Users\mishih\Workspace\openenclave\build\x64-Debug
del /f /q ..\..\build_build.log 2>nul
echo --- Running ninja (this may take a while) ---
ninja > ..\..\build_build.log 2>&1
set ERR=%ERRORLEVEL%
echo Ninja exit code: %ERR%
if %ERR% NEQ 0 echo Build failed. See build_build.log
endlocal
