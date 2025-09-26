@echo off
setlocal
echo === Configuring warn triage build (/W4, no /WX) ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
set REPO_ROOT=C:\Users\mishih\Workspace\openenclave
cd /d %REPO_ROOT%
if not exist build mkdir build
if not exist build\x64-WarnTriage mkdir build\x64-WarnTriage
cd build\x64-WarnTriage
echo --- Running CMake configure ---
cmake -G Ninja -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=C:/openenclave -DOE_ALLOW_UNSUPPORTED_CLANG=ON -DOE_DISABLE_WX=ON -DOE_WARNING_LEVEL=4 ../.. > ..\..\warn_configure.log 2>&1
echo Configure exit code: %ERRORLEVEL%
endlocal
