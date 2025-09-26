@echo off
setlocal
echo === Configuring host-only warn triage build (/W4, no /WX, BUILD_ENCLAVES=OFF) ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
set REPO_ROOT=C:\Users\mishih\Workspace\openenclave
cd /d %REPO_ROOT%
if not exist build mkdir build
if not exist build\x64-HostWarn mkdir build\x64-HostWarn
cd build\x64-HostWarn
echo --- Running CMake configure ---
cmake -G Ninja -DBUILD_ENCLAVES=OFF -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=C:/openenclave -DOE_DISABLE_WX=ON -DOE_WARNING_LEVEL=4 ../.. > ..\..\hostwarn_configure.log 2>&1
echo Configure exit code: %ERRORLEVEL%
endlocal
