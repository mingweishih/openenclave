@echo off
setlocal enabledelayedexpansion
echo === Setting up VS2019 x64 build environment ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
  echo Failed to call vcvars64.bat
  exit /b 1
)
set REPO_ROOT=C:\Users\mishih\Workspace\openenclave
cd /d %REPO_ROOT%
if not exist build mkdir build
if not exist build\x64-Debug mkdir build\x64-Debug
cd build\x64-Debug
echo === Configuring with CMake ===
cmake -G Ninja -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=C:/openenclave -DOE_ALLOW_UNSUPPORTED_CLANG=ON ../.. > ..\..\build_configure.log 2>&1
if errorlevel 1 (
  echo CMake configure failed. See build_configure.log
  exit /b 1
)
echo === Building with Ninja ===
ninja > ..\..\build_build.log 2>&1
set BUILD_ERROR=%ERRORLEVEL%
if %BUILD_ERROR% NEQ 0 (
  echo Ninja build failed with error %BUILD_ERROR%. See build_build.log
  exit /b %BUILD_ERROR%
)
echo Build completed successfully.
endlocal
