@echo off
setlocal
echo === Configuring (only) VS2019 x64 Debug ===
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
set REPO_ROOT=C:\Users\mishih\Workspace\openenclave
cd /d %REPO_ROOT%
if not exist build mkdir build
if not exist build\x64-Debug mkdir build\x64-Debug
cd build\x64-Debug
del /f /q ..\..\build_configure.log 2>nul
echo --- Running CMake configure ---
cmake -G Ninja -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=C:/openenclave -DOE_ALLOW_UNSUPPORTED_CLANG=ON ../.. > ..\..\build_configure.log 2>&1
set ERR=%ERRORLEVEL%
echo Configure exit code: %ERR%
if %ERR% NEQ 0 (
  echo Configure failed. See build_configure.log
  exit /b %ERR%
)
if not exist build.ninja (
  echo ERROR: build.ninja not generated.
  exit /b 2
)
echo Configure succeeded and build.ninja present.
endlocal
