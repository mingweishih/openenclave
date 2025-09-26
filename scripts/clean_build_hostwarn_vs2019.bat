@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
REM Change to repo root (script is in scripts directory)
cd /d %~dp0..
if not exist build\x64-HostWarn (
  echo HostWarn build directory missing. Run configure_hostwarn_vs2019.bat first.
  exit /b 1
)
cd build\x64-HostWarn
echo --- Cleaning Ninja outputs ---
ninja -t clean
echo --- Rebuilding (logging to build_output.log) ---
ninja > build_output.log 2>&1
echo Build complete. Log: %CD%\build_output.log
endlocal
