@echo off
setlocal

cd /d "%~dp0"

python -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --windowed ^
  --name SOCProbe ^
  --paths . ^
  --add-data "config.json;." ^
  launch_socprobe.pyw

echo.
echo Build complete. Executable: dist\SOCProbe.exe
endlocal
