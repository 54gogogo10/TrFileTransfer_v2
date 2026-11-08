@echo off
rem TrFileTransfer v2 release build (Windows).
rem Artifacts:
rem   release\TrFileTransfer-0.1.0.exe            -- CLI
rem   release\TrFileTransfer-GUI-0.1.0.exe        -- desktop GUI (single-file main edition, Evergreen WebView2)
rem   release\TrFileTransfer-server-0.1.0.exe     -- web admin plane
rem   release\*.sha256                            -- sidecars required by the updater (lowercase hash + " *name")
rem   release\TrFileTransfer-GUI-0.1.0-portable.zip -- offline portable edition (GUI exe + fixed-version WebView2
rem       runtime; packaged only when build\WebView2FixedRuntime\ is ready, see build\fetch-webview2-fixed.ps1)
rem Version single source: "version" in crates\trft-gui\tauri.conf.json (keep Cargo.toml in sync).
rem NOTE: this file must stay CRLF + ANSI(GBK) for cmd; edit via an encoding-aware editor.

setlocal
cd /d "%~dp0"
set VERSION=0.2.0

echo [1/3] cargo build --release --workspace
cargo build --release --workspace
if errorlevel 1 goto :fail

echo [2/3] refresh release artifacts + sha256 sidecars
copy /y "target\release\trft.exe"          "release\TrFileTransfer-%VERSION%.exe" >nul || goto :fail
copy /y "target\release\trft-gui.exe"      "release\TrFileTransfer-GUI-%VERSION%.exe" >nul || goto :fail
copy /y "target\release\trft-server.exe"   "release\TrFileTransfer-server-%VERSION%.exe" >nul || goto :fail
rem Prefer pwsh: when build.bat is launched from a PowerShell 7 session, PSModulePath
rem carries PS7 module dirs, and 5.1 then tries to load PS7's Microsoft.PowerShell.Utility
rem and fails (Get-FileHash becomes "not recognized") while still exiting 0 -- which used
rem to write a corrupt .sha256 sidecar silently. Keep this file ASCII-only: cmd reads it in
rem the OEM codepage, and UTF-8 chinese text can desync the parser (GBK trail bytes are ASCII).
set "PSEXE=powershell"
where pwsh >nul 2>nul
if not errorlevel 1 set "PSEXE=pwsh"
for %%F in ("TrFileTransfer-%VERSION%.exe" "TrFileTransfer-GUI-%VERSION%.exe" "TrFileTransfer-server-%VERSION%.exe") do (
  %PSEXE% -NoProfile -Command "$ErrorActionPreference='Stop'; try { $h=(Get-FileHash -Algorithm SHA256 'release\%%~F').Hash.ToLower(); [IO.File]::WriteAllText('release\%%~F.sha256', \"$h *%%~F\", [Text.UTF8Encoding]::new($false)) } catch { Write-Error $_; exit 1 }"
  if errorlevel 1 goto :fail
)

echo [3/3] offline portable edition
set PORTABLE_DIR=release\TrFileTransfer-GUI-%VERSION%-portable
if exist "build\WebView2FixedRuntime\msedgewebview2.exe" (
  if exist "%PORTABLE_DIR%" rmdir /s /q "%PORTABLE_DIR%"
  mkdir "%PORTABLE_DIR%"
  copy /y "target\release\trft-gui.exe" "%PORTABLE_DIR%\TrFileTransfer-GUI-%VERSION%.exe" >nul || goto :fail
  echo       copying fixed runtime - hundreds of MB, please wait ...
  robocopy "build\WebView2FixedRuntime" "%PORTABLE_DIR%\WebView2Runtime" /E /NFL /NDL /NJH /NJS /NP
  if errorlevel 8 goto :fail
  echo       compressing zip ...
  if exist "%PORTABLE_DIR%.zip" del "%PORTABLE_DIR%.zip"
  powershell -NoProfile -Command "Compress-Archive -Path '%PORTABLE_DIR%' -DestinationPath '%PORTABLE_DIR%.zip' -CompressionLevel Optimal"
  if errorlevel 1 goto :fail
  echo       done: %PORTABLE_DIR%.zip
) else (
  echo       [skip] build\WebView2FixedRuntime not found -- run:
  echo         powershell -NoProfile -ExecutionPolicy Bypass -File build\fetch-webview2-fixed.ps1
  echo       then re-run build.bat to produce the portable edition.
)

echo.
echo build finished.
exit /b 0

:fail
echo build FAILED.
exit /b 1
