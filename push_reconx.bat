@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================
echo   reconx  -^>  GitHub push helper
echo ============================================
echo Working folder: %cd%
echo.

REM --- ensure git is available ---
where git >nul 2>&1
if errorlevel 1 (
  echo [ERROR] git is not on PATH for this window.
  echo         Close this, open "Git CMD" from the Start menu, then run:
  echo         cd /d "%~dp0" ^&^& push_reconx.bat
  pause & exit /b 1
)

REM --- initialize repo if this folder is not one yet ---
if not exist ".git" (
  echo [*] Initializing git repository...
  git init -q
  git branch -M main
)

REM --- set identity only if it is not already configured ---
for /f "delims=" %%i in ('git config user.email 2^>nul') do set EMAIL=%%i
if "!EMAIL!"=="" git config user.email "nithishgurukumar@gmail.com"
for /f "delims=" %%i in ('git config user.name 2^>nul') do set UNAME=%%i
if "!UNAME!"=="" git config user.name "Godsec"

REM --- stage ONLY the tool files (skip the zip and this helper) ---
echo [*] Staging project files...
git add reconx.py README.md LICENSE .gitignore
git commit -q -m "reconx: lean fast recon orchestrator (AutoRecon alternative)" 2>nul
if errorlevel 1 echo [i] Nothing new to commit - continuing.
echo.

REM ============================================================
REM  PATH 1: GitHub CLI present -> fully automatic
REM ============================================================
where gh >nul 2>&1
if not errorlevel 1 (
  echo [*] GitHub CLI detected. Checking login status...
  gh auth status >nul 2>&1
  if errorlevel 1 (
    echo.
    echo [*] Not logged in yet. A GitHub login will open now - complete it in
    echo     your browser, then come back to this window.
    echo.
    gh auth login
  )
  echo [*] Creating PUBLIC repo "reconx" and pushing...
  gh repo create reconx --public --source=. --remote=origin --push
  goto done
)

REM ============================================================
REM  PATH 2: no gh -> use plain git against a repo you create
REM ============================================================
echo [!] GitHub CLI (gh) was not found.
echo.
echo     Step 1: In your browser, create an EMPTY repository named "reconx"
echo             ( https://github.com/new  -  do NOT add a README or license )
echo     Step 2: Come back here and enter your GitHub username below.
echo.
set /p GHUSER=GitHub username:
if "!GHUSER!"=="" (
  echo [ERROR] No username entered. Aborting.
  pause & exit /b 1
)
git remote get-url origin >nul 2>&1
if errorlevel 1 (
  git remote add origin https://github.com/!GHUSER!/reconx.git
) else (
  git remote set-url origin https://github.com/!GHUSER!/reconx.git
)
echo [*] Pushing to https://github.com/!GHUSER!/reconx.git
echo     If prompted, a Git Credential Manager browser window will open for login.
git push -u origin main

:done
echo.
echo ============================================
echo   Finished. Open github.com to confirm your repo.
echo ============================================
pause
