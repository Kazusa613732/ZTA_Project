@echo off

:: 檢查 nodemon 是否可用
where nodemon >nul 2>&1
if errorlevel 1 (
    echo [ERROR] nodemon is not installed or not in PATH.
    echo Please run "npm install -g nodemon" and try again.
    pause
    exit /b
)

:: 啟動 NGINX 正確方式（先切換目錄再啟動）
echo Starting NGINX...
pushd "C:\Users\user\Desktop\ZTApj\nginx-1.27.5\nginx-1.27.5"
start "" nginx.exe
popd

if errorlevel 1 (
    echo [ERROR] Failed to start NGINX.
    pause
    exit /b
)

timeout /t 2 >nul

:: 啟動 index.js
echo Starting index.js...
start cmd /k "echo Running index.js... & nodemon index.js || (echo Failed to start index.js & pause)"

timeout /t 2 >nul

:: 啟動 protected.js
echo Starting protected.js...
start cmd /k "echo Running protected.js... & nodemon protected.js || (echo Failed to start protected.js & pause)"

echo All processes started.
pause
