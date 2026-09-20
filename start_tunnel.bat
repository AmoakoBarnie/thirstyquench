@echo off
:: TQ Webapp Public Tunnel Launcher (Windows)
:: Usage: set NGROK_AUTHTOKEN=your_token && start_tq_public.bat
:: Get a free token at https://dashboard.ngrok.com/signup

echo ============================================================
echo   TQ Webapp — Public Tunnel Launcher
echo ============================================================
echo.

if "%NGROK_AUTHTOKEN%"=="" (
    echo ERROR: NGROK_AUTHTOKEN environment variable not set.
    echo Get your free token at https://dashboard.ngrok.com/signup
    echo Then set it: set NGROK_AUTHTOKEN=your_token
    echo.
    pause
    exit /b 1
)

echo [1/2] Opening ngrok tunnel on port 5050 ...
start "TQ ngrok" /B ""C:\Users\Amoako\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" -c ^
"from pyngrok import ngrok; import time; t=ngrok.connect(5050, 'http'); print('[TUNNEL] public URL:', t.public_url); print('[TUNNEL] press Ctrl+C here to stop'); import time; [time.sleep(3600) for _ in range(1)]"

echo Waiting for tunnel to initialize ...
timeout /t 4 /nobreak >nul

echo.
echo [2/2] Starting Flask webapp on 0.0.0.0:5050 ...
echo.
echo Access URLs:
echo   Local:   http://127.0.0.1:5050
echo   LAN:     http://192.168.1.44:5050
echo   Public:  (shown above as [TUNNEL] public URL)
echo.
echo Press Ctrl+C in this window to stop both.
echo ============================================================
echo.

cd /d C:\Users\Amoako\TQ\webapp_dev
"C:\Users\Amoako\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" app.py

echo.
echo Webapp stopped.
pause
