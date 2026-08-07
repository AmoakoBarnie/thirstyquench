@echo off
echo ============================================================
echo   TQ Webapp — Start with Public Tunnel
echo ============================================================
echo.
echo Starting cloudflared tunnel for http://localhost:5050 ...
start "TQ Cloudflare Tunnel" /B ""C:\Users\Amoako\Downloads\cloudflared.exe" tunnel --url http://localhost:5050"
timeout /t 5 /nobreak >nul
echo.
echo If a public URL appeared above, share it to access from any device.
echo Otherwise, wait a few seconds for the tunnel URL to show.
echo.
echo Press any key to ALSO start the Flask webapp locally...
pause >nul
cd /d C:\Users\Amoako\TQ\webapp_dev
"C:\Users\Amoako\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" app.py
pause
