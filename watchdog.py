#!/usr/bin/env python3
"""
TQ Cloudflare Tunnel Watchdog
- Checks if local TQ server is running
- If not, starts it
- Checks if tunnel is reachable via public URL
- If offline or URL changed, restarts tunnel and captures new URL
- Logs everything and sends Telegram notifications on URL changes
"""

import subprocess
import time
import re
import sys
import os
import json
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

# === CONFIG ===
TQ_DIR = Path(r"C:\Users\Amoako\TQ\webapp")
PORT = 5050
HEALTH_URL = f"http://127.0.0.1:{PORT}/login"
STATE_FILE = Path(r"C:\Users\Amoako\TQ\webapp_dev\tunnel_state.json")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
MAX_WAIT_SERVER = 20
MAX_WAIT_TUNNEL = 30
CHECK_INTERVAL_SECONDS = 300  # 5 minutes

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")
    sys.stdout.flush()

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"url": None, "pid": None, "last_ok": None}

def save_state(state):
    STATE_FILE.write_text(json.dumps(state))
    log(f"State saved: {state}")

def is_process_running(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, ValueError, PermissionError):
        return False

def wait_for_server(url, timeout=MAX_WAIT_SERVER):
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TQ-Watchdog/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status < 500:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False

def wait_for_tunnel_health(url, timeout=MAX_WAIT_TUNNEL):
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TQ-Watchdog/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status < 500:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False

def start_tq_server():
    log("Starting TQ Flask server...")
    try:
        proc = subprocess.Popen(
            ["/c/Users/Amoako/AppData/Local/hermes/hermes-agent/venv/Scripts/python", "app.py"],
            cwd=str(TQ_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        if wait_for_server(HEALTH_URL, timeout=MAX_WAIT_SERVER):
            log(f"TQ server started (PID {proc.pid})")
            return proc.pid
        else:
            log("TQ server started but health check failed")
            return None
    except Exception as e:
        log(f"Failed to start TQ server: {e}")
        return None

def start_tunnel():
    log("Starting cloudflared tunnel...")
    try:
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{PORT}"],
            cwd=str(TQ_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        url = None
        deadline = time.time() + MAX_WAIT_TUNNEL
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            try:
                line = proc.stdout.readline()
                if not line:
                    continue
                text = line.decode("utf-8", errors="ignore").strip()
                if "trycloudflare.com" in text:
                    m = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", text)
                    if m:
                        url = m.group(0)
                        break
            except Exception:
                pass
            time.sleep(1)
        if url:
            log(f"Tunnel URL captured: {url}")
            return proc.pid, url
        else:
            log("Tunnel started but URL not captured yet")
            return proc.pid, None
    except Exception as e:
        log(f"Failed to start tunnel: {e}")
        return None, None

def send_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("Telegram not configured, skipping notification")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text, "disable_web_page_preview": True}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        log(f"Telegram notification failed: {e}")
        return False

def main():
    log("=== TQ Tunnel Watchdog started ===")
    state = load_state()
    first_run = True

    while True:
        try:
            old_url = state.get("url")
            tq_pid = state.get("pid")
            tunnel_pid = state.get("tunnel_pid")

            # 1) Ensure TQ server is running
            server_running = False
            if is_process_running(tq_pid):
                server_running = wait_for_server(HEALTH_URL, timeout=5)
            if not server_running:
                log("TQ server not running or not responding, restarting...")
                new_pid = start_tq_server()
                if new_pid:
                    state["pid"] = new_pid
                    save_state(state)
                else:
                    log("Failed to start TQ server, will retry next cycle")
                    time.sleep(CHECK_INTERVAL_SECONDS)
                    continue

            # 2) Ensure tunnel is running and reachable
            tunnel_ok = False
            new_url = None
            if old_url:
                try:
                    req = urllib.request.Request(old_url, headers={"User-Agent": "TQ-Watchdog/1.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        if resp.status < 500:
                            tunnel_ok = True
                            new_url = old_url
                except Exception:
                    tunnel_ok = False

            if not tunnel_ok:
                log("Tunnel offline or unreachable, restarting...")
                new_tunnel_pid, captured_url = start_tunnel()
                if new_tunnel_pid:
                    state["tunnel_pid"] = new_tunnel_pid
                if captured_url:
                    new_url = captured_url
                    state["url"] = new_url
                    save_state(state)
                    if first_run or old_url != new_url:
                        now = datetime.now().strftime("%Y-%m-%d %H:%M")
                        send_telegram(
                            f"TQ Webapp live URL:\n{new_url}\n\nUpdated: {now}\n\nIf this link goes offline, watchdog will auto-restart and resend a fresh link."
                        )
                        first_run = False
                else:
                    log("Tunnel restart started but URL not yet captured")
            else:
                state["last_ok"] = datetime.now().isoformat()
                save_state(state)
                if first_run:
                    now = datetime.now().strftime("%Y-%m-%d %H:%M")
                    send_telegram(
                        f"TQ Webapp live URL:\n{new_url}\n\nWatchdog active: will auto-restart and resend if this link goes offline.\n\nUpdated: {now}"
                    )
                    first_run = False

        except Exception as e:
            log(f"Watchdog error: {e}")

        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
