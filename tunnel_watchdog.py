#!/usr/bin/env python3
"""
TQ Webapp Tunnel Watchdog
Checks local server + public tunnel health.
If offline, restarts tunnel and captures new URL.
Outputs status lines for cron/notification.
"""
import http.client
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

PORT = 5050
STATE_FILE = Path(r"C:\Users\Amoako\TQ\webapp_dev\tunnel_state.json")
EVENT_LOG = Path(r"C:\Users\Amoako\TQ\webapp_dev\tunnel_events.log")
LT_CMD = os.environ.get("LT_CMD") or r"C:\Users\Amoako\AppData\Local\hermes\node\lt.cmd"

def log(msg):
    print(msg, flush=True)
    try:
        EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
        EVENT_LOG.write_text(msg + "\n", encoding="utf-8")
    except Exception:
        pass

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def save_state(state):
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

def http_get(host, path="/login", timeout=10, use_https=False):
    try:
        conn = http.client.HTTPSConnection(host, timeout=timeout) if use_https else http.client.HTTPConnection(host, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "TQ-Watchdog/1.0"})
        r = conn.getresponse()
        body = b""
        while True:
            chunk = r.read(1024)
            if not chunk:
                break
            body += chunk
        conn.close()
        return r.status, body.decode("utf-8", errors="ignore")
    except Exception as e:
        return 0, str(e)

def local_ok():
    status, _ = http_get("127.0.0.1", "/login", timeout=5)
    return status == 200

def public_ok(url):
    try:
        host = url.replace("https://", "", 1).replace("http://", "", 1).split("/")[0]
        status, _ = http_get(host, "/login", timeout=15, use_https=True)
        return status in (200, 301, 302)
    except Exception:
        return False

def start_tunnel():
    try:
        env = os.environ.copy()
        env["PATH"] = env.get("PATH", "") + os.pathsep + r"C:\Users\Amoako\AppData\Local\hermes\node"
        out = subprocess.check_output(
            [LT_CMD, "--port", str(PORT), "--print-requests", "false"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            env=env,
        )
        m = re.search(r"https://[a-zA-Z0-9_-]+\.loca\.lt", out)
        if m:
            return m.group(0)
    except subprocess.TimeoutExpired:
        log("TUNNEL_START_TIMEOUT")
    except FileNotFoundError:
        log("TUNNEL_LT_NOT_FOUND")
    except Exception as e:
        log(f"TUNNEL_START_ERROR: {e}")
    return None

def main():
    state = load_state()
    old_url = state.get("url")
    
    # Check local server
    if not local_ok():
        log("LOCAL_SERVER_DOWN")
        return old_url or ""
    
    # Check if current tunnel URL works
    if old_url and public_ok(old_url):
        log(f"TUNNEL_OK:{old_url}")
        return old_url
    
    # Tunnel is down or no URL - restart it
    log("TUNNEL_OFFLINE_RESTARTING")
    for attempt in range(3):
        new_url = start_tunnel()
        if new_url:
            # Verify the new URL
            if public_ok(new_url):
                state["url"] = new_url
                state["last_ok"] = time.time()
                save_state(state)
                log(f"NEW_TUNNEL_URL:{new_url}")
                return new_url
            else:
                log(f"NEW_URL_VERIFY_FAIL:{new_url}")
                continue
        log(f"LT_ATTEMPT_{attempt+1}_FAIL")
        time.sleep(2)
    
    log("ALL_TUNNEL_ATTEMPTS_FAILED")
    return old_url or ""

if __name__ == "__main__":
    url = main()
    # Always output the URL for cron to pick up
    if url:
        print(f"CURRENT_URL:{url}")
    else:
        print("NO_URL")
