import http.client, json, os, re, subprocess, sys
from pathlib import Path

PORT = 5050
STATE_FILE = Path(r"C:\Users\Amoako\TQ\webapp_dev\tunnel_state.json")
EVENT_FILE = Path(r"C:\Users\Amoako\TQ\webapp_dev\tunnel_events.log")
LT = os.environ.get("LT_CMD") or r"C:\Users\Amoako\AppData\Local\hermes\node\lt.cmd"

def log_event(text: str):
    try:
        EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)
        EVENT_FILE.write_text(text + "\n", encoding="utf-8")
    except Exception:
        pass
    print(text, flush=True)

def load():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def save(state: dict):
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

def http_get(host: str, path: str = "/login", timeout: int = 10, use_https: bool = False):
    try:
        conn = http.client.HTTPSConnection(host, timeout=timeout) if use_https else http.client.HTTPConnection(host, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "TQ-Watchdog/1.0"})
        r = conn.getresponse()
        body = ""
        while True:
            chunk = r.read(1024)
            if not chunk:
                break
            body += chunk
        conn.close()
        return r.status, body
    except Exception as e:
        return 0, str(e)

def local_ok() -> bool:
    status, _ = http_get("127.0.0.1", "/login", timeout=5)
    return status == 200

def start_tunnel():
    try:
        out = subprocess.check_output(
            [LT, "--port", str(PORT), "--print-requests", "false"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=25,
        )
        m = re.search(r"https://[a-zA-Z0-9_-]+\.loca\.lt", out)
        if m:
            return m.group(0)
    except Exception as e:
        log_event(f"TUNNEL_START_ERROR: {e}")
    return None

def public_ok(url: str) -> bool:
    try:
        host = url.replace("https://", "", 1).replace("http://", "", 1).split("/")[0]
        status, _ = http_get(host, "/login", timeout=12, use_https=True)
        return status in (200, 301, 302)
    except Exception:
        return False

def main() -> str:
    state = load()
    previous = state.get("url")

    if not local_ok():
        log_event("LOCAL_DOWN")
        return previous or ""

    if previous and public_ok(previous):
        log_event(f"URL_OK:{previous}")
        return previous

    log_event("TUNNEL_OFFLINE")
    for i in range(3):
        new_url = start_tunnel()
        if new_url:
            state["url"] = new_url
            save(state)
            verified = public_ok(new_url) or ("NEW_URL:" + new_url)
            # Re-verify once; if ok, emit final event
            if public_ok(new_url):
                log_event(f"NEW_URL:{new_url}")
                return new_url
            else:
                log_event(f"NEW_URL_VERIFY_FAIL:{new_url}")
                return new_url
        log_event(f"LT_ATTEMPT_{i+1}_FAIL")
    log_event("ALL_ATTEMPTS_FAILED")
    return previous or ""

if __name__ == "__main__":
    main()
