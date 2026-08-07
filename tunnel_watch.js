const http = require('http');
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORT = 5050;
const STATE_FILE = path.join(__dirname, 'tunnel_state.json');
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
const PUBLIC_CHECK_TIMEOUT_MS = 12 * 1000;
const LT = process.env.LT_CMD || 'lt';

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return {}; }
}
function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}
function httpGet(url, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', (err) => resolve({ status: 0, body: err.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: 'timeout' }); });
  });
}

async function getTunnelUrl() {
  const out = execSync(`${LT} --port ${PORT} --print-requests false`, {
    encoding: 'utf8',
    timeout: 25 * 1000,
    env: { ...process.env, PATH: process.env.PATH + (process.platform === 'win32' ? ';' : ':') + path.join(process.env.APPDATA || '', '..\Local\hermes\node') },
  }).toString();
  const m = out.match(/(https:\/\/[a-zA-Z0-9_-]+\.loca\.lt)/);
  if (!m) throw new Error('No URL in output: ' + out.slice(0, 200));
  return m[1];
}

async function check() {
  const state = loadState();
  const local = await httpGet(`http://127.0.0.1:${PORT}/login`, 4000);
  if (local.status !== 200) {
    console.log('LOCAL_DOWN', local.status, local.body.slice(0, 120));
    return state;
  }

  let publicOk = false;
  if (state.url) {
    const pub = await httpGet(state.url + '/login', PUBLIC_CHECK_TIMEOUT_MS);
    publicOk = pub.status === 200 || pub.status === 302 || pub.status === 301;
    if (!publicOk) console.log('PUBLIC_FAIL', state.url, pub.status, pub.body.slice(0, 120));
  }

  if (!state.url || !publicOk) {
    let newUrl = null;
    for (let i = 0; i < 3; i++) {
      try {
        newUrl = await getTunnelUrl();
        break;
      } catch (e) {
        console.log('LT_ATTEMPT_FAIL', i + 1, e.message);
        await new Promise((r) => setTimeout(r, 1500));
      }
    }
    if (newUrl) {
      const verify = await httpGet(newUrl + '/login', PUBLIC_CHECK_TIMEOUT_MS);
      const ok = verify.status === 200 || verify.status === 302 || verify.status === 301;
      if (ok) {
        const next = { ...state, url: newUrl, pid: state.pid || null, last_ok: Date.now() };
        saveState(next);
        console.log('NEW_URL', newUrl);
        return next;
      } else {
        console.log('NEW_URL_VERIFY_FAIL', newUrl, verify.status);
      }
    }
  } else {
    const next = { ...state, last_ok: Date.now() };
    saveState(next);
    console.log('URL_OK', state.url);
    return next;
  }
  return state;
}

(async () => {
  try {
    await check();
  } catch (e) {
    console.log('WATCHDOG_ERROR', e.message);
  }
})();
