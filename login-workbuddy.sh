#!/usr/bin/env bash
# login-workbuddy.sh — WorkBuddy/CodeBuddy OAuth 设备授权登录：
#   POST /v2/plugin/auth/state 拿 state → 浏览器腾讯 SSO 登录 → 轮询 /v2/plugin/auth/token 拿 token
# 对齐官方 CLI 2.139.0 流程：
#   - 鉴权域 https://copilot.tencent.com，计费域 https://www.codebuddy.cn
#   - 轮询 /v2/plugin/auth/token 为 GET（带 state）
#   - 身份（uid/enterpriseId/nickname）走 GET /v2/plugin/login/account
set -euo pipefail

cd "$(dirname "$0")"
AUTH_DIR="./auths"
mkdir -p "$AUTH_DIR"

# ─── 探测可用 Python（排除 Windows Store 占位符）───
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "pass" 2>/dev/null; then
    PY="$cand"
    break
  fi
done
if [[ -z "$PY" ]]; then
  echo "[!] 未找到可用的 Python（python3/python）"
  exit 1
fi

"$PY" - <<'PYEOF'
import json, os, sys, time, urllib.parse, urllib.request, urllib.error

AUTH = "https://copilot.tencent.com"
UA = "CLI/2.139.0 CodeBuddy/2.139.0"
ORIGIN = "https://www.codebuddy.cn"
AUTH_DIR = "./auths"
POLL_INTERVAL = 3
POLL_TIMEOUT = 300

COMMON = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": ORIGIN,
    "Referer": ORIGIN + "/",
    "User-Agent": UA,
}

def request(method, url, body=None, headers=None):
    data = None
    if body is not None:
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers if headers is not None else COMMON).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            obj = json.loads(e.read().decode() or "{}")
        except Exception:
            obj = {}
        return e.code, obj

# ─── 1) 拿 state ───
st, resp = request("POST", AUTH + "/v2/plugin/auth/state?platform=CLI", {})
if resp.get("code") != 0:
    print("[!] 获取 state 失败: " + json.dumps(resp, ensure_ascii=False)[:300], file=sys.stderr)
    sys.exit(1)
data = resp.get("data") or {}
state = data.get("state")
auth_url = data.get("authUrl") or data.get("auth_url")
if not state or not auth_url:
    print("[!] state 响应缺少 state/authUrl: " + json.dumps(resp, ensure_ascii=False)[:300], file=sys.stderr)
    sys.exit(1)

print("=" * 56)
print("  WorkBuddy 登录（OAuth 设备授权）")
print("=" * 56)
print("")
print("请在浏览器打开并完成腾讯 SSO 登录：")
print("")
print("  " + auth_url)
print("")
print("登录完成后本脚本会自动检测（最多等待 %d 秒，Ctrl+C 取消）..." % POLL_TIMEOUT, flush=True)

# ─── 2) 轮询换 token ───
access_token = refresh_token = domain = ""
expires_in = 0
deadline = time.time() + POLL_TIMEOUT
token_url = AUTH + "/v2/plugin/auth/token?state=" + urllib.parse.quote(state)
while True:
    st, resp = request("GET", token_url)
    if st >= 500:
        print("[!] token 接口 HTTP %d" % st, file=sys.stderr)
        sys.exit(1)
    if st < 300 and resp.get("code") == 0:
        tdata = resp.get("data") or {}
        access_token = tdata.get("accessToken") or ""
        refresh_token = tdata.get("refreshToken") or ""
        expires_in = int(tdata.get("expiresIn") or 0)
        domain = tdata.get("domain") or ""
        if access_token:
            break
    if time.time() >= deadline:
        print("[!] 等待授权超时，请重试", file=sys.stderr)
        sys.exit(1)
    time.sleep(POLL_INTERVAL)

print("[*] 已获取 accessToken")

# ─── 3) 拉取账号身份 ───
hdr = dict(COMMON)
hdr["Authorization"] = "Bearer " + access_token
st, resp = request("GET", AUTH + "/v2/plugin/login/account?state=" + urllib.parse.quote(state), None, hdr)
adata = (resp.get("data") or {}) if resp.get("code") == 0 else {}
uid = str(adata.get("uid") or "")
enterprise_id = str(adata.get("enterpriseId") or "")
nickname = str(adata.get("nickname") or "")
if not uid:
    print("[!] 未能获取 uid: " + json.dumps(resp, ensure_ascii=False)[:300], file=sys.stderr)
    sys.exit(1)

# ─── 4) 落盘 ───
expires_at = int(time.time()) + (expires_in if expires_in > 0 else 7200)
final_domain = domain or "codebuddy.cn"
doc = {
    "account": {"uid": uid, "enterpriseId": enterprise_id, "nickname": nickname},
    "auth": {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": expires_at,
        "domain": final_domain,
    },
}
out_path = os.path.join(AUTH_DIR, "workbuddy-%s.json" % uid)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=1, ensure_ascii=False)

print("[*] 已保存凭证: " + out_path)
print("[*] UID: %s  昵称: %s" % (uid, nickname or "（未获取）"))
PYEOF

echo ""
echo "============================================================"
echo "  登录完成！凭证已写入 auths/workbuddy-<uid>.json"
echo "  可运行 ./signin-workbuddy.sh 试签到"
echo "============================================================"