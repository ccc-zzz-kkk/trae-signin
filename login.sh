#!/usr/bin/env bash
# login.sh — TRAE SOLO 登录：生成登录链接 → 浏览器登录 → 粘贴回调链接 → 换 token 落盘。
# 对齐官方客户端新流程（参考 rockswang/wild-work 逆向）：
#   - machine_id: 64 位 hex；device_id: 15 位数字（真实客户端格式）
#   - PKCE：登录 URL 带 code_challenge(S256)，回调 authCodeInfo.AuthCode + code_verifier + 设备公钥换 token
#   - 兼容旧回调（refreshToken / userJwt 兜底）
set -euo pipefail

cd "$(dirname "$0")"
AUTH_DIR="./auths"
CLIENT_ID="en1oxy7wnw8j9n"
APP_VERSION="0.1.52"
PLUGIN_VERSION="2.3.73734"
API_HOST="https://api.trae.com.cn"   # ExchangeToken(旧流程) / GetUserInfo
UG_HOST="https://api.trae.cn"        # PKCE 交换 / 签到接口
DEVICE_BRAND="20Y5A002XX"
OS_VERSION="Windows 10 Pro"

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

# ─── 生成机器/设备 id：与真实客户端格式一致 ───
MACHINE_ID="$(openssl rand -hex 32 2>/dev/null || "$PY" -c 'import secrets;print(secrets.token_hex(32))')"
DEVICE_ID="$("$PY" -c 'import secrets;print(int.from_bytes(secrets.token_bytes(8),"big")%900000000000000+100000000000000)' 2>/dev/null || true)"
if [[ -z "$DEVICE_ID" ]]; then
  RAW="$(od -An -N7 -tu8 /dev/urandom | tr -d ' \n')"
  DEVICE_ID="$(( RAW % 900000000000000 + 100000000000000 ))"
fi

# ─── PKCE：code_verifier 必须保存，交换 AuthCode 时用 ───
PKCE="$("$PY" - <<'PYEOF'
import base64, hashlib, secrets
v = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
print(v)
print(c)
PYEOF
)"
CODE_VERIFIER="$(echo "$PKCE" | sed -n '1p')"
CODE_CHALLENGE="$(echo "$PKCE" | sed -n '2p')"

# ─── 一次性 ECDSA P-256 设备密钥对：公钥随 AuthCode 交换上传 ───
# 优先 openssl；否则 cryptography 库；最后纯 Python 标准库（DER 手工编码）
DEVICE_PUB_PEM=""
if openssl ecparam -genkey -name prime256v1 -noout 2>/dev/null | openssl ec -pubout 2>/dev/null | grep -q "PUBLIC KEY"; then
  DEVICE_PUB_PEM="$(openssl ecparam -genkey -name prime256v1 -noout 2>/dev/null | openssl ec -pubout 2>/dev/null)"
fi
if [[ -z "$DEVICE_PUB_PEM" ]]; then
  DEVICE_PUB_PEM="$("$PY" - <<'PYEOF'
import base64, secrets

def gen_pub_pem():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        k = ec.generate_private_key(ec.SECP256R1())
        return k.public_key().public_bytes(serialization.Encoding.PEM,
              serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    except Exception:
        pass
    # 纯标准库：P-256 标量乘 + SPKI DER 编码
    p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a  = p - 3
    n  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    def inv(x, m): return pow(x, m - 2, m)
    def add(P, Q):
        if P is None: return Q
        if Q is None: return P
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
        if P == Q:
            lam = (3 * P[0] * P[0] + a) * inv(2 * P[1], p) % p
        else:
            lam = (Q[1] - P[1]) * inv(Q[0] - P[0], p) % p
        x = (lam * lam - P[0] - Q[0]) % p
        y = (lam * (P[0] - x) - P[1]) % p
        return (x, y)
    def mul(k, P):
        R = None
        while k:
            if k & 1: R = add(R, P)
            P = add(P, P)
            k >>= 1
        return R
    d = secrets.randbelow(n - 1) + 1
    x, y = mul(d, (gx, gy))
    point = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    # SPKI: SEQUENCE(0x59) { AlgorithmIdentifier, BIT STRING(0x00+point) }，共 91 字节
    spki = (b'\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01'
            b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00' + point)
    b64 = base64.encodebytes(spki).decode()
    return "-----BEGIN PUBLIC KEY-----\n" + b64 + "-----END PUBLIC KEY-----\n"

print(gen_pub_pem(), end="")
PYEOF
)"
fi
if [[ -z "$DEVICE_PUB_PEM" ]]; then
  echo "[!] 无法生成 ECDSA 设备密钥对"
  exit 1
fi

echo "============================================================"
echo "  TRAE SOLO 登录 - 纯签到版（新流程）"
echo "============================================================"
echo ""
echo "步骤："
echo "  1. 在浏览器打开下面链接，用手机号/验证码登录"
echo "  2. 登录成功后浏览器会跳到打不开的 127.0.0.1 地址"
echo "  3. 复制浏览器地址栏的完整链接，粘贴到下面"
echo ""

LOGIN_URL="$(MACHINE_ID="$MACHINE_ID" DEVICE_ID="$DEVICE_ID" CLIENT_ID="$CLIENT_ID" \
APP_VERSION="$APP_VERSION" PLUGIN_VERSION="$PLUGIN_VERSION" CODE_CHALLENGE="$CODE_CHALLENGE" \
DEVICE_BRAND="$DEVICE_BRAND" OS_VERSION="$OS_VERSION" "$PY" - <<'PYEOF'
import os, secrets, urllib.parse

def uuid4():
    b = bytearray(secrets.token_bytes(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

params = {
    "login_version": "1",
    "auth_from": "solo",
    "login_channel": "native_ide",
    "plugin_version": os.environ["PLUGIN_VERSION"],
    "auth_type": "local",
    "client_id": os.environ["CLIENT_ID"],
    "redirect": "0",
    "login_trace_id": uuid4(),
    "auth_callback_url": "http://127.0.0.1:18080/authorize",
    "machine_id": os.environ["MACHINE_ID"],
    "device_id": os.environ["DEVICE_ID"],
    "x_device_id": os.environ["DEVICE_ID"],
    "x_machine_id": os.environ["MACHINE_ID"],
    "x_device_brand": os.environ["DEVICE_BRAND"],
    "x_device_type": "windows",
    "x_os_version": os.environ["OS_VERSION"],
    "x_env": "",
    "x_app_version": os.environ["APP_VERSION"],
    "x_app_type": "stable",
    "code_challenge": os.environ["CODE_CHALLENGE"],
    "code_challenge_method": "S256",
    "hide_saas_login": "true",
    "channel_name": "common",
    "click_id": "TRAE SOLOSetup-stable-" + os.environ["PLUGIN_VERSION"],
}
print("https://www.trae.cn/authorization?" + urllib.parse.urlencode(params))
PYEOF
)"

echo "请在浏览器打开："
echo ""
echo "  $LOGIN_URL"
echo ""

read -rp "登录完成后，请粘贴浏览器地址栏的完整回调链接（不回显）: " -s callback_url || true
echo ""
if [[ -z "$callback_url" ]]; then
    echo "未输入回调链接，已取消"
    exit 1
fi

RESULT=$(CLIENT_ID="$CLIENT_ID" API_HOST="$API_HOST" UG_HOST="$UG_HOST" APP_VERSION="$APP_VERSION" \
MACHINE_ID="$MACHINE_ID" DEVICE_ID="$DEVICE_ID" CODE_VERIFIER="$CODE_VERIFIER" \
DEVICE_PUB_PEM="$DEVICE_PUB_PEM" DEVICE_BRAND="$DEVICE_BRAND" OS_VERSION="$OS_VERSION" \
CALLBACK_URL="$callback_url" "$PY" - <<'PYEOF'
import json, os, sys, time, urllib.parse, urllib.request, urllib.error

CLIENT_ID = os.environ["CLIENT_ID"]
API_HOST = os.environ["API_HOST"]
UG_HOST = os.environ["UG_HOST"]
APP_VERSION = os.environ["APP_VERSION"]
MACHINE_ID = os.environ["MACHINE_ID"]
DEVICE_ID = os.environ["DEVICE_ID"]
CODE_VERIFIER = os.environ["CODE_VERIFIER"]
DEVICE_PUB_PEM = os.environ["DEVICE_PUB_PEM"]
CALLBACK = os.environ["CALLBACK_URL"]

class HttpFail(Exception):
    pass

def http_post_json(url, body, headers, timeout=60, retries=2):
    req = urllib.request.Request(url, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    data = json.dumps(body).encode()
    last = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, data, timeout=timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            raise HttpFail(f"HTTP {e.code} ({url}): {raw[:400]}")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
            if attempt < retries:
                print(f"[*] 网络瞬时错误，重试 {attempt + 1}/{retries}: {e}", file=sys.stderr)
                time.sleep(1)
                continue
    raise HttpFail(f"请求失败 ({url}): {last}")

def parse_json_param(raw):
    if not raw:
        return None
    for val in (raw, urllib.parse.unquote(raw)):
        try:
            obj = json.loads(val)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return None

qs = urllib.parse.parse_qs(urllib.parse.urlparse(CALLBACK).query)
refresh_token = (qs.get("refreshToken") or [""])[0]
user_info = parse_json_param((qs.get("userInfo") or [""])[0]) or {}
user_jwt = parse_json_param((qs.get("userJwt") or [""])[0]) or {}

uid = str(user_info.get("UserID") or "")
nickname = str(user_info.get("ScreenName") or "")

# 回调凭证优先级：refreshToken（旧流程）→ authCodeInfo.AuthCode（PKCE 新流程）→ userJwt 兜底
auth_code = ""
raw_info = (qs.get("authCodeInfo") or [""])[0]
if raw_info:
    for val in (raw_info, urllib.parse.unquote(raw_info)):
        try:
            m = json.loads(val)
        except Exception:
            m = None
        if isinstance(m, dict):
            for container in (m, m.get("Result"), m.get("result")):
                if isinstance(container, dict) and container.get("AuthCode"):
                    auth_code = str(container["AuthCode"])
                    break
        elif val.strip():
            auth_code = val.strip()
        if auth_code:
            break

jwt_token = str(user_jwt.get("Token") or "")
jwt_refresh = str(user_jwt.get("RefreshToken") or "")
if not refresh_token:
    refresh_token = jwt_refresh

token, new_refresh, expires_at = "", refresh_token, 0

def normalize_exp(v, dur=0):
    if v and v > 10**12:
        v //= 1000
    if v and v > time.time():
        return int(v)
    if dur:
        d = dur / 1000 if dur > 10**9 else dur
        return int(time.time()) + int(d)
    return int(time.time()) + 1209600

if refresh_token:
    body = {"ClientID": CLIENT_ID, "RefreshToken": refresh_token, "ClientSecret": "-", "UserID": ""}
    try:
        resp = http_post_json(API_HOST + "/cloudide/api/v3/trae/oauth/ExchangeToken", body,
                              {"Content-Type": "application/json", "User-Agent": f"Trae/{APP_VERSION}"})
    except HttpFail as e:
        print(f"[!] ExchangeToken 失败: {e}", file=sys.stderr)
        sys.exit(1)
    result = resp.get("Result") or {}
    token = result.get("Token") or ""
    if not token:
        print("[!] ExchangeToken 失败: " + json.dumps(resp, ensure_ascii=False)[:300], file=sys.stderr)
        sys.exit(1)
    new_refresh = result.get("RefreshToken") or refresh_token
    expires_at = normalize_exp(int(result.get("TokenExpireAt") or 0), int(result.get("TokenExpireDuration") or 0))
    print("[*] ExchangeToken 成功（旧流程）")
elif auth_code:
    device_info = {
        "DeviceID": DEVICE_ID,
        "MachineID": MACHINE_ID,
        "PlatformCode": "SOLO_PC",
        "DeviceType": "PC",
        "DeviceName": os.environ.get("USERNAME") or os.environ.get("USER") or "PC",
        "DeviceModel": os.environ["DEVICE_BRAND"],
        "ClientVersion": APP_VERSION,
        "DevicePublicKey": DEVICE_PUB_PEM,
        "DeviceBrand": os.environ["DEVICE_BRAND"],
        "DeviceCPU": "",
        "OSInfo": "windows",
        "OSVersion": os.environ["OS_VERSION"],
    }
    body = {"ClientID": CLIENT_ID, "AuthCode": auth_code, "CodeVerifier": CODE_VERIFIER,
            "DeviceInfo": device_info, "IDEVersion": APP_VERSION}
    hdrs = {"Content-Type": "application/json", "Accept": "application/json",
            "User-Agent": f"Trae/{APP_VERSION}"}
    last_err = ""
    for origin in (UG_HOST, API_HOST):
        try:
            resp = http_post_json(origin + "/trae/api/v3/oauth/ExchangeToken", body, hdrs, retries=1)
        except HttpFail as e:
            last_err = str(e)
            continue
        result = resp.get("Result") or resp.get("result") or resp.get("data") or resp
        if isinstance(result, dict):
            token = result.get("AccessToken") or result.get("accessToken") or result.get("Token") or ""
            new_refresh = result.get("RefreshToken") or result.get("refreshToken") or ""
            expires_at = normalize_exp(int(result.get("TokenExpireAt") or result.get("ExpiresAt") or 0),
                                       int(result.get("TokenExpireDuration") or 0))
        if token:
            print(f"[*] AuthCode 交换成功（PKCE 新流程, {origin}）")
            break
        last_err = json.dumps(resp, ensure_ascii=False)[:300]
    if not token:
        print(f"[!] AuthCode 交换失败: {last_err}", file=sys.stderr)
        sys.exit(1)
elif jwt_token:
    token = jwt_token
    new_refresh = ""
    expires_at = normalize_exp(int(user_jwt.get("TokenExpireAt") or 0))
    print("[*] 使用 userJwt 的 Token 兜底")
else:
    print("[!] 回调链接缺少 refreshToken / authCodeInfo", file=sys.stderr)
    sys.exit(1)

try:
    ui = http_post_json(API_HOST + "/cloudide/api/v3/trae/GetUserInfo",
                        {"ReqSource": "IDE", "IDEVersion": APP_VERSION},
                        {"Content-Type": "application/json", "x-cloudide-token": token,
                         "User-Agent": f"Trae/{APP_VERSION}"})
    u = ui.get("Result") or ui
    if u.get("UserID"):
        uid = str(u.get("UserID") or uid)
        nickname = str(u.get("ScreenName") or nickname)
except Exception as e:
    print(f"[*] GetUserInfo 失败: {e}", file=sys.stderr)

if not uid:
    print("[!] 未能获取 uid", file=sys.stderr)
    sys.exit(1)

out = {
    "uid": uid, "nickname": nickname, "access_token": token,
    "refresh_token": new_refresh, "expires_at": expires_at,
    "api_host": API_HOST, "machine_id": MACHINE_ID, "device_id": DEVICE_ID,
}
print("JSON:" + json.dumps(out))
PYEOF
)

CRED=$(echo "$RESULT" | sed -n 's/^JSON://p')
if [[ -z "$CRED" ]]; then
    echo "$RESULT" >&2
    echo "解析/换 token 失败"
    exit 1
fi

ACCT_UID=$(echo "$CRED" | "$PY" -c "import json,sys; print(json.load(sys.stdin)['uid'])")
NICKNAME=$(echo "$CRED" | "$PY" -c "import json,sys; print(json.load(sys.stdin)['nickname'])")
TOKEN=$(echo "$CRED" | "$PY" -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
REFRESH=$(echo "$CRED" | "$PY" -c "import json,sys; print(json.load(sys.stdin)['refresh_token'])")
EXPIRES_AT=$(echo "$CRED" | "$PY" -c "import json,sys; print(json.load(sys.stdin)['expires_at'])")

AUTH_FILE="$AUTH_DIR/trae-${ACCT_UID}.json"
if [[ -f "$AUTH_FILE" ]]; then
    echo "账号已存在（uid=$ACCT_UID），将覆盖更新凭证"
    ACTION="覆盖"
else
    echo "新账号（uid=$ACCT_UID），新增 auth 文件"
    ACTION="新增"
fi

MACHINE_ID="$MACHINE_ID" DEVICE_ID="$DEVICE_ID" TOKEN="$TOKEN" REFRESH="$REFRESH" \
EXPIRES_AT="$EXPIRES_AT" ACCT_UID="$ACCT_UID" NICKNAME="$NICKNAME" AUTH_FILE="$AUTH_FILE" \
ACTION="$ACTION" "$PY" - <<'PYEOF'
import json, os
auth = {
    "account": {"uid": os.environ["ACCT_UID"], "enterpriseId": "", "nickname": os.environ["NICKNAME"]},
    "auth": {
        "accessToken": os.environ["TOKEN"],
        "refreshToken": os.environ["REFRESH"],
        "expiresAt": int(os.environ["EXPIRES_AT"]),
        "domain": "trae.cn",
        "apiHost": "https://api.trae.com.cn",
        "machineId": os.environ["MACHINE_ID"],
        "deviceId": os.environ["DEVICE_ID"],
    },
}
with open(os.environ["AUTH_FILE"], "w") as f:
    json.dump(auth, f, indent=1, ensure_ascii=False)
print(f"已保存（{os.environ['ACTION']}）: {os.environ['AUTH_FILE']}")
PYEOF

# 自动签到 + 查积分（带完整设备指纹头，登录后可立即验证）
TOKEN="$TOKEN" DEVICE_ID="$DEVICE_ID" APP_VERSION="$APP_VERSION" \
DEVICE_BRAND="$DEVICE_BRAND" OS_VERSION="$OS_VERSION" "$PY" - <<'PYEOF'
import json, os, urllib.request
UG = "https://api.trae.cn"
HDRS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "Trae/" + os.environ["APP_VERSION"],
    "Authorization": "Cloud-IDE-JWT " + os.environ["TOKEN"],
    "X-User-Region": "CN",
    "x-device-brand": os.environ["DEVICE_BRAND"],
    "x-device-type": "windows",
    "x-os-version": os.environ["OS_VERSION"],
    "x-app-version": os.environ["APP_VERSION"],
    "x-device-id": os.environ["DEVICE_ID"],
}
def post(path, body=b"{}"):
    req = urllib.request.Request(UG + path, method="POST", data=body, headers=HDRS)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode() or "{}")
try:
    st = post("/trae/api/v2/ug/checkin_credits/status")
    if st.get("code", 0) != 0:
        print(f"签到状态: {st.get('message', st)}")
    elif not st.get("checked_in") and st.get("enable"):
        r = post("/trae/api/v2/ug/checkin_credits/claim")
        print(f"签到: code={r.get('code')} {r.get('message', 'success')}")
    else:
        print(f"签到状态: checked_in={st.get('checked_in')} enable={st.get('enable')}")
except Exception as e:
    print(f"签到: {e}")
try:
    ent = post("/trae/api/v2/pay/ide_user_ent_usage")
    packs = ent.get("user_entitlement_pack_list") or []
    total = sum(p.get("entitlement_base_info", {}).get("quota", {}).get("credits_limit", 0) for p in packs)
    print(f"当前积分: {total}")
except Exception as e:
    print(f"查积分: {e}")
PYEOF

echo ""
echo "============================================================"
echo "  登录完成！"
echo "  UID: $ACCT_UID"
echo "  Nickname: ${NICKNAME:-（未获取到）}"
echo "  有效期: $(date -d "@$EXPIRES_AT" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$EXPIRES_AT")"
echo "============================================================"
