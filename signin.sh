#!/usr/bin/env bash
# signin.sh — TRAE 批量签到脚本，签到后通过 ntfy 推送通知
set -e
cd "$(dirname "$0")"

# ntfy 推送地址：运行前请自行 export NTFY_URL='https://ntfy.sh/你的主题'
# 注意：不要将真实 ntfy 主题硬编码进仓库。GitHub Actions 通过 secrets.NTFY_URL 注入。
NTFY_URL="${NTFY_URL:-}"
if [ -z "$NTFY_URL" ]; then
  echo "⚠️ 未设置 NTFY_URL，跳过 ntfy 推送。本地运行可先: export NTFY_URL='https://ntfy.sh/你的主题'"
fi

go build -o signin_bin ./cmd/signin

# 执行签到并捕获输出
SIGNIN_OUTPUT=$(./signin_bin "${1:-auths}" 2>&1)
SIGNIN_EXIT=$?

echo "$SIGNIN_OUTPUT"

# 提取关键信息用于 Bark 推送
TOTAL=$(echo "$SIGNIN_OUTPUT" | grep -oP '总计=\K\d+' || echo "?")
OK=$(echo "$SIGNIN_OUTPUT" | grep -oP '签到成功=\K\d+' || echo "?")
ALREADY=$(echo "$SIGNIN_OUTPUT" | grep -oP '已签=\K\d+' || echo "?")
FAIL=$(echo "$SIGNIN_OUTPUT" | grep -oP '失败=\K\d+' || echo "?")

# 提取每个账号的信息
ACCOUNTS=""
while IFS= read -r line; do
    if echo "$line" | grep -qP '│\s+\d+'; then
        uid=$(echo "$line" | sed 's/│/\n/g' | sed -n '2p' | xargs)
        nick=$(echo "$line" | sed 's/│/\n/g' | sed -n '3p' | xargs)
        status=$(echo "$line" | sed 's/│/\n/g' | sed -n '4p' | xargs)
        credits=$(echo "$line" | sed 's/│/\n/g' | sed -n '5p' | xargs)
        ACCOUNTS="${ACCOUNTS}${nick} ${status} 积分${credits}\n"
    fi
done <<< "$SIGNIN_OUTPUT"

# 构建 ntfy 推送内容
TITLE="TRAE 签到"
TAG="information_source"
if [ "$SIGNIN_EXIT" -eq 0 ]; then
    if [ "$OK" -gt 0 ] 2>/dev/null; then
        TITLE="✅ TRAE 签到成功"
        TAG="white_check_mark"
    elif [ "$FAIL" -gt 0 ] 2>/dev/null; then
        TITLE="⚠️ TRAE 签到异常"
        TAG="warning"
    else
        TITLE="📌 TRAE 已签到"
        TAG="pushpin"
    fi
else
    TITLE="❌ TRAE 签到失败"
    TAG="x"
fi

BODY="总计${TOTAL} | 成功${OK} | 已签${ALREADY} | 失败${FAIL}\n${ACCOUNTS}"

# 发送 ntfy 通知（标题走 Header，正文用 %b 把 \n 还原成真实换行）
if [ -n "$NTFY_URL" ]; then
  curl -s -H "Title: $TITLE" -H "Tags: $TAG" \
       -d "$(printf '%b' "$BODY")" "$NTFY_URL" > /dev/null 2>&1 || true
  echo "📲 ntfy 通知已发送"
else
  echo "📲 未配置 NTFY_URL，跳过 ntfy 推送"
fi
