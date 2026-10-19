// Package upstream 封装 TRAE SOLO 签到、积分查询、Token 刷新等上游 API。
package upstream

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
	"trae-signin/internal/auth"
)

const (
	UgHost          = "https://api.trae.cn"
	OAuthHost       = "https://api.trae.com.cn"
	ClientID        = "en1oxy7wnw8j9n" // 旧客户端 / SOLO 线 token
	ClientIDIde     = "ono9krqynydwx5" // 新版桌面端 ClientID（续期优先）
	IdeVersion      = "1.107.1"
	IdeVersionCode  = "20260811"
	DeviceBrand     = "20Y5A002XX"
	OSVersion       = "10.0.19045"
	EpExchange      = "/cloudide/api/v3/trae/oauth/ExchangeToken" // 旧续期（无设备证明，兜底）
	EpExchangeProof = "/trae/api/v3/oauth/ExchangeToken"         // 新版续期（必须带设备证明）
	EpCheckinStatus = "/trae/api/v2/ug/checkin_credits/status"
	EpCheckinClaim  = "/trae/api/v2/ug/checkin_credits/claim"
	EpEntUsage      = "/trae/api/v2/pay/ide_user_ent_usage"
)

// reqSourceBody 签到/积分接口请求体，必须带 req_source（客户端同款），空体会被拒成 9074。
const reqSourceBody = `{"req_source":1}`

var clientUA = "Trae/" + IdeVersion

type Client struct {
	HTTP *http.Client
}

func New() *Client {
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{
		HTTP: &http.Client{Timeout: 60 * time.Second, Transport: tr},
	}
}
func (c *Client) doJSON(req *http.Request) (json.RawMessage, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return raw, nil
}

// RefreshToken 通过 ExchangeToken 强制刷新 access token。
// 新版接口要求带设备证明（ECDSA P-256 签名），缺了会返回 20405；有设备材料时优先走新端点。
func (c *Client) RefreshToken(a *auth.Auth) error {
	a.Lock()
	defer a.Unlock()
	if strings.TrimSpace(a.RefreshToken) == "" {
		return fmt.Errorf("no refreshToken")
	}
	if a.DevicePrivateKey != "" && a.DevicePublicKey != "" && a.DeviceID != "" {
		return c.refreshWithProof(a)
	}
	return c.refreshLegacy(a)
}

// refreshLegacy 旧端点续期（无设备证明），旧 token / 缺设备材料时兜底。
func (c *Client) refreshLegacy(a *auth.Auth) error {
	host := a.ApiHost
	if host == "" {
		host = OAuthHost
	}
	body := map[string]any{
		"ClientID":     ClientID,
		"RefreshToken": a.RefreshToken,
		"ClientSecret": "-",
		"UserID":       "",
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, host+EpExchange, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", clientUA)
	data, err := c.doJSON(req)
	if err != nil {
		return err
	}
	return applyExchangeResult(a, data)
}

// refreshWithProof 新版端点续期：带 DeviceProof + DeviceInfo。
// 依次尝试「新桌面 ClientID→旧 IDE→SOLO」组合，10101/20403 表示不匹配时换下一组。
func (c *Client) refreshWithProof(a *auth.Auth) error {
	path := EpExchangeProof
	combos := [][2]string{
		{ClientIDIde, "IDE_PC"},
		{ClientID, "IDE_PC"},
		{ClientID, "SOLO_PC"},
	}
	var lastErr error
	for _, combo := range combos {
		cid, pcode := combo[0], combo[1]
		proof, info, err := buildDeviceProof(path, cid, pcode, a)
		if err != nil {
			return fmt.Errorf("设备签名失败（检查设备私钥）: %w", err)
		}
		body := map[string]any{
			"ClientID":     cid,
			"ClientSecret": "",
			"RefreshToken": a.RefreshToken,
			"DeviceInfo":   info,
			"DeviceProof":  proof,
			"IDEVersion":   clientVersion(a),
		}
		raw, _ := json.Marshal(body)
		status, respRaw, err := c.postRaw(UgHost+path, map[string]string{
			"Content-Type":     "application/json",
			"x-cloudide-token": "",
		}, raw)
		if err != nil {
			lastErr = err
			continue
		}
		if status < 400 {
			return applyExchangeResult(a, respRaw)
		}
		lastErr = fmt.Errorf("refresh http=%d %s", status, explainRefreshErr(respRaw))
		// 10101（token 与客户端不匹配）/ 20403（设备不匹配）→ 换下一组组合再试
		if !strings.Contains(string(respRaw), "10101") && !strings.Contains(string(respRaw), "20403") {
			break
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("refresh_failed: no token — re-login required")
}

// applyExchangeResult 解析并写回 ExchangeToken 返回的新 token（旧/新端点共用结构）。
func applyExchangeResult(a *auth.Auth, data []byte) error {
	var resp struct {
		Result struct {
			Token               string `json:"Token"`
			TokenExpireAt       int64  `json:"TokenExpireAt"`
			TokenExpireDuration int64  `json:"TokenExpireDuration"`
			RefreshToken        string `json:"RefreshToken"`
		} `json:"Result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("exchange parse: %w", err)
	}
	if resp.Result.Token == "" {
		return fmt.Errorf("refresh_failed: no token — re-login required")
	}
	a.AccessToken = resp.Result.Token
	if resp.Result.RefreshToken != "" {
		a.RefreshToken = resp.Result.RefreshToken
	}
	switch {
	case resp.Result.TokenExpireAt > 0:
		exp := resp.Result.TokenExpireAt
		if exp > 1e12 {
			exp /= 1000
		}
		a.ExpiresAt = exp
	case resp.Result.TokenExpireDuration > 0:
		a.ExpiresAt = time.Now().Add(time.Duration(resp.Result.TokenExpireDuration) * time.Second).Unix()
	default:
		if exp := jwtExp(resp.Result.Token); exp > 0 {
			a.ExpiresAt = exp
		}
	}
	return nil
}

// buildDeviceProof 构造新版 ExchangeToken 的 (DeviceProof, DeviceInfo)。
func buildDeviceProof(path, clientID, platformCode string, a *auth.Auth) (proof, info map[string]any, err error) {
	ts := time.Now().Unix()
	nonce := randomHex(16)
	canonical := strings.Join([]string{"POST", path, clientID, a.RefreshToken, strconv.FormatInt(ts, 10), nonce}, "\n")
	sig, err := ecdsaSignP256(a.DevicePrivateKey, []byte(canonical))
	if err != nil {
		return nil, nil, err
	}
	proof = map[string]any{
		"Timestamp": ts,
		"Nonce":     nonce,
		"Signature": sig,
	}
	ver := clientVersion(a)
	info = map[string]any{
		"DeviceID":        a.DeviceID,
		"MachineID":       a.MachineID,
		"PlatformCode":    platformCode,
		"DeviceType":      "PC",
		"DeviceName":      "PC",
		"DeviceModel":     DeviceBrand,
		"ClientVersion":   ver,
		"DevicePublicKey": a.DevicePublicKey,
		"DeviceBrand":     DeviceBrand,
		"DeviceCPU":       "",
		"OSInfo":          "Windows",
		"OSVersion":       OSVersion,
	}
	return proof, info, nil
}

func clientVersion(a *auth.Auth) string {
	if strings.TrimSpace(a.ClientVersion) != "" {
		return a.ClientVersion
	}
	return IdeVersion
}

// ecdsaSignP256 ECDSA P-256 / SHA-256 签名，返回 base64(DER)，低 s 归一化（与客户端一致）。
func ecdsaSignP256(pemPriv string, payload []byte) (string, error) {
	priv, err := parseECPrivateKey(pemPriv)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return "", err
	}
	n := priv.Curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	return base64.StdEncoding.EncodeToString(encodeECDSASigDER(r, s)), nil
}

func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("设备私钥 PEM 解析失败")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ec, ok := k.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, fmt.Errorf("设备私钥不是 ECDSA 私钥")
	}
	return nil, fmt.Errorf("设备私钥格式无法识别（需 EC PRIVATE KEY 或 PKCS#8）")
}

func encodeECDSASigDER(r, s *big.Int) []byte {
	enc := func(x *big.Int) []byte {
		b := x.Bytes()
		if len(b) == 0 {
			b = []byte{0}
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	rb := enc(r)
	sb := enc(s)
	body := append(append([]byte{}, rb...), sb...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return fmt.Sprintf("%x", b)
}

// jwtExp 从 accessToken 的 JWT 里读到期（秒）：优先标准 exp，其次中国版 tokenExpireAt/TokenExpireAt（可能为字符串）。
func jwtExp(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0
	}
	for _, k := range []string{"exp", "TokenExpireAt", "tokenExpireAt"} {
		if v, ok := payload[k]; ok {
			if f := toFloat(v); f > 0 {
				if f > 1e11 { // 毫秒量级 → 秒
					f /= 1000
				}
				return int64(f)
			}
		}
	}
	return 0
}

func toFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		var f float64
		fmt.Sscanf(strings.TrimSpace(t), "%f", &f)
		return f
	case int64:
		return float64(t)
	case int:
		return float64(t)
	}
	return 0
}

// explainRefreshErr 把 ExchangeToken 的错误码翻译成人话。
func explainRefreshErr(raw []byte) string {
	var e struct {
		ResponseMetadata struct {
			Error struct {
				Code    int64  `json:"Code"`
				Message string `json:"Message"`
				Data    struct {
					MsgError string `json:"__Message.error"`
				} `json:"Data"`
			} `json:"Error"`
		} `json:"ResponseMetadata"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return truncate(string(raw), 200)
	}
	code := e.ResponseMetadata.Error.Code
	msg := e.ResponseMetadata.Error.Data.MsgError
	if msg == "" {
		msg = e.ResponseMetadata.Error.Message
	}
	hints := map[int64]string{
		20101: "refreshToken 已失效或被轮换，请重新登录",
		10101: "refreshToken 与客户端不匹配，请重新登录",
		20405: "服务端要求设备证明：请确认已配置设备私钥/公钥/设备号",
		20403: "设备与 token 不匹配：确认密钥与签发该 token 的是同一设备",
	}
	h := hints[code]
	if h != "" {
		h = "（" + h + "）"
	}
	return fmt.Sprintf("code=%d %s%s", code, msg, h)
}

// postRaw 直接 POST JSON 并返回原始状态码与响应体（用于需要区分业务码/状态码的场景）。
func (c *Client) postRaw(url string, headers map[string]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

// CheckinStatus 查询签到状态。
func (c *Client) CheckinStatus(a *auth.Auth) (checkedIn bool, credits int64, enable bool, err error) {
	req, err := http.NewRequest(http.MethodPost, UgHost+EpCheckinStatus, bytes.NewReader([]byte(reqSourceBody)))
	if err != nil {
		return false, 0, false, err
	}
	ugHeaders(req, a)
	data, err := c.doJSON(req)
	if err != nil {
		return false, 0, false, err
	}
	if err := checkBizCode(data); err != nil {
		return false, 0, false, err
	}
	var resp struct {
		CheckedIn bool  `json:"checked_in"`
		Credits   int64 `json:"credits"`
		Enable    bool  `json:"enable"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return false, 0, false, fmt.Errorf("checkin status parse: %w", err)
	}
	return resp.CheckedIn, resp.Credits, resp.Enable, nil
}

// CheckinClaim 执行签到。
// 注意：claim 接口在限流等场景仍返回 HTTP 200，需解析响应体中的业务码，
// 避免「日志显示成功、实际未签到」。
func (c *Client) CheckinClaim(a *auth.Auth) error {
	req, err := http.NewRequest(http.MethodPost, UgHost+EpCheckinClaim, bytes.NewReader([]byte(reqSourceBody)))
	if err != nil {
		return err
	}
	ugHeaders(req, a)
	data, err := c.doJSON(req)
	if err != nil {
		return err
	}
	if err := checkBizCode(data); err != nil {
		return fmt.Errorf("claim failed: %w", err)
	}
	return nil
}

// UserEntUsage 查询剩余积分：优先使用 usage_summary（剩余 = 总额 - 已消耗），
// 与 Trae App 显示口径一致；无汇总数据时回退为各权益包 credits_limit 之和。
func (c *Client) UserEntUsage(a *auth.Auth) (remain float64, err error) {
	req, err := http.NewRequest(http.MethodPost, UgHost+EpEntUsage, bytes.NewReader([]byte(reqSourceBody)))
	if err != nil {
		return 0, err
	}
	ugHeaders(req, a)
	data, err := c.doJSON(req)
	if err != nil {
		return 0, err
	}
	if err := checkBizCode(data); err != nil {
		return 0, err
	}
	var resp struct {
		UsageSummary struct {
			ConsumedAmount float64 `json:"consumed_amount"`
			TotalAmount    float64 `json:"total_amount"`
		} `json:"usage_summary"`
		UserEntitlementPackList []struct {
			EntitlementBaseInfo struct {
				Quota struct {
					CreditsLimit int64 `json:"credits_limit"`
				} `json:"quota"`
			} `json:"entitlement_base_info"`
		} `json:"user_entitlement_pack_list"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, fmt.Errorf("ent usage parse: %w", err)
	}
	if resp.UsageSummary.TotalAmount > 0 {
		return resp.UsageSummary.TotalAmount - resp.UsageSummary.ConsumedAmount, nil
	}
	var limit int64
	for _, p := range resp.UserEntitlementPackList {
		limit += p.EntitlementBaseInfo.Quota.CreditsLimit
	}
	return float64(limit), nil
}

// ugHeaders 设置 UG（签到/积分）接口请求头。
// 注意：官方客户端会注入设备指纹头，服务端校验这些头，
// 缺任一项会以业务码 9074（"当前参与用户太多"）拒绝，与真实限流无关。
// x-device-id 只发小写（同时发大小写两个头会被风控判为异常客户端）。
func ugHeaders(req *http.Request, a *auth.Auth) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("Authorization", "Cloud-IDE-JWT "+a.JWT())
	req.Header.Set("X-User-Region", "CN")
	req.Header.Set("x-device-type", "Windows")
	req.Header.Set("x-os-version", OSVersion)
	req.Header.Set("x-app-version", IdeVersion)
	req.Header.Set("x-device-brand", DeviceBrand)
	if a.DeviceID != "" {
		req.Header.Set("x-device-id", a.DeviceID) // 值须为账号真实注册的设备 ID
	}
}

// checkBizCode 校验上游 UG 接口的统一业务码。
// 这些接口即使业务失败也常返回 HTTP 200，仅靠状态码判断会误报成功；
// 若响应体是 {code, message} 结构且 code != 0，则返回错误，由调用方决定如何归类。
func checkBizCode(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var b struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
		Msg     string `json:"msg"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		// 响应体不是统一业务码结构，交给调用方自行按字段解析。
		return nil
	}
	if b.Code == 0 {
		return nil
	}
	msg := b.Message
	if msg == "" {
		msg = b.Msg
	}
	if msg == "" {
		return fmt.Errorf("code=%d", b.Code)
	}
	return fmt.Errorf("code=%d: %s", b.Code, msg)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
