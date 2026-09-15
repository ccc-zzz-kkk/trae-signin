// Package workbuddy 封装 WorkBuddy/CodeBuddy 的 OAuth 设备登录、Token 刷新、
// 每日签到与积分查询等上游 API。
//
// 关键来源为官方 CLI 2.139.0 的逆向实现（见 cli2api / 77cinc/workbuddy-daily-checkin）：
//   - 鉴权域 https://copilot.tencent.com，计费域 https://www.codebuddy.cn
//   - 登录：POST /v2/plugin/auth/state 拿 state → 浏览器授权 → GET /v2/plugin/auth/token 轮询换 token
//   - 身份：GET /v2/plugin/login/account 用 state + Bearer 换取 uid/enterpriseId/nickname
//   - 刷新：POST /v2/plugin/auth/token/refresh，body 为 {}，refreshToken 走 X-Refresh-Token 头
package workbuddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"trae-signin/internal/auth"
)

const (
	AuthHost    = "https://copilot.tencent.com"
	BillingHost = "https://www.codebuddy.cn"
	UserAgent   = "CLI/2.139.0 CodeBuddy/2.139.0"
	Origin      = "https://www.codebuddy.cn"

	EpAuthState    = "/v2/plugin/auth/state"
	EpAuthToken    = "/v2/plugin/auth/token"
	EpAuthAccount  = "/v2/plugin/login/account"
	EpTokenRefresh = "/v2/plugin/auth/token/refresh"
	EpDailyCheckin = "/v2/billing/meter/daily-checkin"
	EpUserResource = "/v2/billing/meter/get-user-resource"
)

// envelope 是 WorkBuddy 上游统一响应包裹：{code, msg, data}。
// 业务失败也常返回 HTTP 200，仅靠状态码会误报，需同时校验 code。
type envelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

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
		HTTP: &http.Client{
			Timeout:   60 * time.Second,
			Transport: tr,
			// 路径不匹配时插件接口会 302 到 OIDC/登录 HTML，
			// 跟随重定向会丢失真实状态码，这里保留原始响应。
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *Client) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, nil
}

func commonHeaders(h http.Header) {
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/plain, */*")
	h.Set("X-Requested-With", "XMLHttpRequest")
	h.Set("Origin", Origin)
	h.Set("Referer", Origin+"/")
	h.Set("User-Agent", UserAgent)
}

// billingHeaders 设置计费域（签到/积分）请求头。
// 官方客户端要求 Bearer 前缀，缺前缀会 401；X-User-Id/X-Domain 一并注入。
func billingHeaders(h http.Header, a *auth.Auth) {
	commonHeaders(h)
	h.Set("Authorization", "Bearer "+a.JWT())
	if a.UID != "" {
		h.Set("X-User-Id", a.UID)
	}
	if a.EnterpriseID != "" {
		h.Set("X-Enterprise-Id", a.EnterpriseID)
		h.Set("X-Tenant-Id", a.EnterpriseID)
	}
	if a.Domain != "" {
		h.Set("X-Domain", a.Domain)
	}
}

// GetLoginState 请求服务端下发 state 与授权 URL（设备授权流程第一步）。
func (c *Client) GetLoginState() (state, authURL string, err error) {
	req, _ := http.NewRequest(http.MethodPost, AuthHost+EpAuthState+"?platform=CLI", bytes.NewReader([]byte("{}")))
	commonHeaders(req.Header)
	raw, status, err := c.do(req)
	if err != nil {
		return "", "", err
	}
	if status >= 300 {
		return "", "", fmt.Errorf("auth state http %d: %s", status, truncate(string(raw), 200))
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Code != 0 {
		return "", "", fmt.Errorf("auth state code=%d msg=%s", env.Code, env.Msg)
	}
	var data struct {
		State   string `json:"state"`
		AuthURL string `json:"authUrl"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil || data.State == "" {
		return "", "", fmt.Errorf("auth state response missing state")
	}
	return data.State, data.AuthURL, nil
}

// PollToken 用 state 轮询 /v2/plugin/auth/token 换 token，并拉取账号身份。
// 用户尚未完成浏览器授权时返回 waiting=true，调用方应稍后重试。
func (c *Client) PollToken(state string) (a auth.Auth, waiting bool, err error) {
	req, _ := http.NewRequest(http.MethodGet, AuthHost+EpAuthToken+"?state="+url.QueryEscape(state), nil)
	commonHeaders(req.Header)
	raw, status, err := c.do(req)
	if err != nil {
		return auth.Auth{}, false, err
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	if status >= 500 {
		return auth.Auth{}, false, fmt.Errorf("token http %d", status)
	}
	if status >= 300 || env.Code != 0 {
		return auth.Auth{}, true, nil
	}
	var data struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int64  `json:"expiresIn"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil || data.AccessToken == "" {
		return auth.Auth{}, true, nil
	}
	uid, ent, nick, err := c.account(state, data.AccessToken)
	if err != nil {
		return auth.Auth{}, false, err
	}
	domain := data.Domain
	if domain == "" {
		domain = "codebuddy.cn"
	}
	expiresAt := time.Now().Add(time.Duration(data.ExpiresIn) * time.Second).Unix()
	if data.ExpiresIn <= 0 {
		expiresAt = 0
	}
	return auth.Auth{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresAt:    expiresAt,
		Domain:       domain,
		UID:          uid,
		EnterpriseID: ent,
		Nickname:     nick,
	}, false, nil
}

func (c *Client) account(state, accessToken string) (uid, enterpriseID, nickname string, err error) {
	req, _ := http.NewRequest(http.MethodGet, AuthHost+EpAuthAccount+"?state="+url.QueryEscape(state), nil)
	commonHeaders(req.Header)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	raw, _, err := c.do(req)
	if err != nil {
		return "", "", "", err
	}
	var env envelope
	var id struct {
		UID          string `json:"uid"`
		EnterpriseID string `json:"enterpriseId"`
		Nickname     string `json:"nickname"`
	}
	if json.Unmarshal(raw, &env) == nil && env.Code == 0 {
		_ = json.Unmarshal(env.Data, &id)
	}
	return id.UID, id.EnterpriseID, id.Nickname, nil
}

// RefreshToken 用 refreshToken 刷新 access token。
// 官方客户端把 refreshToken 放在 X-Refresh-Token 头，body 为 {}。
func (c *Client) RefreshToken(a *auth.Auth) error {
	a.Lock()
	defer a.Unlock()
	rt := a.RefreshToken
	if strings.TrimSpace(rt) == "" {
		return fmt.Errorf("no refreshToken")
	}
	req, _ := http.NewRequest(http.MethodPost, AuthHost+EpTokenRefresh, bytes.NewReader([]byte("{}")))
	commonHeaders(req.Header)
	req.Header.Set("X-Refresh-Token", rt)
	req.Header.Set("X-Auth-Refresh-Source", "workbuddy")
	if a.EnterpriseID != "" {
		req.Header.Set("X-Enterprise-Id", a.EnterpriseID)
	}
	raw, status, err := c.do(req)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("refresh http %d: %s", status, truncate(string(raw), 200))
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Code != 0 {
		return fmt.Errorf("refresh code=%d msg=%s", env.Code, env.Msg)
	}
	var data struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int64  `json:"expiresIn"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil || data.AccessToken == "" {
		return fmt.Errorf("refresh response missing accessToken")
	}
	a.AccessToken = data.AccessToken
	if data.RefreshToken != "" {
		a.RefreshToken = data.RefreshToken
	}
	if data.Domain != "" {
		a.Domain = data.Domain
	}
	if data.ExpiresIn > 0 {
		a.ExpiresAt = time.Now().Add(time.Duration(data.ExpiresIn) * time.Second).Unix()
	}
	return nil
}

// DailyCheckin 执行每日签到。返回本次积分、连续天数。
// 今日已签到时 already=true（不视为错误，重复调用幂等）。
func (c *Client) DailyCheckin(a *auth.Auth) (credit int64, streak int64, already bool, err error) {
	req, _ := http.NewRequest(http.MethodPost, BillingHost+EpDailyCheckin, bytes.NewReader([]byte("{}")))
	billingHeaders(req.Header, a)
	raw, status, err := c.do(req)
	if err != nil {
		return 0, 0, false, err
	}
	text := strings.TrimSpace(string(raw))
	if status >= 300 {
		return 0, 0, false, fmt.Errorf("checkin http %d: %s", status, truncate(text, 200))
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, 0, false, fmt.Errorf("checkin parse: %w", err)
	}
	msg := strings.TrimSpace(env.Msg)
	lower := strings.ToLower(msg)
	if env.Code != 0 {
		if strings.Contains(msg, "已签到") || (strings.Contains(lower, "already") && strings.Contains(lower, "check")) {
			return 0, 0, true, nil
		}
		if msg == "" {
			msg = fmt.Sprintf("code=%d", env.Code)
		}
		return 0, 0, false, fmt.Errorf("%s", msg)
	}
	// data 字段在官方客户端与各逆向实现间有 snake/camel 两种写法，做兼容解析。
	var d struct {
		Credit        int64 `json:"credit"`
		DailyCredit   int64 `json:"daily_credit"`
		DailyCreditCc int64 `json:"dailyCredit"`
		StreakDays    int64 `json:"streak_days"`
		StreakDaysCc  int64 `json:"streakDays"`
	}
	_ = json.Unmarshal(env.Data, &d)
	credit = firstNonZero(d.Credit, d.DailyCredit, d.DailyCreditCc)
	streak = firstNonZero(d.StreakDays, d.StreakDaysCc)
	return credit, streak, false, nil
}

// UserResource 查询总积分（data.Response.Data.TotalDosage），与桌面端口径一致。
func (c *Client) UserResource(a *auth.Auth) (totalDosage int64, err error) {
	now := time.Now()
	body := map[string]any{
		"PageNumber":               1,
		"PageSize":                 100,
		"ProductCode":              "p_tcaca",
		"Status":                   []int{0, 3},
		"PackageEndTimeRangeBegin": now.Format("2006-01-02 15:04:05"),
		"PackageEndTimeRangeEnd":   now.Add(365 * 101 * 24 * time.Hour).Format("2006-01-02 15:04:05"),
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, BillingHost+EpUserResource, bytes.NewReader(raw))
	billingHeaders(req.Header, a)
	resp, status, err := c.do(req)
	if err != nil {
		return 0, err
	}
	if status >= 300 {
		return 0, fmt.Errorf("user-resource http %d: %s", status, truncate(string(resp), 200))
	}
	var env struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Response struct {
				Data struct {
					TotalDosage int64 `json:"TotalDosage"`
				} `json:"Data"`
			} `json:"Response"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &env); err != nil {
		return 0, fmt.Errorf("user-resource parse: %w", err)
	}
	if env.Code != 0 {
		return 0, fmt.Errorf("user-resource code=%d msg=%s", env.Code, env.Msg)
	}
	return env.Data.Response.Data.TotalDosage, nil
}

func firstNonZero(vals ...int64) int64 {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}