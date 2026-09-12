// Package upstream 封装 TRAE SOLO 签到、积分查询、Token 刷新等上游 API。
package upstream

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"trae-signin/internal/auth"
)

const (
	UgHost          = "https://api.trae.cn"
	OAuthHost       = "https://api.trae.com.cn"
	ClientID        = "en1oxy7wnw8j9n"
	IdeVersion      = "0.1.52"
	IdeVersionCode  = "20260811"
	DeviceBrand     = "20Y5A002XX"
	OSVersion       = "Windows 10 Pro"
	EpExchange      = "/cloudide/api/v3/trae/oauth/ExchangeToken"
	EpCheckinStatus = "/trae/api/v2/ug/checkin_credits/status"
	EpCheckinClaim  = "/trae/api/v2/ug/checkin_credits/claim"
	EpEntUsage      = "/trae/api/v2/pay/ide_user_ent_usage"
)

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
func (c *Client) RefreshToken(a *auth.Auth) error {
	a.Lock()
	defer a.Unlock()
	if strings.TrimSpace(a.RefreshToken) == "" {
		return fmt.Errorf("no refreshToken")
	}
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
	if resp.Result.TokenExpireAt > 0 {
		exp := resp.Result.TokenExpireAt
		if exp > 1e12 {
			exp /= 1000
		}
		a.ExpiresAt = exp
	} else if resp.Result.TokenExpireDuration > 0 {
		a.ExpiresAt = time.Now().Add(time.Duration(resp.Result.TokenExpireDuration) * time.Second).Unix()
	}
	return nil
}

// CheckinStatus 查询签到状态。
func (c *Client) CheckinStatus(a *auth.Auth) (checkedIn bool, credits int64, enable bool, err error) {
	req, err := http.NewRequest(http.MethodPost, UgHost+EpCheckinStatus, bytes.NewReader([]byte("{}")))
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
	req, err := http.NewRequest(http.MethodPost, UgHost+EpCheckinClaim, bytes.NewReader([]byte("{}")))
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
	req, err := http.NewRequest(http.MethodPost, UgHost+EpEntUsage, bytes.NewReader([]byte("{}")))
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
func ugHeaders(req *http.Request, a *auth.Auth) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("Authorization", "Cloud-IDE-JWT "+a.JWT())
	req.Header.Set("X-User-Region", "CN")
	req.Header.Set("x-device-brand", DeviceBrand)
	req.Header.Set("x-device-type", "windows")
	req.Header.Set("x-os-version", OSVersion)
	req.Header.Set("x-app-version", IdeVersion)
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
	return fmt.Errorf("%s", msg)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
