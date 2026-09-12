// signin — TRAE 纯签到工具：遍历 auths/trae-*.json 全部账号，
// 自动刷新过期 token，逐个签到并查询积分。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"trae-signin/internal/auth"
	"trae-signin/internal/upstream"
)

type row struct {
	file   string
	uid    string
	nick   string
	status string
	detail string
	remain float64
	hasRem bool
}

func main() {
	dir := "auths"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	files, err := filepath.Glob(filepath.Join(dir, "trae-*.json"))
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "❌ 在 %s 中没有找到 trae-*.json 凭证文件\n", dir)
		fmt.Fprintf(os.Stderr, "   请先运行 login.sh 登录账号\n")
		os.Exit(1)
	}
	sort.Strings(files)
	up := upstream.New()
	var rows []row
	okN, alreadyN, failN, disabledN := 0, 0, 0, 0
	for _, f := range files {
		r := row{file: filepath.Base(f)}
		raw, err := os.ReadFile(f)
		if err != nil {
			r.status, r.detail = "LOAD_ERR", err.Error()
			rows = append(rows, r)
			failN++
			continue
		}
		a, err := auth.Parse(raw)
		if err != nil {
			r.status, r.detail = "LOAD_ERR", err.Error()
			rows = append(rows, r)
			failN++
			continue
		}
		a.FilePath = f
		r.uid, r.nick = a.UID, a.Nickname
		// 刷新过期 token（2h 缓冲）
		if a.NeedsRefresh(2 * time.Hour) {
			fmt.Printf("🔄 %s token 即将过期，正在刷新...\n", r.uid)
			if err := up.RefreshToken(a); err != nil {
				r.status = "FAIL"
				r.detail = "refresh: " + short(err.Error())
				rows = append(rows, r)
				failN++
				continue
			}
			_ = a.SaveAtomic()
			fmt.Printf("   ✅ token 刷新成功\n")
		}
		// 签到
		checkedIn, _, enable, serr := up.CheckinStatus(a)
		switch {
		case serr != nil:
			if isAlready(serr.Error()) {
				r.status = "ALREADY"
				r.detail = short(serr.Error())
				alreadyN++
			} else {
				r.status = "FAIL"
				r.detail = short(serr.Error())
				failN++
			}
		case checkedIn:
			r.status = "ALREADY"
			r.detail = "今日已签到"
			alreadyN++
		case !enable:
			r.status = "DISABLED"
			r.detail = "签到已禁用"
			disabledN++
		default:
			claimErr := claimWithRetry(up, a, r.uid)
			switch {
			case claimErr == nil:
				r.status = "✅ OK"
				okN++
			case isAlready(claimErr.Error()):
				r.status = "ALREADY"
				r.detail = "今日已签到"
				alreadyN++
			default:
				r.status = "FAIL"
				r.detail = short(claimErr.Error())
				failN++
			}
		}
		// 查剩余积分
		if remain, qerr := up.UserEntUsage(a); qerr == nil {
			r.remain, r.hasRem = remain, true
		}
		rows = append(rows, r)
	}
	// 报告
	fmt.Println()
	fmt.Println("┌──────────────────────────────────────┬───────────────┬──────────────┬──────────┬──────────────────────────────────────┐")
	fmt.Println("│ UID                                  │ 昵称          │ 状态         │ 剩余积分 │ 详情                                 │")
	fmt.Println("├──────────────────────────────────────┼───────────────┼──────────────┼──────────┼──────────────────────────────────────┤")
	for _, r := range rows {
		remain := "-"
		if r.hasRem {
			remain = fmt.Sprintf("%.2f", r.remain)
		}
		fmt.Printf("│ %-36s │ %-13s │ %-12s │ %-8s │ %-36s │\n",
			trunc(r.uid, 36), trunc(r.nick, 13), r.status, remain, trunc(r.detail, 36))
	}
	fmt.Println("└──────────────────────────────────────┴───────────────┴──────────────┴──────────┴──────────────────────────────────────┘")
	fmt.Println()
	fmt.Printf("📊 总计=%d  签到成功=%d  已签=%d  禁用=%d  失败=%d\n", len(rows), okN, alreadyN, disabledN, failN)
}

const claimMaxRetries = 3

// claimWithRetry 执行签到；失败时（如限流等瞬时错误）按递增间隔自动重试。
// 返回 nil 表示签到成功；返回「已签到」类错误表示今日已签；其余为最终失败。
func claimWithRetry(up *upstream.Client, a *auth.Auth, uid string) error {
	var lastErr error
	for i := 0; i <= claimMaxRetries; i++ {
		if i > 0 {
			delay := time.Duration(5*i) * time.Second
			fmt.Printf("   ⏳ %s 签到未成功（%s），%d 秒后重试 %d/%d...\n",
				uid, short(lastErr.Error()), int(delay.Seconds()), i, claimMaxRetries)
			time.Sleep(delay)
		}
		err := up.CheckinClaim(a)
		if err == nil {
			return nil
		}
		lastErr = err
		if isAlready(err.Error()) {
			return err
		}
	}
	return fmt.Errorf("重试 %d 次仍失败: %s", claimMaxRetries, short(lastErr.Error()))
}

func isAlready(msg string) bool {
	s := strings.ToLower(msg)
	return strings.Contains(s, "已签到") ||
		strings.Contains(s, "already check") ||
		strings.Contains(s, "already checked")
}
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
func short(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 60 {
		return s[:60]
	}
	return s
}
