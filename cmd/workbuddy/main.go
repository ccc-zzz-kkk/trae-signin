// workbuddy — WorkBuddy/CodeBuddy 纯签到工具：遍历 auths/workbuddy-*.json 全部账号，
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
	"trae-signin/internal/workbuddy"
)

type row struct {
	file   string
	uid    string
	nick   string
	status string
	detail string
	remain int64
	hasRem bool
}

func main() {
	dir := "auths"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	files, err := filepath.Glob(filepath.Join(dir, "workbuddy-*.json"))
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "❌ 在 %s 中没有找到 workbuddy-*.json 凭证文件\n", dir)
		fmt.Fprintf(os.Stderr, "   请先运行 login-workbuddy.sh 登录账号\n")
		os.Exit(1)
	}
	sort.Strings(files)
	up := workbuddy.New()
	var rows []row
	okN, alreadyN, failN := 0, 0, 0
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
		// 每日签到
		credit, streak, already, cerr := up.DailyCheckin(a)
		switch {
		case cerr != nil:
			r.status = "FAIL"
			r.detail = short(cerr.Error())
			failN++
		case already:
			r.status = "ALREADY"
			r.detail = "今日已签到"
			alreadyN++
		default:
			r.status = "✅ OK"
			okN++
			switch {
			case credit > 0 && streak > 0:
				r.detail = fmt.Sprintf("本次 +%d，连续 %d 天", credit, streak)
			case credit > 0:
				r.detail = fmt.Sprintf("本次 +%d", credit)
			case streak > 0:
				r.detail = fmt.Sprintf("连续 %d 天", streak)
			}
		}
		// 查总积分
		if remain, qerr := up.UserResource(a); qerr == nil {
			r.remain, r.hasRem = remain, true
		}
		rows = append(rows, r)
	}
	// 报告
	fmt.Println()
	fmt.Println("┌──────────────────────────────────────┬───────────────┬──────────────┬──────────┬──────────────────────────────────────┐")
	fmt.Println("│ UID                                  │ 昵称          │ 状态         │ 总积分   │ 详情                                 │")
	fmt.Println("├──────────────────────────────────────┼───────────────┼──────────────┼──────────┼──────────────────────────────────────┤")
	for _, r := range rows {
		remain := "-"
		if r.hasRem {
			remain = fmt.Sprintf("%d", r.remain)
		}
		fmt.Printf("│ %-36s │ %-13s │ %-12s │ %-8s │ %-36s │\n",
			trunc(r.uid, 36), trunc(r.nick, 13), r.status, remain, trunc(r.detail, 36))
	}
	fmt.Println("└──────────────────────────────────────┴───────────────┴──────────────┴──────────┴──────────────────────────────────────┘")
	fmt.Println()
	fmt.Printf("📊 总计=%d  签到成功=%d  已签=%d  失败=%d\n", len(rows), okN, alreadyN, failN)
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