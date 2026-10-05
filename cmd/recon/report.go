package main

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mogpnet/targetscan/internal/models"
)

func hostKeyOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

func groupDirsByHost(dirs []models.DirResult) map[string][]models.DirResult {
	groups := make(map[string][]models.DirResult)
	for _, d := range dirs {
		k := hostKeyOf(d.URL)
		groups[k] = append(groups[k], d)
	}
	for k := range groups {
		sort.SliceStable(groups[k], func(i, j int) bool {
			return groups[k][i].URL < groups[k][j].URL
		})
	}
	return groups
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "s2"
	case code >= 300 && code < 400:
		return "s3"
	case code >= 400:
		return "s4"
	}
	return ""
}

func writeReport(domain string, subdomainsTotal int, liveHosts []models.HostResult, dirs []models.DirResult, elapsed time.Duration) {
	hosts := append([]models.HostResult(nil), liveHosts...)
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].URL < hosts[j].URL })

	groups := groupDirsByHost(dirs)
	totalDirs := len(dirs)

	safe := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(domain)
	txtPath := safe + ".txt"
	htmlPath := safe + ".html"

	writeTXT(txtPath, domain, subdomainsTotal, hosts, groups, totalDirs, elapsed)
	writeHTML(htmlPath, domain, subdomainsTotal, hosts, groups, totalDirs, elapsed)

	fmt.Printf("[+] Отчёты сохранены: %s и %s\n", txtPath, htmlPath)
}

func writeTXT(path, domain string, subdomainsTotal int, hosts []models.HostResult, groups map[string][]models.DirResult, totalDirs int, elapsed time.Duration) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("TargetScan report: %s\n", domain))
	sb.WriteString(fmt.Sprintf("Дата: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Поддоменов найдено: %d | Живых хостов: %d | Директорий: %d | Время: %v\n",
		subdomainsTotal, len(hosts), totalDirs, elapsed.Round(time.Millisecond)))

	sb.WriteString("\n=== ЖИВЫЕ ХОСТЫ ===\n")
	for _, h := range hosts {
		sb.WriteString(fmt.Sprintf("[%d] %s | IP: %s | Server: %s | Title: %s\n",
			h.StatusCode, h.URL, orDash(h.IP), orDash(h.Server), orDash(h.Title)))
	}

	sb.WriteString("\n=== ДИРЕКТОРИИ ===\n")
	anyDirs := false
	for _, h := range hosts {
		hostDirs, ok := groups[h.URL]
		if !ok || len(hostDirs) == 0 {
			continue
		}
		anyDirs = true
		sb.WriteString(fmt.Sprintf("\n--- %s (%d) ---\n", h.URL, len(hostDirs)))
		for _, d := range hostDirs {
			sb.WriteString(fmt.Sprintf("[%d] %s %s | %d bytes | Title: %s\n",
				d.StatusCode, d.Method, d.URL, d.Length, orDash(d.Title)))
		}
	}
	if !anyDirs {
		sb.WriteString("Директории не найдены.\n")
	}

	os.WriteFile(path, []byte(sb.String()), 0644)
}

func writeHTML(path, domain string, subdomainsTotal int, hosts []models.HostResult, groups map[string][]models.DirResult, totalDirs int, elapsed time.Duration) {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TargetScan — ` + html.EscapeString(domain) + `</title>
<style>
:root { --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8; --ok:#34d399; --warn:#fbbf24; --err:#f87171; }
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; padding:24px; }
.container { max-width:1100px; margin:0 auto; }
h1 { font-size:26px; margin-bottom:4px; }
.subtitle { color:var(--muted); margin-bottom:24px; }
.cards { display:flex; gap:16px; flex-wrap:wrap; margin-bottom:28px; }
.card { background:var(--card); border-radius:12px; padding:18px 22px; min-width:150px; }
.card .num { font-size:30px; font-weight:700; color:var(--accent); }
.card .lbl { color:var(--muted); font-size:13px; margin-top:4px; }
h2 { font-size:19px; margin:26px 0 12px; border-bottom:1px solid #334155; padding-bottom:8px; }
table { width:100%; border-collapse:collapse; background:var(--card); border-radius:12px; overflow:hidden; }
th, td { padding:10px 12px; text-align:left; font-size:14px; border-bottom:1px solid #334155; }
th { color:var(--muted); font-weight:600; background:#16213a; }
tr:last-child td { border-bottom:none; }
a { color:var(--accent); text-decoration:none; }
a:hover { text-decoration:underline; }
.status { font-weight:700; }
.s2 { color:var(--ok); } .s3 { color:var(--warn); } .s4 { color:var(--err); }
.hostcard { background:var(--card); border-radius:12px; margin-bottom:14px; overflow:hidden; }
.hosthead { display:flex; align-items:center; gap:12px; padding:14px 18px; }
.hosthead a { font-weight:600; font-size:15px; }
.badge { font-size:12px; color:var(--muted); }
summary { cursor:pointer; padding:10px 18px; color:var(--muted); font-size:13px; }
summary:hover { color:var(--text); }
details table { border-radius:0; }
.empty { color:var(--muted); padding:12px 18px; font-size:14px; }
</style>
</head>
<body>
<div class="container">
<h1>TargetScan Report</h1>
<div class="subtitle">Домен: <b>` + html.EscapeString(domain) + `</b> · ` + time.Now().Format("2006-01-02 15:04:05") + ` · Время работы: ` + html.EscapeString(elapsed.Round(time.Millisecond).String()) + `</div>
<div class="cards">
<div class="card"><div class="num">` + fmt.Sprint(subdomainsTotal) + `</div><div class="lbl">Поддоменов найдено</div></div>
<div class="card"><div class="num">` + fmt.Sprint(len(hosts)) + `</div><div class="lbl">Живых хостов</div></div>
<div class="card"><div class="num">` + fmt.Sprint(totalDirs) + `</div><div class="lbl">Директорий найдено</div></div>
</div>
<h2>Живые хосты</h2>
<table>
<tr><th>Статус</th><th>URL</th><th>IP</th><th>Server</th><th>Title</th><th>Директорий</th></tr>
`)
	for _, h := range hosts {
		dirsCount := len(groups[h.URL])
		dirsTxt := "—"
		if dirsCount > 0 {
			dirsTxt = fmt.Sprint(dirsCount)
		}
		sb.WriteString(`<tr><td class="status ` + statusClass(h.StatusCode) + `">` + fmt.Sprint(h.StatusCode) + `</td><td><a href="` + html.EscapeString(h.URL) + `" target="_blank" rel="noopener">` + html.EscapeString(h.URL) + `</a></td><td>` + html.EscapeString(orDash(h.IP)) + `</td><td>` + html.EscapeString(orDash(h.Server)) + `</td><td>` + html.EscapeString(orDash(h.Title)) + `</td><td>` + dirsTxt + `</td></tr>`)
	}
	sb.WriteString("</table>\n<h2>Найденные директории</h2>\n")
	anyDirs := false
	for _, h := range hosts {
		hostDirs := groups[h.URL]
		if len(hostDirs) == 0 {
			continue
		}
		anyDirs = true
		sb.WriteString(`<div class="hostcard"><div class="hosthead"><a href="` + html.EscapeString(h.URL) + `" target="_blank" rel="noopener">` + html.EscapeString(h.URL) + `</a><span class="badge">` + fmt.Sprintf("%d путей", len(hostDirs)) + `</span></div><details><summary>Показать директории</summary><table><tr><th>Статус</th><th>Метод</th><th>Путь</th><th>Размер</th><th>Title</th></tr>`)
		for _, d := range hostDirs {
			sb.WriteString(`<tr><td class="status ` + statusClass(d.StatusCode) + `">` + fmt.Sprint(d.StatusCode) + `</td><td>` + html.EscapeString(d.Method) + `</td><td><a href="` + html.EscapeString(d.URL) + `" target="_blank" rel="noopener">` + html.EscapeString(d.URL) + `</a></td><td>` + fmt.Sprint(d.Length) + `</td><td>` + html.EscapeString(orDash(d.Title)) + `</td></tr>`)
		}
		sb.WriteString(`</table></details></div>`)
	}
	if !anyDirs {
		sb.WriteString(`<div class="empty">Директории не найдены.</div>`)
	}
	sb.WriteString(`</div></body></html>`)
	os.WriteFile(path, []byte(sb.String()), 0644)
}
