package probing

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mogpnet/targetscan/internal/models"
	"golang.org/x/net/http2"
)

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

type Prober struct {
	threads int
	verbose bool
	client  *http.Client
}

func NewProber(threads int, timeout time.Duration, verbose bool) *Prober {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			// Даём резолву системного/дефолтного резолвера собственный,
			// более щедрый таймаут, а не полагаемся на отдельную
			// preflight-проверку DNS перед запросом (это и убивало
			// пробинг ранее — см. probeURL).
			Timeout:   8 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 2 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
	}

	_ = http2.ConfigureTransport(transport)

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Prober{
		threads: threads,
		verbose: verbose,
		client:  client,
	}
}

func (p *Prober) Run(subdomains []string) []models.HostResult {
	fmt.Printf("\n[*] Старт HTTP-пробинга (%d хостов, %d потоков)...\n", len(subdomains), p.threads)

	seen := make(map[string]bool)
	var uniqueSubs []string
	for _, sub := range subdomains {
		if !seen[sub] {
			seen[sub] = true
			uniqueSubs = append(uniqueSubs, sub)
		}
	}

	var targets []string
	for _, sub := range uniqueSubs {
		targets = append(targets, "https://"+sub)
		targets = append(targets, "http://"+sub)
	}

	jobs := make(chan string, len(targets))
	results := make(chan *models.HostResult, len(targets))
	var wg sync.WaitGroup

	for i := 0; i < p.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range jobs {
				res := p.probeURL(targetURL)
				if res != nil {
					results <- res
				}
			}
		}()
	}

	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	wg.Wait()
	close(results)

	var liveHosts []models.HostResult
	seenDomains := make(map[string]bool)

	for res := range results {
		cleanDomain := strings.TrimPrefix(strings.TrimPrefix(res.URL, "https://"), "http://")
		if !seenDomains[cleanDomain] {
			seenDomains[cleanDomain] = true
			liveHosts = append(liveHosts, *res)
		}
	}

	fmt.Printf("  [+] HTTP-пробинг завершен. Найдено живых веб-сервисов: %d\n", len(liveHosts))
	return liveHosts
}

// probeURL больше НЕ делает отдельный preflight DNS-резолв через кастомный
// резолвер (это и было причиной 100% провала пробинга: раздельный ручной
// DNS-запрос на 1.1.1.1:53/8.8.8.8:53 либо блокировался сетью, либо не
// укладывался в таймаут при высокой конкурентности, и хост помечался
// мёртвым ДО того, как реальный HTTP-запрос вообще пытался выполниться).
//
// Теперь резолвинг делает сам http.Transport при установке соединения
// (тот же путь, который успешно сработал для HackerTarget/URLScan), а IP
// адрес мы достаём из реального соединения через httptrace — без лишнего
// дублирующего DNS-запроса.
func (p *Prober) probeURL(targetURL string) *models.HostResult {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Ch-Ua", `"Not-A.Brand";v="99", "Chromium";v="124", "Google Chrome";v="124"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	var resolvedIP string
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				if host, _, err := net.SplitHostPort(info.Conn.RemoteAddr().String()); err == nil {
					resolvedIP = host
				}
			}
		},
	}
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)

	resp, err := p.client.Do(req)
	if err != nil {
		if p.verbose {
			fmt.Printf("  [-] [DEBUG] %s -> Ошибка: %v\n", targetURL, err)
		}
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(bodyBytes)

	title := "N/A"
	match := titleRegex.FindStringSubmatch(bodyStr)
	if len(match) > 1 {
		title = strings.TrimSpace(match[1])
		title = strings.ReplaceAll(title, "\n", " ")
		title = strings.ReplaceAll(title, "\r", "")
	}

	if p.verbose {
		fmt.Printf("  [+] [DEBUG] %s -> Status: %d, IP: %s, Title: %s\n", targetURL, resp.StatusCode, resolvedIP, title)
	}

	return &models.HostResult{
		URL:        targetURL,
		IP:         resolvedIP,
		StatusCode: resp.StatusCode,
		Title:      title,
		Server:     resp.Header.Get("Server"),
	}
}
