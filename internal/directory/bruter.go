package directory

import (
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mogpnet/targetscan/internal/models"
	"golang.org/x/net/http2"
)

var (
	titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
	}
)

const (
	MAX_BODY_READ          = 4 * 1024
	BINARY_CHECK_SIZE      = 512
	MAX_CONSECUTIVE_ERRORS = 20
	ERROR_BACKOFF          = 15 * time.Second
	RATELIMIT_COOLDOWN     = 5 * time.Second
)

type Target struct {
	URL string
	IP  string
}

type Bruter struct {
	threads       int
	timeout       time.Duration
	verbose       bool
	methods       []string
	statusFilter  []int
	delay         time.Duration
	client        *http.Client
	seenURLs      map[string]bool
	seenURLsMu    sync.Mutex
	hostIPs       map[string]string
	ipMu          sync.RWMutex
	deadHosts     map[string]bool
	deadHostsMu   sync.RWMutex
	totalRequests int64
	doneRequests  int64
	errorRequests int64
}

// scanState — состояние одного хоста во время брута: счётчик ошибок,
// cooldown после WAF/рейт-лимита и эталон ответа "не найдено" (soft-404).
type scanState struct {
	consecutiveErrors atomic.Int64
	cooldownUntil     atomic.Int64 // unix nano; 0 = паузы нет
	baselineStatus    int
	baselineLength    int64
}

func NewBruter(threads int, timeout time.Duration, verbose bool, methods []string, statusFilter []int, targets []Target, delayMs int) *Bruter {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"}, // Включаем HTTP/2!
	}
	b := &Bruter{
		threads:      threads,
		timeout:      timeout,
		verbose:      verbose,
		methods:      methods,
		statusFilter: statusFilter,
		delay:        time.Duration(delayMs) * time.Millisecond,
		seenURLs:     make(map[string]bool),
		hostIPs:      make(map[string]string),
		deadHosts:    make(map[string]bool),
	}
	for _, t := range targets {
		u, err := url.Parse(t.URL)
		if err == nil {
			if isIPv4(t.IP) {
				b.hostIPs[u.Hostname()] = t.IP
			}
		}
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   5 * time.Second,
		DialContext:           b.dialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10, // Уменьшаем, чтобы не долбить один хост сотнями соединений
		MaxConnsPerHost:       20, // Жестко ограничиваем макс. соединений на хост (защита от WAF)
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	_ = http2.ConfigureTransport(transport) // Активируем HTTP/2

	b.client = &http.Client{
		Transport: transport,
		Timeout:   0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if len(via) > 0 {
				req.Header.Set("User-Agent", via[0].Header.Get("User-Agent"))
			}
			return nil
		},
	}
	return b
}

// isIPv4 проверяет является ли строка IPv4 адресом
func isIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() != nil
}

// resolveIPv4 резолвит hostname и возвращает ТОЛЬКО IPv4
func (b *Bruter) resolveIPv4(hostname string) (string, bool) {
	b.ipMu.RLock()
	ip, ok := b.hostIPs[hostname]
	b.ipMu.RUnlock()
	if ok {
		return ip, true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil || len(ips) == 0 {
		return "", false
	}

	for _, ip := range ips {
		if ip.IP.To4() != nil {
			resolvedIP := ip.IP.String()
			b.ipMu.Lock()
			b.hostIPs[hostname] = resolvedIP
			b.ipMu.Unlock()
			return resolvedIP, true
		}
	}
	return "", false
}

func (b *Bruter) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	ip, ok := b.resolveIPv4(host)
	if ok {
		addr = net.JoinHostPort(ip, port)
	}

	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, "tcp4", addr)
}

func (b *Bruter) Run(baseURLs []string, wordlist []string) []models.DirResult {
	b.totalRequests = int64(len(baseURLs) * len(wordlist) * len(b.methods))
	fmt.Printf("\n[*] Старт брутфорса директорий (%d хостов, %d слов, %d потоков, delay: %v)...\n",
		len(baseURLs), len(wordlist), b.threads, b.delay)

	stopStats := make(chan struct{})
	go b.printStats(stopStats)

	var allResults []models.DirResult
	var mu sync.Mutex

	var hostWg sync.WaitGroup
	hostJobs := make(chan string, len(baseURLs))
	for _, baseURL := range baseURLs {
		hostJobs <- baseURL
	}
	close(hostJobs)

	numHostWorkers := len(baseURLs)
	if numHostWorkers > b.threads {
		numHostWorkers = b.threads
	}

	for i := 0; i < numHostWorkers; i++ {
		hostWg.Add(1)
		go func() {
			defer hostWg.Done()
			for baseURL := range hostJobs {
				b.brute(baseURL, wordlist, &allResults, &mu)
			}
		}()
	}

	hostWg.Wait()
	close(stopStats)
	fmt.Printf("\n[+] Брутфорс завершен. Найдено путей: %d (Ошибок: %d)\n", len(allResults), atomic.LoadInt64(&b.errorRequests))
	return allResults
}

func (b *Bruter) printStats(stop chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	startTime := time.Now()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if b.verbose {
				continue
			}
			done := atomic.LoadInt64(&b.doneRequests)
			errs := atomic.LoadInt64(&b.errorRequests)
			total := atomic.LoadInt64(&b.totalRequests)
			elapsed := time.Since(startTime).Seconds()
			rps := float64(done) / elapsed

			if total > 0 {
				fmt.Printf("\r  [>] Прогресс: %d/%d (%.1f%%) | Ошибок: %d | Скорость: %.1f req/s   ",
					done, total, float64(done)/float64(total)*100, errs, rps)
			}
		}
	}
}

func (b *Bruter) isAlreadySeen(u string) bool {
	b.seenURLsMu.Lock()
	defer b.seenURLsMu.Unlock()
	if b.seenURLs[u] {
		return true
	}
	b.seenURLs[u] = true
	return false
}

func (b *Bruter) isDeadHost(hostname string) bool {
	b.deadHostsMu.RLock()
	defer b.deadHostsMu.RUnlock()
	return b.deadHosts[hostname]
}

func (b *Bruter) markDeadHost(hostname string) {
	b.deadHostsMu.Lock()
	defer b.deadHostsMu.Unlock()
	b.deadHosts[hostname] = true
}

// waitCooldown блокирует воркер до окончания паузы хоста (WAF/рейт-лимит).
func waitCooldown(st *scanState) {
	for {
		until := st.cooldownUntil.Load()
		if until == 0 {
			return
		}
		wait := time.Until(time.Unix(0, until))
		if wait <= 0 {
			st.cooldownUntil.Store(0)
			return
		}
		time.Sleep(wait)
	}
}

func (b *Bruter) brute(baseURL string, wordlist []string, results *[]models.DirResult, mu *sync.Mutex) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	if b.isDeadHost(parsed.Hostname()) {
		fmt.Printf("\n[!] Пропуск мёртвого хоста: %s\n", baseURL)
		return
	}

	testURL := baseURL + "/__test_connection__"
	if !b.isHostAlive(testURL) {
		fmt.Printf("\n[!] Хост недоступен, пропускаем: %s\n", baseURL)
		b.markDeadHost(parsed.Hostname())
		return
	}

	// Эталон "не найдено": рандомный заведомо несуществующий путь.
	// Ответы, неотличимые от эталона (soft-404 / catch-all), находкой
	// не считаются.
	st := &scanState{}
	baselineURL := baseURL + fmt.Sprintf("/nonexistent-%d", rand.Int63())
	if bs, bl, ok := b.fetchBaseline(baselineURL); ok {
		st.baselineStatus = bs
		st.baselineLength = bl
		if b.verbose {
			fmt.Printf("\n[DEBUG] Baseline %s -> %d (%d bytes)\n", baselineURL, bs, bl)
		}
	}

	jobs := make(chan string, b.threads*2)
	resultChan := make(chan *models.DirResult, b.threads*2)
	var wg sync.WaitGroup

	for i := 0; i < b.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				waitCooldown(st)

				// Делаем задержку, если она задана
				if b.delay > 0 {
					time.Sleep(b.delay)
				}

				resList, isError := b.scanPath(baseURL, word, st)
				for _, res := range resList {
					resultChan <- &res
				}

				if isError {
					if errCount := st.consecutiveErrors.Add(1); errCount >= MAX_CONSECUTIVE_ERRORS {
						// Пауза (Backoff) и продолжаем с того же места —
						// словарь НЕ обрезается, как это было раньше.
						fmt.Printf("\n[!] %d подряд ошибок (WAF/Таймаут). Пауза %v для хоста: %s\n",
							MAX_CONSECUTIVE_ERRORS, ERROR_BACKOFF, baseURL)
						st.cooldownUntil.Store(time.Now().Add(ERROR_BACKOFF).UnixNano())
						st.consecutiveErrors.Store(0)
					} else {
						// Короткая пауза при одиночных сетевых сбоях
						time.Sleep(500 * time.Millisecond)
					}
				} else {
					st.consecutiveErrors.Store(0)
				}
			}
		}()
	}

	go func() {
		for _, w := range wordlist {
			jobs <- w
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		mu.Lock()
		*results = append(*results, *res)
		mu.Unlock()
		if b.verbose {
			fmt.Printf("\n[+] %s %s -> %d (%d bytes)", res.Method, res.URL, res.StatusCode, res.Length)
		}
	}
}

func (b *Bruter) isHostAlive(testURL string) bool {
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false
	}
	// Рандомный User-Agent для тестового запроса
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	client := &http.Client{
		Transport: b.client.Transport,
		Timeout:   5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// fetchBaseline делает один запрос на заведомо несуществующий путь и
// возвращает (status, length) эталона "не найдено".
func (b *Bruter) fetchBaseline(urlStr string) (int, int64, bool) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return 0, 0, false
	}
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := b.client.Do(req)
	if err != nil {
		return 0, 0, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MAX_BODY_READ))
	bodyLen := resp.ContentLength
	if bodyLen < 0 {
		bodyLen = int64(len(bodyBytes))
	}
	return resp.StatusCode, bodyLen, true
}

func isBinaryData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	checkSize := len(data)
	if checkSize > BINARY_CHECK_SIZE {
		checkSize = BINARY_CHECK_SIZE
	}
	for i := 0; i < checkSize; i++ {
		b := data[i]
		if b < 32 && b != '\t' && b != '\n' && b != '\r' {
			return true
		}
	}
	return false
}

// scanPath сканирует ОДНО слово всеми методами и возвращает результаты по
// каждому методу. 429/503 (WAF/рейт-лимит) находкой НЕ считаются — вместо
// этого выставляется cooldown хоста.
func (b *Bruter) scanPath(baseURL, word string, st *scanState) ([]models.DirResult, bool) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	word = strings.TrimPrefix(word, "/")
	targetURL := fmt.Sprintf("%s/%s", baseURL, word)

	var results []models.DirResult

	for _, method := range b.methods {
		// Дедуп по URL+method: каждый метод сканирует URL ровно один раз.
		dedupeKey := method + " " + targetURL
		if b.isAlreadySeen(dedupeKey) {
			continue
		}

		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			continue
		}

		// РОТАЦИЯ USER-AGENT (Критично для обхода WAF)
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Connection", "keep-alive")

		resp, err := b.client.Do(req)
		atomic.AddInt64(&b.doneRequests, 1)

		if err != nil {
			atomic.AddInt64(&b.errorRequests, 1)
			if b.verbose {
				fmt.Printf("\n[-] [DEBUG] %s %s -> Ошибка: %v", method, targetURL, err)
			}
			return results, true // Сетевая ошибка!
		}

		// 429/503 — WAF или рейт-лимит: НЕ сохраняем как находку,
		// а делаем паузу по хосту.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			resp.Body.Close()
			st.cooldownUntil.Store(time.Now().Add(RATELIMIT_COOLDOWN).UnixNano())
			return results, false
		}

		if len(b.statusFilter) > 0 {
			matched := false
			for _, code := range b.statusFilter {
				if resp.StatusCode == code {
					matched = true
					break
				}
			}
			if !matched {
				resp.Body.Close()
				continue
			}
		}

		limitedReader := io.LimitReader(resp.Body, MAX_BODY_READ)
		bodyBytes, _ := io.ReadAll(limitedReader)
		resp.Body.Close()

		bodyLen := resp.ContentLength
		if bodyLen < 0 {
			bodyLen = int64(len(bodyBytes))
		}

		// Soft-404: ответ, неотличимый от эталона "не найдено", пропускаем.
		if st.baselineStatus > 0 && resp.StatusCode == st.baselineStatus && bodyLen == st.baselineLength {
			continue
		}

		title := "N/A"
		if isBinaryData(bodyBytes) {
			title = "N/A (binary)"
		} else if match := titleRegex.FindStringSubmatch(string(bodyBytes)); len(match) > 1 {
			title = strings.TrimSpace(match[1])
			title = strings.ReplaceAll(title, "\n", " ")
			title = strings.ReplaceAll(title, "\r", "")
		}

		results = append(results, models.DirResult{
			URL:        targetURL,
			Method:     method,
			StatusCode: resp.StatusCode,
			Length:     bodyLen,
			Title:      title,
		})
	}

	return results, false
}

func LoadWordlist(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var words []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, nil
}

//go:embed embed_wordlist.txt
var defaultWordlist string

func GetDefaultWordlist() []string {
	var words []string
	for _, line := range strings.Split(defaultWordlist, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words
}
