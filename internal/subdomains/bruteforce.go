package subdomains

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var dnsResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
	"8.8.4.4:53",
	"1.0.0.1:53",
}

var dohProviders = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/resolve",
}

const (
	dnsLookupTimeout    = 1500 * time.Millisecond
	dnsHealthTimeout    = 3 * time.Second
	dohLookupTimeout    = 5 * time.Second
	dohHealthTimeout    = 2 * time.Second
	dnsMinWorkers       = 25
	dnsMaxWorkers       = 200
	dnsMaxResolverFails = 3
	dohMaxPrimaryFails  = 5
	dnsProgressInterval = 3 * time.Second
	udpLookupAttempts   = 2
)

// dohUserAgent — нейтральный браузерный UA для DNS-over-HTTPS (без имени тула).
const dohUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

type BruteForceRunner struct {
	Threads int
	Timeout time.Duration
}

func NewBruteForceRunner(threads int, timeout time.Duration) *BruteForceRunner {
	return &BruteForceRunner{
		Threads: threads,
		Timeout: timeout,
	}
}

// dnsBackend — выбранный транспорт для DNS-запросов: DoH (HTTP, устойчив к
// потерям UDP и закрытым 53-портам) либо классический UDP-резолвер.
type dnsBackend struct {
	name    string
	workers int
	timeout time.Duration
	lookup  func(ctx context.Context, host string) ([]string, error)
}

type dnsResolver struct {
	addr  string
	res   *net.Resolver
	fails atomic.Int64
	dead  atomic.Bool
}

// newResolver создаёт резолвер, который ходит строго через указанный
// DNS-сервер по UDP; таймаут короткий, чтобы одно "мёртвое" слово не
// задерживало весь брут.
func newResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dnsLookupTimeout}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// lookupIP4 запрашивает только A-записи — вдвое меньше DNS-запросов на слово,
// чем у LookupHost (тот ходит ещё и за AAAA).
func lookupIP4(ctx context.Context, r *net.Resolver, host string) ([]string, error) {
	ips, err := r.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out, nil
}

// isNotFound — окончательный ответ DNS (NXDOMAIN/NODATA): повторять его на
// других резолверах бессмысленно. Ранее любой ответ трактовался как ошибка и
// слово по очереди переспрашивало все резолверы по UDP и TCP — это и
// растягивало брут на часы.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func probeResolvers(all []*dnsResolver) []*dnsResolver {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		healthy []*dnsResolver
	)
	for _, r := range all {
		wg.Add(1)
		go func(r *dnsResolver) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), dnsHealthTimeout)
			defer cancel()
			if _, err := lookupIP4(ctx, r.res, "example.com"); err == nil {
				mu.Lock()
				healthy = append(healthy, r)
				mu.Unlock()
			}
		}(r)
	}
	wg.Wait()
	return healthy
}

// healthyUDPResolvers отбрасывает недоступные DNS-серверы до старта брута.
// Если публичные не отвечают (закрытая сеть), пробуем системный резолвер.
func healthyUDPResolvers() []*dnsResolver {
	public := make([]*dnsResolver, 0, len(dnsResolvers))
	for _, addr := range dnsResolvers {
		public = append(public, &dnsResolver{addr: addr, res: newResolver(addr)})
	}
	if ok := probeResolvers(public); len(ok) > 0 {
		return ok
	}
	if ok := probeResolvers([]*dnsResolver{{addr: "system", res: net.DefaultResolver}}); len(ok) > 0 {
		return ok
	}
	return nil
}

// pickResolver выбирает следующий живой резолвер по кругу, стараясь не брать
// avoid (тот, что только что не ответил). Если живых больше нет — вернёт его.
func pickResolver(pool []*dnsResolver, rr *atomic.Uint64, avoid *dnsResolver) *dnsResolver {
	n := uint64(len(pool))
	var fallback *dnsResolver
	for i := 0; i < len(pool); i++ {
		r := pool[rr.Add(1)%n]
		if r.dead.Load() {
			continue
		}
		if r == avoid {
			if fallback == nil {
				fallback = r
			}
			continue
		}
		return r
	}
	return fallback
}

// resolveUDP делает 1-2 быстрых A-запроса. nil error означает, что DNS
// ответил (в том числе "записи нет"); непустой error — DNS не ответил вообще.
func resolveUDP(parent context.Context, host string, pool []*dnsResolver, rr *atomic.Uint64) ([]string, error) {
	var (
		lastErr error
		avoid   *dnsResolver
	)
	for attempt := 0; attempt < udpLookupAttempts; attempt++ {
		r := pickResolver(pool, rr, avoid)
		if r == nil {
			break
		}
		ctx, cancel := context.WithTimeout(parent, dnsLookupTimeout)
		ips, err := lookupIP4(ctx, r.res, host)
		cancel()

		if err == nil {
			r.fails.Store(0)
			return ips, nil
		}
		if isNotFound(err) {
			r.fails.Store(0)
			return nil, nil
		}
		if r.fails.Add(1) >= dnsMaxResolverFails {
			r.dead.Store(true)
		}
		lastErr = err
		avoid = r
	}
	if lastErr == nil {
		lastErr = errors.New("нет доступных DNS-резолверов")
	}
	return nil, lastErr
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func providerHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

// newDoHClient: сознательно HTTP/1.1 (без ForceAttemptHTTP2). HTTP/2
// мультиплексирует всё в одно соединение, и на высоких RTT/через VPN
// упирается в лимиты потока — замеры дают ~2x меньше запросов в секунду,
// чем при нескольких параллельных HTTP/1.1 соединениях.
func newDoHClient() *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        400,
		MaxIdleConnsPerHost: 200,
		MaxConnsPerHost:     200,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: dohLookupTimeout}
}

// dohPool: несколько DoH-провайдеров с одним активным. Вторичный провайдер
// включается только если активный стабильно отвечает ошибками — иначе
// медленный фолбэк на каждый сбой резко просаживает скорость брута.
type dohPool struct {
	client    *http.Client
	providers []string

	mu      sync.Mutex
	primary int
	fails   int
}

func (p *dohPool) query(ctx context.Context, host string) ([]string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		idx := p.primary
		p.mu.Unlock()

		ips, err := dohQuery(ctx, p.client, p.providers[idx], host)
		if err == nil {
			p.mu.Lock()
			p.fails = 0
			p.mu.Unlock()
			return ips, nil
		}
		lastErr = err

		p.mu.Lock()
		p.fails++
		if p.fails >= dohMaxPrimaryFails && len(p.providers) > 1 {
			p.primary = (p.primary + 1) % len(p.providers)
			p.fails = 0
		}
		p.mu.Unlock()
	}
	return nil, lastErr
}

// dohQuery спрашивает A-запись через DoH JSON API. nil error = DNS ответил
// (в том числе "записи нет" — пустой список).
func dohQuery(ctx context.Context, client *http.Client, provider, host string) ([]string, error) {
	reqURL := provider + "?name=" + url.QueryEscape(host) + "&type=A"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", dohUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("doh %s: статус %d", provider, resp.StatusCode)
	}

	var data dohResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil {
		return nil, err
	}
	if data.Status == 3 { // NXDOMAIN
		return nil, nil
	}
	if data.Status != 0 { // SERVFAIL/REFUSED и прочее
		return nil, fmt.Errorf("doh %s: dns status %d", provider, data.Status)
	}

	ips := make([]string, 0, len(data.Answer))
	for _, a := range data.Answer {
		if a.Type == 1 {
			ips = append(ips, a.Data)
		}
	}
	return ips, nil
}

// selectBackend выбирает транспорт: сначала DoH (быстро и устойчиво), при
// недоступности — UDP-резолверы. nil = DNS недоступен вообще.
func (b *BruteForceRunner) selectBackend() *dnsBackend {
	workers := b.Threads * 3
	if workers < dnsMinWorkers {
		workers = dnsMinWorkers
	}
	if workers > dnsMaxWorkers {
		workers = dnsMaxWorkers
	}

	// Health-check провайдеров параллельно и с коротким таймаутом: медленный
	// вторичный резолвер не должен задерживать старт брута.
	client := newDoHClient()
	okProviders := make([]bool, len(dohProviders))
	var hwg sync.WaitGroup
	for i, p := range dohProviders {
		hwg.Add(1)
		go func(i int, p string) {
			defer hwg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), dohHealthTimeout)
			defer cancel()
			if _, err := dohQuery(ctx, client, p, "example.com"); err == nil {
				okProviders[i] = true
			}
		}(i, p)
	}
	hwg.Wait()

	var healthy []string
	for i, p := range dohProviders {
		if okProviders[i] {
			healthy = append(healthy, p)
		}
	}
	if len(healthy) > 0 {
		names := make([]string, 0, len(healthy))
		for _, p := range healthy {
			names = append(names, providerHost(p))
		}
		pool := &dohPool{client: client, providers: healthy}
		return &dnsBackend{
			name:    "DoH " + strings.Join(names, ", "),
			workers: workers,
			timeout: dohLookupTimeout,
			lookup:  pool.query,
		}
	}

	pool := healthyUDPResolvers()
	if len(pool) == 0 {
		return nil
	}
	rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	var rr atomic.Uint64

	udpWorkers := b.Threads
	if udpWorkers < 15 {
		udpWorkers = 15
	}
	if udpWorkers > 32 {
		udpWorkers = 32
	}
	// UDP страдает от потерь пакетов: умеренная конкурентность и запас на 2 попытки.
	udpTimeout := time.Duration(udpLookupAttempts) * dnsLookupTimeout

	return &dnsBackend{
		name:    fmt.Sprintf("UDP, резолверов %d/%d", len(pool), len(dnsResolvers)),
		workers: udpWorkers,
		timeout: udpTimeout,
		lookup: func(ctx context.Context, host string) ([]string, error) {
			return resolveUDP(ctx, host, pool, &rr)
		},
	}
}

func isWildcardHit(ips []string, wildcardSet map[string]struct{}) bool {
	if len(wildcardSet) == 0 {
		return false
	}
	if len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		if _, ok := wildcardSet[ip]; !ok {
			return false
		}
	}
	return true
}

func loadBruteWords(wordlistPath, defaultWordlist string) []string {
	var raw []string

	if wordlistPath != "" {
		file, err := os.Open(wordlistPath)
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				raw = append(raw, scanner.Text())
			}
			file.Close()
		}
	}

	if len(raw) == 0 && defaultWordlist != "" {
		scanner := bufio.NewScanner(strings.NewReader(defaultWordlist))
		for scanner.Scan() {
			raw = append(raw, scanner.Text())
		}
	}

	seen := make(map[string]struct{}, len(raw))
	words := make([]string, 0, len(raw))
	for _, line := range raw {
		w := strings.TrimSpace(line)
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		words = append(words, w)
	}
	return words
}

func (b *BruteForceRunner) Run(domain string, wordlistPath string, defaultWordlist string) []string {
	words := loadBruteWords(wordlistPath, defaultWordlist)
	if len(words) == 0 {
		return nil
	}

	backend := b.selectBackend()
	if backend == nil {
		fmt.Println("  [!] DNS недоступен (ни DoH, ни UDP) — DNS-брутфорс пропущен (пассивные источники уже собраны).")
		return nil
	}

	ctx := context.Background()
	cancel := func() {}
	if b.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, b.Timeout)
	}
	defer cancel()

	limit := "без лимита"
	if b.Timeout > 0 {
		limit = b.Timeout.Round(time.Second).String()
	}
	fmt.Printf("  [*] DNS-брутфорс [%s]: %d слов, %d потоков, лимит %s\n",
		backend.name, len(words), backend.workers, limit)

	wildcardSet := make(map[string]struct{})
	for i := 0; i < 2; i++ {
		wildcardHost := fmt.Sprintf("wildcard-check-%d.%s", rand.Int63(), domain)
		wctx, wcancel := context.WithTimeout(ctx, backend.timeout)
		ips, err := backend.lookup(wctx, wildcardHost)
		wcancel()
		if err == nil {
			for _, ip := range ips {
				wildcardSet[ip] = struct{}{}
			}
		}
	}
	if len(wildcardSet) > 0 {
		fmt.Println("  [!] Обнаружен wildcard DNS. Ответы с теми же IP отфильтровываются.")
	}

	var (
		done       atomic.Int64
		foundCount atomic.Int64
	)

	jobs := make(chan string, backend.workers*2)
	results := make(chan string, backend.workers*2)

	var wg sync.WaitGroup
	for i := 0; i < backend.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				sub := word + "." + domain
				lctx, lcancel := context.WithTimeout(ctx, backend.timeout)
				ips, err := backend.lookup(lctx, sub)
				lcancel()
				done.Add(1)

				if err != nil {
					continue
				}
				if len(ips) > 0 && !isWildcardHit(ips, wildcardSet) {
					foundCount.Add(1)
					results <- sub
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, w := range words {
			select {
			case <-ctx.Done():
				return
			case jobs <- w:
			}
		}
	}()

	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(dnsProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				d := done.Load()
				fmt.Printf("\r  [>] DNS-брут: %d/%d (%.0f%%) | найдено: %d   ",
					d, len(words), float64(d)/float64(len(words))*100, foundCount.Load())
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var found []string
	for sub := range results {
		found = append(found, sub)
	}
	close(progressDone)

	checked := done.Load()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Printf("\r  [!] DNS-брутфорс остановлен по лимиту времени: проверено %d/%d, найдено %d\n",
			checked, len(words), len(found))
	} else {
		fmt.Printf("\r  [+] DNS-брутфорс завершён: проверено %d слов, найдено %d\n",
			checked, len(found))
	}
	return found
}
