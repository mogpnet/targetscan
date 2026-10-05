package subdomains

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"time"
)

//go:embed embed_wordlist.txt
var DefaultWordlist string

type Engine struct {
	providers []Provider
}

func NewEngine() *Engine {
	return &Engine{
		providers: []Provider{
			// Оставляем только стабильные и рабочие источники
			NewHackerTargetProvider(),
			NewURLScanProvider(),
		},
	}
}

func (e *Engine) FetchAll(domain string, wordlistPath string, threads int, bruteEnabled bool, bruteTimeout time.Duration) []string {
	resultsChan := make(chan []string, len(e.providers)+1)
	var wg sync.WaitGroup

	fmt.Println("[*] Запуск параллельного сбора из пассивных источников...")

	for _, p := range e.providers {
		wg.Add(1)
		go func(provider Provider) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			subs, err := provider.Fetch(ctx, domain)
			if err != nil {
				fmt.Printf("  [-] [%s] Ошибка: %v (пропущен)\n", provider.Name(), err)
				return
			}
			fmt.Printf("  [+] [%s] Успешно получено: %d записей\n", provider.Name(), len(subs))
			resultsChan <- subs
		}(p)
	}

	// Параллельно запускаем DNS-брутфорс (дополнительный источник,
	// можно отключить флагом -no-brute)
	if bruteEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			brute := NewBruteForceRunner(threads, bruteTimeout)
			bruteResults := brute.Run(domain, wordlistPath, DefaultWordlist)
			resultsChan <- bruteResults
		}()
	}

	wg.Wait()
	close(resultsChan)

	// Дедупликация и нормализация
	uniqueDomains := make(map[string]struct{})
	for subs := range resultsChan {
		for _, sub := range subs {
			sub = strings.TrimSpace(sub)
			sub = strings.TrimPrefix(sub, "*.")
			sub = strings.ToLower(sub)
			if sub != "" && (sub == domain || strings.HasSuffix(sub, "."+domain)) {
				uniqueDomains[sub] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(uniqueDomains))
	for sub := range uniqueDomains {
		result = append(result, sub)
	}

	return result
}
