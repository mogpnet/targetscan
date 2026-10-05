package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mogpnet/targetscan/internal/directory"
	"github.com/mogpnet/targetscan/internal/models"
	"github.com/mogpnet/targetscan/internal/probing"
	"github.com/mogpnet/targetscan/internal/subdomains"
)

func main() {
	targetDomain := flag.String("d", "", "Целевой домен для разведки (например, example.com)")
	wordlist := flag.String("w", "", "Путь к кастомному словарю для DNS-брутфорса")
	dirWordlist := flag.String("dw", "", "Путь к словарю директорий (по умолчанию встроенный)")
	threads := flag.Int("t", 50, "Количество потоков")
	verbose := flag.Bool("v", false, "Включить подробный вывод (DEBUG)")
	noDirBrute := flag.Bool("no-dir", false, "Отключить брутфорс директорий")
	noBrute := flag.Bool("no-brute", false, "Отключить DNS-брутфорс поддоменов (только пассивные источники)")
	bruteTimeout := flag.Int("brute-timeout", 90, "Лимит времени DNS-брутфорса в секундах (0 = без лимита)")
	methods := flag.String("methods", "GET", "HTTP методы для брутфорса директорий (через запятую, например GET,POST)")
	statusFilter := flag.String("status", "200,301,302,403,405", "Фильтр по статус-кодам")
	delay := flag.Int("delay", 50, "Задержка между запросами в мс (для обхода WAF, рек. 50-200)")

	flag.Parse()

	if *targetDomain == "" {
		fmt.Println("Использование: targetscan -d <domain> [-w wordlist.txt] [-dw dirwordlist.txt] [-t 50] [-v] [-no-dir] [-no-brute] [-brute-timeout 90]")
		os.Exit(1)
	}

	fmt.Printf("[*] Старт разведки для домена: %s\n", *targetDomain)
	startTime := time.Now()

	// 1. Этап сбора поддоменов
	engine := subdomains.NewEngine()
	subdomainsList := engine.FetchAll(*targetDomain, *wordlist, *threads, !*noBrute, time.Duration(*bruteTimeout)*time.Second)

	fmt.Printf("\n[+] Всего уникальных поддоменов найдено: %d\n", len(subdomainsList))

	if len(subdomainsList) == 0 {
		fmt.Println("[-] Поддомены не найдены. Завершение работы.")
		return
	}

	// 2. Этап HTTP Probing
	prober := probing.NewProber(*threads, 15*time.Second, *verbose)
	liveHosts := prober.Run(subdomainsList)

	fmt.Println("\n[+] Список живых хостов:")
	fmt.Println("--------------------------------------------------------------------------------")
	for _, host := range liveHosts {
		fmt.Printf("[%d] %-40s | IP: %-15s | Title: %s\n",
			host.StatusCode,
			host.URL,
			host.IP,
			host.Title,
		)
	}
	fmt.Println("--------------------------------------------------------------------------------")

	// 3. Этап брутфорса директорий
	var dirResults []models.DirResult
	if !*noDirBrute && len(liveHosts) > 0 {
		// Подготовка целей с IP для обхода DNS-таймаутов
		var targetObjs []directory.Target
		var targetURLs []string
		for _, host := range liveHosts {
			targetObjs = append(targetObjs, directory.Target{URL: host.URL, IP: host.IP})
			targetURLs = append(targetURLs, host.URL)
		}

		// Загрузка словаря директорий
		var dirWords []string
		if *dirWordlist != "" {
			dirWords, _ = directory.LoadWordlist(*dirWordlist)
		}
		if len(dirWords) == 0 {
			dirWords = directory.GetDefaultWordlist()
		}

		methodList := strings.Split(*methods, ",")
		for i := range methodList {
			methodList[i] = strings.TrimSpace(methodList[i])
		}

		var statusCodes []int
		for _, s := range strings.Split(*statusFilter, ",") {
			var code int
			fmt.Sscanf(s, "%d", &code)
			if code > 0 {
				statusCodes = append(statusCodes, code)
			}
		}

		bruter := directory.NewBruter(*threads, 15*time.Second, *verbose, methodList, statusCodes, targetObjs, *delay)
		dirResults = bruter.Run(targetURLs, dirWords)

		fmt.Println("\n[+] Найденные директории:")
		fmt.Println("--------------------------------------------------------------------------------")
		for _, res := range dirResults {
			fmt.Printf("[%d] %s %-5s | %d bytes | Title: %s\n",
				res.StatusCode,
				res.URL,
				res.Method,
				res.Length,
				res.Title,
			)
		}
		fmt.Println("--------------------------------------------------------------------------------")
	}

	elapsed := time.Since(startTime)
	fmt.Printf("\n[*] Завершено за %v\n", elapsed)

	// 4. Сохранение отчётов (txt + html)
	writeReport(*targetDomain, len(subdomainsList), liveHosts, dirResults, elapsed)
}
