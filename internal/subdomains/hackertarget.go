package subdomains

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type HackerTargetProvider struct {
	Client *http.Client
}

func NewHackerTargetProvider() *HackerTargetProvider {
	return &HackerTargetProvider{
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *HackerTargetProvider) Name() string {
	return "HackerTarget"
}

func (p *HackerTargetProvider) Fetch(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	resp, err := MakeRequest(ctx, p.Client, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	var subdomains []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			subdomains = append(subdomains, parts[0])
		}
	}
	return subdomains, nil
}
