package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type URLScanResponse struct {
	Results []struct {
		Page struct {
			Domain string `json:"domain"`
		} `json:"page"`
	} `json:"results"`
}

type URLScanProvider struct {
	Client *http.Client
}

func NewURLScanProvider() *URLScanProvider {
	return &URLScanProvider{
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *URLScanProvider) Name() string {
	return "URLScan"
}

func (p *URLScanProvider) Fetch(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)

	resp, err := MakeRequest(ctx, p.Client, apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	var data URLScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, item := range data.Results {
		if item.Page.Domain != "" {
			subdomains = append(subdomains, item.Page.Domain)
		}
	}

	return subdomains, nil
}
