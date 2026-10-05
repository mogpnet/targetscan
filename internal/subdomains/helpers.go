package subdomains

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// MakeRequestWithRetry выполняет GET-запрос с поддержкой Context и Retry
func MakeRequest(ctx context.Context, client *http.Client, reqURL string) (*http.Response, error) {
	maxRetries := 2
	var lastErr error

	for i := 0; i <= maxRetries; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "application/json, text/html, */*")

		resp, err := client.Do(req)
		if err == nil {
			// Если сервер перегружен, делаем короткую паузу и пробуем снова
			if resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
				resp.Body.Close()
				time.Sleep(time.Duration(i+1) * 1 * time.Second)
				continue
			}
			return resp, nil
		}

		lastErr = err
		time.Sleep(time.Duration(i+1) * 1 * time.Second)
	}

	return nil, fmt.Errorf("request failed after retries: %w", lastErr)
}
