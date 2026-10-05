package subdomains

import "context"

// Provider описывает единый интерфейс для любого источника поддоменов
type Provider interface {
	Name() string
	Fetch(ctx context.Context, domain string) ([]string, error)
}
