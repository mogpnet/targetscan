package models

type SubdomainResult struct {
	Domain string `json:"domain"`
	Source string `json:"source"`
}

type HostResult struct {
	URL        string   `json:"url"`
	IP         string   `json:"ip"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Server     string   `json:"server"`
	TechStack  []string `json:"tech_stack,omitempty"`
}

type DirResult struct {
	URL        string   `json:"url"`
	Method     string   `json:"method"`
	StatusCode int      `json:"status_code"`
	Length     int64    `json:"length"`
	Title      string   `json:"title"`
	Links      []string `json:"links,omitempty"`
}
