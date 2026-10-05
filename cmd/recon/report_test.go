package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mogpnet/targetscan/internal/models"
)

func TestWriteReports(t *testing.T) {
	hosts := []models.HostResult{
		{URL: "https://www.example.com", IP: "1.2.3.4", StatusCode: 200, Title: "Title <b>with html</b>", Server: "nginx"},
		{URL: "http://api.example.com", IP: "5.6.7.8", StatusCode: 403, Title: "Forbidden"},
	}
	dirs := []models.DirResult{
		{URL: "https://www.example.com/admin", Method: "GET", StatusCode: 301, Length: 0, Title: "Admin"},
		{URL: "https://www.example.com/api", Method: "GET", StatusCode: 200, Length: 123, Title: "API"},
		{URL: "http://api.example.com/v1", Method: "GET", StatusCode: 200, Length: 99, Title: "V1"},
	}

	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	writeReport("example.com", 5, hosts, dirs, 42*time.Second)

	txt, err := os.ReadFile("example.com.txt")
	if err != nil {
		t.Fatalf("txt not written: %v", err)
	}
	ts := string(txt)
	for _, want := range []string{"Поддоменов найдено: 5", "Живых хостов: 2", "Директорий: 3",
		"[200] https://www.example.com", "--- https://www.example.com (2) ---", "[301] GET https://www.example.com/admin"} {
		if !strings.Contains(ts, want) {
			t.Errorf("txt missing %q\n%s", want, ts)
		}
	}

	html, err := os.ReadFile("example.com.html")
	if err != nil {
		t.Fatalf("html not written: %v", err)
	}
	hs := string(html)
	for _, want := range []string{"Title &lt;b&gt;with html&lt;/b&gt;", "Показать директории",
		"https://www.example.com/admin", "2 путей", "s2", "s4"} {
		if !strings.Contains(hs, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(hs, "<b>with html</b>") {
		t.Errorf("html not escaped")
	}
}
