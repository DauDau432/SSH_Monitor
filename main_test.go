package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalOnly(t *testing.T) {
	h := localOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cases := []struct {
		name   string
		host   string
		origin string
		want   int
	}{
		{"localhost, không Origin", "localhost:8888", "", http.StatusOK},
		{"127.0.0.1 cùng origin", "127.0.0.1:8888", "http://127.0.0.1:8888", http.StatusOK},
		{"IPv6 loopback", "[::1]:8888", "http://[::1]:8888", http.StatusOK},
		{"website lạ gọi vào (CSRF/WS hijack)", "localhost:8888", "https://evil.example", http.StatusForbidden},
		{"Origin null", "localhost:8888", "null", http.StatusForbidden},
		{"DNS rebinding", "evil.example:8888", "http://evil.example:8888", http.StatusForbidden},
		{"truy cập từ IP LAN", "192.168.1.10:8888", "", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/sync/start", nil)
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("code = %d, want %d", w.Code, c.want)
			}
		})
	}
}

// File config hỏng phải báo lỗi (main sẽ dừng) thay vì chạy với config rỗng rồi ghi đè
func TestLoadConfigInvalidJSONKeepsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.json")
	bad := []byte(`{"servers": [{"id": "1", "host": "1.2.3.4"},]}`)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if err := NewApp(path).LoadConfig(); err == nil {
		t.Fatal("LoadConfig với JSON hỏng phải trả lỗi")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(bad) {
		t.Fatal("file config bị thay đổi")
	}
}

func TestSaveConfigAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.json")
	app := NewApp(path)
	app.config.Servers = []ServerConfig{{ID: "1", Host: "1.2.3.4", Port: 22}}
	if err := app.SaveConfig(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("file tạm còn sót lại")
	}
	app2 := NewApp(path)
	if err := app2.LoadConfig(); err != nil || len(app2.config.Servers) != 1 {
		t.Fatalf("đọc lại config: err=%v servers=%d", err, len(app2.config.Servers))
	}
}
