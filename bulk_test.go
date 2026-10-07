package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newBulkTestApp(t *testing.T) *App {
	app := NewApp(filepath.Join(t.TempDir(), "servers.json"))
	app.config.Groups = []string{"Default", "A", "B"}
	app.config.Servers = []ServerConfig{
		{ID: "1", Group: "A"}, {ID: "2", Group: "A"}, {ID: "3", Group: "B"},
	}
	return app
}

func doBulk(app *App, path, body string) int {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Host = "localhost:8888"
	app.SetupRoutes().ServeHTTP(w, r)
	return w.Code
}

func TestBulkServers(t *testing.T) {
	app := newBulkTestApp(t)
	if c := doBulk(app, "/api/servers/bulk", `{"ids":["1","3"],"action":"set_group","group":"B"}`); c != 200 {
		t.Fatalf("set_group code = %d", c)
	}
	for _, s := range app.config.Servers {
		if s.ID != "2" && s.Group != "B" {
			t.Fatalf("server %s group = %s", s.ID, s.Group)
		}
	}
	if c := doBulk(app, "/api/servers/bulk", `{"ids":["1"],"action":"set_group","group":"X"}`); c != http.StatusBadRequest {
		t.Fatalf("group không tồn tại: code = %d", c)
	}
	if c := doBulk(app, "/api/servers/bulk", `{"ids":["1"],"action":"set_proxy","proxy_id":"nope"}`); c != http.StatusBadRequest {
		t.Fatalf("proxy không tồn tại: code = %d", c)
	}
	if c := doBulk(app, "/api/servers/bulk", `{"ids":["1","2"],"action":"delete"}`); c != 200 {
		t.Fatalf("delete code = %d", c)
	}
	if len(app.config.Servers) != 1 || app.config.Servers[0].ID != "3" {
		t.Fatalf("servers sau xóa = %+v", app.config.Servers)
	}
	if c := doBulk(app, "/api/servers/bulk", `{"ids":["9"],"action":"delete"}`); c != http.StatusNotFound {
		t.Fatalf("id không tồn tại: code = %d", c)
	}
}

func TestBulkDeleteGroups(t *testing.T) {
	app := newBulkTestApp(t)
	if c := doBulk(app, "/api/groups/bulk", `{"groups":["A","Default"]}`); c != 200 {
		t.Fatalf("code = %d", c)
	}
	if strings.Join(app.config.Groups, ",") != "Default,B" {
		t.Fatalf("groups = %v", app.config.Groups)
	}
	for _, s := range app.config.Servers {
		want := map[string]string{"1": "Default", "2": "Default", "3": "B"}[s.ID]
		if s.Group != want {
			t.Fatalf("server %s group = %s, want %s", s.ID, s.Group, want)
		}
	}
}
