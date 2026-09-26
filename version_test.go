package main

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool // latest có mới hơn current không
	}{
		{"2026.9.26", "2026.9.26", false},
		{"2026.9.26", "2026.9.27", true},
		{"2026.9.26", "2026.10.1", true},
		{"2026.9.26", "2027.1.1", true},
		{"2026.9.26", "2026.9.25", false},
		{"2026.9.26", "v2026.9.27", true},
		{"2026.9", "2026.9.1", true},
		{"2026.9.26", "2026.9", false},
	}
	for _, c := range cases {
		if got := compareVersions(c.current, c.latest); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %v, muốn %v", c.current, c.latest, got, c.want)
		}
	}
}

func TestParseVersionParts(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
	}{
		{"2026.9.26", [3]int{2026, 9, 26}},
		{"v2026.12.1", [3]int{2026, 12, 1}},
		{"2026", [3]int{2026, 0, 0}},
		{"", [3]int{0, 0, 0}},
	}
	for _, c := range cases {
		if got := parseVersionParts(c.in); got != c.want {
			t.Errorf("parseVersionParts(%q) = %v, muốn %v", c.in, got, c.want)
		}
	}
}

func TestCommitNewerThanVersion(t *testing.T) {
	// AppVersion = 2026.9.26 → mốc cuối ngày 2026-09-26
	if commitNewerThanVersion("2026-09-27T00:00:00Z") != true {
		t.Error("commit sau ngày version phải là true")
	}
	if commitNewerThanVersion("2026-09-25T00:00:00Z") != false {
		t.Error("commit trước ngày version phải là false")
	}
	if commitNewerThanVersion("không-phải-ngày") != false {
		t.Error("ngày không hợp lệ phải là false")
	}
}

func TestVersionHandlerData(t *testing.T) {
	if AppVersion == "" {
		t.Fatal("AppVersion không được rỗng")
	}
	if got := repoURL(); got != "https://github.com/DauDau432/SSH_Monitor" {
		t.Errorf("repoURL() = %q", got)
	}
}