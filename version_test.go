package main

import (
	"testing"
	"time"
)

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
	// Mốc = cuối ngày của AppVersion. Tính ngày sau mốc 1 cách linh hoạt
	// để test không phụ thuộc giá trị AppVersion cụ thể.
	p := parseVersionParts(AppVersion)
	vDay := time.Date(p[0], time.Month(p[1]), p[2], 0, 0, 0, 0, time.UTC)
	after := vDay.AddDate(0, 0, 2).Format(time.RFC3339)  // sau mốc → true
	before := vDay.AddDate(0, 0, -1).Format(time.RFC3339) // trước mốc → false

	if commitNewerThanVersion(after) != true {
		t.Errorf("commit %s sau ngày version phải là true", after)
	}
	if commitNewerThanVersion(before) != false {
		t.Errorf("commit %s trước ngày version phải là false", before)
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