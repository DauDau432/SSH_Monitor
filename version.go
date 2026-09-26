// ===========================================================================
// SSH Monitor — Version & cập nhật (kiểm tra bản mới trên GitHub)
// ===========================================================================

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ========================== Thông tin phiên bản ==========================

// AppVersion — Phiên bản hiện tại của ứng dụng (định dạng YYYY.M.D).
// Mỗi lần phát hành bản mới, sửa hằng số này thành ngày phát hành.
const AppVersion = "2026.9.27"

const (
	// GitHubRepoOwner / GitHubRepoName — Repo nguồn để kiểm tra cập nhật
	GitHubRepoOwner = "DauDau432"
	GitHubRepoName  = "SSH_Monitor"

	// TelegramContact — Liên hệ / kênh Telegram của tác giả
	TelegramContact = "Daukute"

	// updateCacheTTL — Thời gian cache kết quả kiểm tra (tránh rate limit GitHub)
	updateCacheTTL = 1 * time.Hour
	// githubAPITimeout — Timeout gọi GitHub API
	githubAPITimeout = 10 * time.Second
)

// repoURL — URL repo trên GitHub
func repoURL() string {
	return fmt.Sprintf("https://github.com/%s/%s", GitHubRepoOwner, GitHubRepoName)
}

// ========================== Kiểm tra cập nhật ==========================

// updateInfo — Kết quả kiểm tra cập nhật (gửi về frontend)
type updateInfo struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	HasUpdate      bool   `json:"has_update"`
	CheckedAt      string `json:"checked_at"`
	Error          string `json:"error,omitempty"`

	// Chi tiết bản phát hành mới nhất (nếu có)
	ReleaseName string `json:"release_name,omitempty"`
	ReleaseURL  string `json:"release_url,omitempty"`
	ReleaseBody string `json:"release_body,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`

	// Chi tiết commit mới nhất
	CommitSHA     string `json:"commit_sha,omitempty"`
	CommitMessage string `json:"commit_message,omitempty"`
	CommitURL     string `json:"commit_url,omitempty"`
	CommitDate    string `json:"commit_date,omitempty"`

	RepoURL string `json:"repo_url"`
}

// updateCache — Cache kết quả kiểm tra (TTL 1h)
var (
	updateCacheMu   sync.Mutex
	updateCacheData *updateInfo
	updateCacheTime time.Time
)

// githubRelease — Rút gọn response từ GitHub Releases API
type githubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
}

// githubCommit — Rút gọn response từ GitHub Commits API
type githubCommit struct {
	SHA    string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Date string `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

// compareVersions — So sánh 2 phiên bản dạng "YYYY.M.D".
// Trả về true nếu b > a (có bản mới hơn).
func compareVersions(a, b string) bool {
	pa, pb := parseVersionParts(a), parseVersionParts(b)
	for i := 0; i < 3; i++ {
		if pb[i] != pa[i] {
			return pb[i] > pa[i]
		}
	}
	return false
}

// parseVersionParts — Tách "2026.9.26" thành [2026, 9, 26]; thiếu phần nào coi là 0
func parseVersionParts(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n, _ := strconv.Atoi(strings.TrimSpace(parts[i]))
		out[i] = n
	}
	return out
}

// githubGetJSON — Gọi GitHub API và decode JSON vào dst
func githubGetJSON(client *http.Client, url string, dst interface{}) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SSH-Monitor/"+AppVersion)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub trả về HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// checkForUpdate — Kiểm tra bản phát hành/commit mới nhất trên GitHub.
// Kết quả được cache trong updateCacheTTL; force=true bỏ qua cache.
func checkForUpdate(force bool) *updateInfo {
	updateCacheMu.Lock()
	defer updateCacheMu.Unlock()

	if !force && updateCacheData != nil && time.Since(updateCacheTime) < updateCacheTTL {
		return updateCacheData
	}

	info := &updateInfo{
		CurrentVersion: AppVersion,
		LatestVersion:  AppVersion,
		CheckedAt:      time.Now().Format(time.RFC3339),
		RepoURL:        repoURL(),
	}

	client := &http.Client{Timeout: githubAPITimeout}
	var errs []string

	// 1) Bản phát hành mới nhất (repo chưa có release sẽ trả 404 → bỏ qua)
	var rel githubRelease
	relURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", GitHubRepoOwner, GitHubRepoName)
	if err := githubGetJSON(client, relURL, &rel); err == nil {
		info.ReleaseName = rel.Name
		info.ReleaseBody = rel.Body
		info.ReleaseURL = rel.HTMLURL
		info.PublishedAt = rel.PublishedAt
		if strings.TrimSpace(rel.TagName) != "" {
			info.LatestVersion = strings.TrimPrefix(rel.TagName, "v")
		}
	} else {
		errs = append(errs, "release: "+err.Error())
	}

	// 2) Commit mới nhất trên nhánh main
	var commits []githubCommit
	cmtURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?sha=main&per_page=1", GitHubRepoOwner, GitHubRepoName)
	if err := githubGetJSON(client, cmtURL, &commits); err == nil && len(commits) > 0 {
		c := commits[0]
		info.CommitSHA = c.SHA
		info.CommitURL = c.HTMLURL
		info.CommitMessage = strings.SplitN(c.Commit.Message, "\n", 2)[0]
		info.CommitDate = c.Commit.Author.Date
	} else if err != nil {
		errs = append(errs, "commit: "+err.Error())
	}

	// Có bản mới khi: có bản phát hành mới hơn HIỆN TẠI,
	// hoặc có commit trên main sau ngày của phiên bản hiện tại.
	info.HasUpdate = compareVersions(AppVersion, info.LatestVersion) ||
		commitNewerThanVersion(info.CommitDate)

	if len(errs) > 0 && info.ReleaseURL == "" && info.CommitURL == "" {
		info.Error = strings.Join(errs, "; ")
	}

	updateCacheData = info
	updateCacheTime = time.Now()
	return info
}

// commitNewerThanVersion — Ngày commit có sau ngày trong AppVersion (YYYY.M.D) không
func commitNewerThanVersion(commitDate string) bool {
	t, err := time.Parse(time.RFC3339, commitDate)
	if err != nil {
		return false
	}
	parts := parseVersionParts(AppVersion)
	// Lấy hết ngày của version hiện tại làm mốc
	versionDate := time.Date(parts[0], time.Month(parts[1]), parts[2], 23, 59, 59, 0, time.UTC)
	return t.After(versionDate)
}

// ========================== HTTP Handler ==========================

// handleVersion — GET /api/version → phiên bản + thông tin liên hệ
func (app *App) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":      AppVersion,
		"repo_url":     repoURL(),
		"telegram":     TelegramContact,
		"telegram_url": "https://t.me/" + TelegramContact,
	})
}

// handleUpdateCheck — GET /api/update/check?force=1 → kiểm tra bản mới
func (app *App) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	force := r.URL.Query().Get("force") == "1"
	writeJSON(w, http.StatusOK, checkForUpdate(force))
}