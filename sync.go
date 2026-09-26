// ===========================================================================
// File Sync — Đồng bộ 1 file từ VPS nguồn tới nhiều VPS đích
// Truyền file bằng luồng "cat" qua SSH, đi xuyên proxy sẵn có của từng server
// ===========================================================================

package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Giới hạn kích thước file đồng bộ — dữ liệu được đọc trọn vào RAM để
// fan-out tới nhiều máy đích và để kiểm tra md5 sau khi ghi.
const SyncMaxFileSize = 256 * 1024 * 1024 // 256 MB

// Thời gian chờ cho mỗi lệnh SSH của tính năng đồng bộ (dài hơn metrics
// vì stat/md5sum trên file lớn chậm hơn đọc /proc).
const syncCmdTimeout = 60 * time.Second

// ========================== Data Structures ==========================

// SyncTargetState — Trạng thái đồng bộ của 1 máy đích
type SyncTargetState struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Host     string `json:"host"`
	Status   string `json:"status"` // pending, copying, done, failed
	Progress int64  `json:"progress"`
	Error    string `json:"error,omitempty"`
	DestHash string `json:"dest_hash,omitempty"`
}

// SyncJob — Một lần đồng bộ
type SyncJob struct {
	ID         string            `json:"id"`
	SourceID   string            `json:"source_id"`
	SourceName string            `json:"source_name"`
	SourcePath string            `json:"source_path"`
	DestPath   string            `json:"dest_path"`
	FileSize   int64             `json:"file_size"`
	FileHash   string            `json:"file_hash"`
	Status     string            `json:"status"` // running, done, failed, cancelled
	Error      string            `json:"error,omitempty"`
	Targets    []SyncTargetState `json:"targets"`
	CreatedAt  int64             `json:"created_at"`

	mu        sync.Mutex
	cancelled bool
}

// snapshot — Bản copy an toàn để trả về qua API (con trỏ, tránh copy mutex)
func (j *SyncJob) snapshot() *SyncJob {
	j.mu.Lock()
	defer j.mu.Unlock()

	snap := &SyncJob{
		ID:         j.ID,
		SourceID:   j.SourceID,
		SourceName: j.SourceName,
		SourcePath: j.SourcePath,
		DestPath:   j.DestPath,
		FileSize:   j.FileSize,
		FileHash:   j.FileHash,
		Status:     j.Status,
		Error:      j.Error,
		CreatedAt:  j.CreatedAt,
		Targets:    make([]SyncTargetState, len(j.Targets)),
	}
	copy(snap.Targets, j.Targets)
	return snap
}

func (j *SyncJob) setTargetStatus(idx int, status, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Targets[idx].Status = status
	j.Targets[idx].Error = errMsg
}

func (j *SyncJob) setTargetProgress(idx int, n int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Targets[idx].Progress = n
}

func (j *SyncJob) setTargetHash(idx int, hash string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Targets[idx].DestHash = hash
}

func (j *SyncJob) isCancelled() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cancelled
}

// SyncManager — Giữ các job đồng bộ trong RAM (không lưu xuống đĩa)
type SyncManager struct {
	mu   sync.Mutex
	jobs map[string]*SyncJob
	seq  int64
}

func NewSyncManager() *SyncManager {
	return &SyncManager{jobs: make(map[string]*SyncJob)}
}

func (sm *SyncManager) newJobID() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.seq++
	return "sync-" + strconv.FormatInt(time.Now().Unix(), 10) + "-" + strconv.FormatInt(sm.seq, 10)
}

func (sm *SyncManager) put(j *SyncJob) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.jobs[j.ID] = j
}

func (sm *SyncManager) get(id string) *SyncJob {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.jobs[id]
}

// ========================== SSH helpers ==========================

// sshTargetByID — Tìm config + proxy của 1 server theo ID
func (app *App) sshTargetByID(id string) (ServerConfig, *ProxyConfig, error) {
	app.configMu.RLock()
	var cfg ServerConfig
	found := false
	for _, s := range app.config.Servers {
		if s.ID == id {
			cfg = s
			found = true
			break
		}
	}
	app.configMu.RUnlock()

	if !found {
		return cfg, nil, fmt.Errorf("không tìm thấy server id %q", id)
	}
	return cfg, app.findProxy(cfg.ProxyID), nil
}

// openSSH — Mở kết nối SSH mới tới 1 server (qua proxy nếu có cấu hình)
func (app *App) openSSH(id string) (*ssh.Client, ServerConfig, error) {
	cfg, proxy, err := app.sshTargetByID(id)
	if err != nil {
		return nil, cfg, err
	}
	client, err := dialSSHClient(cfg, proxy)
	if err != nil {
		return nil, cfg, err
	}
	return client, cfg, nil
}

// runSSHOnClient — Chạy lệnh trên client có sẵn, có timeout
func runSSHOnClient(client *ssh.Client, cmd string, timeout time.Duration) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := session.CombinedOutput(cmd)
		ch <- result{out, err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			msg := strings.TrimSpace(string(res.out))
			if msg == "" {
				msg = res.err.Error()
			}
			return nil, fmt.Errorf("%s", msg)
		}
		return res.out, nil
	case <-time.After(timeout):
		session.Close()
		return nil, fmt.Errorf("lệnh SSH quá thời gian chờ %v", timeout)
	}
}

// shellQuote — Bọc chuỗi trong nháy đơn an toàn cho shell POSIX
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// cleanRemotePath — Chuẩn hóa đường dẫn remote: tuyệt đối, không "..", không rỗng
func cleanRemotePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("đường dẫn không được để trống")
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("đường dẫn phải là tuyệt đối (bắt đầu bằng /)")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("đường dẫn không được chứa '..'")
		}
	}
	// Gộp dấu / trùng và bỏ / ở cuối (trừ chính nó "/")
	clean := "/" + strings.Join(strings.FieldsFunc(p, func(r rune) bool { return r == '/' }), "/")
	if len(clean) > 4096 {
		return "", fmt.Errorf("đường dẫn quá dài")
	}
	return clean, nil
}

// ========================== Remote file stat ==========================

// remoteFileInfo — Thông tin 1 file trên máy remote
type remoteFileInfo struct {
	State string `json:"state"` // file, missing, dir, noread, notfile
	Size  int64  `json:"size"`
	Hash  string `json:"hash"`
	Mode  string `json:"mode"`
}

// statRemoteFile — Kiểm tra file trên máy remote bằng 1 lệnh shell duy nhất
func statRemoteFile(client *ssh.Client, path string) (*remoteFileInfo, error) {
	q := shellQuote(path)
	cmd := fmt.Sprintf(`P=%s
if [ ! -e "$P" ]; then echo "state=missing"; exit 0; fi
if [ -d "$P" ]; then echo "state=dir"; exit 0; fi
if [ ! -f "$P" ]; then echo "state=notfile"; exit 0; fi
if [ ! -r "$P" ]; then echo "state=noread"; exit 0; fi
echo "state=file"
echo "size=$(stat -c '%%s' "$P" 2>/dev/null | tr -d '[:space:]')"
echo "mode=$(stat -c '%%A' "$P" 2>/dev/null)"
echo "hash=$(md5sum "$P" 2>/dev/null | cut -d' ' -f1)"`, q)

	out, err := runSSHOnClient(client, cmd, syncCmdTimeout)
	if err != nil {
		return nil, err
	}

	info := &remoteFileInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "state":
			info.State = kv[1]
		case "size":
			info.Size, _ = strconv.ParseInt(kv[1], 10, 64)
		case "mode":
			info.Mode = kv[1]
		case "hash":
			info.Hash = kv[1]
		}
	}
	if info.State == "" {
		return nil, fmt.Errorf("không đọc được thông tin file (output rỗng)")
	}
	return info, nil
}

// statRemoteDir — Kiểm tra thư mục cha của đường dẫn đích có tồn tại & ghi được không
func statRemoteDir(client *ssh.Client, path string) (state string, err error) {
	q := shellQuote(path)
	cmd := fmt.Sprintf(`D=$(dirname %s)
echo "dir=$D"
if [ ! -e "$D" ]; then echo "state=missing"; elif [ ! -d "$D" ]; then echo "state=notdir"; elif [ ! -w "$D" ]; then echo "state=nowrite"; else echo "state=ok"; fi`, q)

	out, err := runSSHOnClient(client, cmd, syncCmdTimeout)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "state=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "state=")), nil
		}
	}
	return "", fmt.Errorf("không kiểm tra được thư mục đích")
}

// ========================== File browser ==========================

// fsEntry — 1 dòng trong danh sách thư mục remote
type fsEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	MTime int64  `json:"mtime"`
}

// handleFSList — POST /api/fs/list
// Duyệt thư mục trên 1 VPS để admin chọn file nguồn (không phải gõ đường dẫn)
func (app *App) handleFSList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServerID string `json:"server_id"`
		Path     string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ServerID) == "" {
		httpError(w, "Thiếu server_id", http.StatusBadRequest)
		return
	}

	client, _, err := app.openSSH(req.ServerID)
	if err != nil {
		httpError(w, "Không kết nối được SSH: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer client.Close()

	raw := strings.TrimSpace(req.Path)
	var cmd string
	isFileReq := false
	if raw == "" || raw == "~" {
		// Mặc định mở thư mục home của user SSH
		cmd = `P="$HOME"; cd "$P" 2>/dev/null || { echo "CANNOT_CD"; exit 0; }`
	} else {
		path, perr := cleanRemotePath(raw)
		if perr != nil {
			httpError(w, perr.Error(), http.StatusBadRequest)
			return
		}
		// Nếu đường dẫn là file: báo ISFILE và duyệt thư mục chứa nó
		cmd = fmt.Sprintf(`P=%s
if [ -f "$P" ]; then echo "ISFILE"; P=$(dirname "$P"); fi
cd "$P" 2>/dev/null || { echo "CANNOT_CD"; exit 0; }`, shellQuote(path))
		isFileReq = true
	}
	cmd += `
echo "PATH=$(pwd -P)"
for f in * .[!.]* ..?*; do
  [ -e "$f" ] || continue
  stat -c '%F|%s|%Y|%A|%n' "$f" 2>/dev/null
done`

	out, err := runSSHOnClient(client, cmd, syncCmdTimeout)
	if err != nil {
		httpError(w, "Lỗi liệt kê thư mục: "+err.Error(), http.StatusBadGateway)
		return
	}

	resolvedPath := raw
	entries := []fsEntry{}
	cannotCD := false
	isFile := false

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "CANNOT_CD" {
			cannotCD = true
			continue
		}
		if trimmed == "ISFILE" {
			isFile = true
			continue
		}
		if strings.HasPrefix(trimmed, "PATH=") {
			resolvedPath = strings.TrimPrefix(trimmed, "PATH=")
			continue
		}
		// Dòng stat: loại|size|mtime|quyền|tên   (tên có thể chứa '|')
		parts := strings.SplitN(line, "|", 5)
		if len(parts) != 5 {
			continue
		}
		size, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		mtime, _ := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		ftype := strings.TrimSpace(parts[0])
		entries = append(entries, fsEntry{
			Name:  parts[4],
			IsDir: ftype == "directory",
			Size:  size,
			Mode:  strings.TrimSpace(parts[3]),
			MTime: mtime,
		})
	}

	if cannotCD {
		httpError(w, "Không vào được thư mục "+raw+" (không tồn tại hoặc không có quyền đọc)", http.StatusBadRequest)
		return
	}

	resp := map[string]interface{}{
		"path":    resolvedPath,
		"parent":  parentPath(resolvedPath),
		"entries": entries,
	}
	// Đường dẫn là file: báo để frontend tự chọn file đó và duyệt thư mục chứa nó
	if isFileReq && isFile {
		resp["is_file"] = true
		resp["file_path"] = raw
	}
	writeJSON(w, http.StatusOK, resp)
}

// parentPath — Đường dẫn cha (dùng cho nút "Lên 1 cấp")
func parentPath(p string) string {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "/"
	}
	idx := strings.LastIndex(p, "/")
	if idx <= 0 {
		return "/"
	}
	return p[:idx]
}

// ========================== Inspect (duyệt trước khi đồng bộ) ==========================

// inspectSource — Kết quả kiểm tra máy nguồn
type inspectSource struct {
	OK    bool            `json:"ok"`
	State string          `json:"state"`
	Error string          `json:"error,omitempty"`
	Info  *remoteFileInfo `json:"info,omitempty"`
}

// inspectTarget — Kết quả kiểm tra 1 máy đích
type inspectTarget struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Host      string `json:"host"`
	Group     string `json:"group"`
	OK        bool   `json:"ok"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
	DirState  string `json:"dir_state,omitempty"`
	DestDir   string `json:"dest_dir,omitempty"`
	Exists    bool   `json:"exists"`
	Size      int64  `json:"size"`
	Hash      string `json:"hash,omitempty"`
	Same      bool   `json:"same"` // md5 trùng nguồn → không cần copy
}

// handleSyncInspect — POST /api/sync/inspect
// Kiểm tra kỹ trước khi copy: file nguồn có thật không, nặng bao nhiêu,
// md5 là gì; từng máy đích đã có file chưa, thư mục đích có ghi được không.
func (app *App) handleSyncInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SourceID   string   `json:"source_id"`
		SourcePath string   `json:"source_path"`
		DestPath   string   `json:"dest_path"`
		TargetIDs  []string `json:"target_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	srcPath, err := cleanRemotePath(req.SourcePath)
	if err != nil {
		httpError(w, "Đường dẫn nguồn: "+err.Error(), http.StatusBadRequest)
		return
	}
	dstPath := srcPath
	if strings.TrimSpace(req.DestPath) != "" {
		dstPath, err = cleanRemotePath(req.DestPath)
		if err != nil {
			httpError(w, "Đường dẫn đích: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if strings.TrimSpace(req.SourceID) == "" {
		httpError(w, "Chưa chọn máy nguồn", http.StatusBadRequest)
		return
	}

	res := struct {
		Source     inspectSource   `json:"source"`
		Targets    []inspectTarget `json:"targets"`
		SourcePath string          `json:"source_path"`
		DestPath   string          `json:"dest_path"`
		DestDir    string          `json:"dest_dir"`
	}{
		Source:     inspectSource{},
		Targets:    []inspectTarget{},
		SourcePath: srcPath,
		DestPath:   dstPath,
		DestDir:    parentPath(dstPath),
	}

	// --- Kiểm tra máy nguồn ---
	srcClient, srcCfg, err := app.openSSH(req.SourceID)
	if err != nil {
		res.Source.State = "unreachable"
		res.Source.Error = err.Error()
		writeJSON(w, http.StatusOK, res)
		return
	}

	srcInfo, err := statRemoteFile(srcClient, srcPath)
	srcClient.Close()
	if err != nil {
		res.Source.State = "error"
		res.Source.Error = err.Error()
		writeJSON(w, http.StatusOK, res)
		return
	}
	res.Source.Info = srcInfo
	res.Source.State = srcInfo.State
	res.Source.OK = srcInfo.State == "file"
	switch srcInfo.State {
	case "missing":
		res.Source.Error = "File không tồn tại trên máy nguồn"
	case "dir":
		res.Source.Error = "Đường dẫn là thư mục, không phải file"
	case "notfile":
		res.Source.Error = "Đường dẫn không phải file thường"
	case "noread":
		res.Source.Error = "Không có quyền đọc file này"
	case "file":
		if srcInfo.Size > SyncMaxFileSize {
			res.Source.OK = false
			res.Source.Error = fmt.Sprintf("File %s vượt giới hạn %s",
				humanBytes(srcInfo.Size), humanBytes(SyncMaxFileSize))
		}
	}
	_ = srcCfg

	// Máy nguồn lỗi thì không cần kiểm tra đích
	if !res.Source.OK {
		writeJSON(w, http.StatusOK, res)
		return
	}

	// --- Kiểm tra song song từng máy đích ---
	type indexed struct {
		i int
		t inspectTarget
	}
	results := make(chan indexed, len(req.TargetIDs))
	var wg sync.WaitGroup

	for i, tid := range req.TargetIDs {
		wg.Add(1)
		go func(i int, tid string) {
			defer wg.Done()
			results <- indexed{i, app.inspectOneTarget(tid, dstPath, res.Source.Info.Hash)}
		}(i, tid)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]inspectTarget, len(req.TargetIDs))
	for r := range results {
		out[r.i] = r.t
	}
	res.Targets = out

	writeJSON(w, http.StatusOK, res)
}

// inspectOneTarget — Kiểm tra 1 máy đích: reach được không, thư mục đích, file đã tồn tại
func (app *App) inspectOneTarget(id, destPath, srcHash string) inspectTarget {
	app.configMu.RLock()
	var cfg ServerConfig
	found := false
	for _, s := range app.config.Servers {
		if s.ID == id {
			cfg = s
			found = true
			break
		}
	}
	app.configMu.RUnlock()

	t := inspectTarget{ID: id}
	if !found {
		t.Error = "Không tìm thấy server trong cấu hình"
		return t
	}
	t.Label = cfg.Label
	if t.Label == "" {
		t.Label = cfg.Host
	}
	t.Host = cfg.Host
	t.Group = cfg.Group
	t.DestDir = parentPath(destPath)

	client, _, err := app.openSSH(id)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	defer client.Close()
	t.Reachable = true

	dirState, err := statRemoteDir(client, destPath)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	t.DirState = dirState
	if dirState != "ok" {
		switch dirState {
		case "missing":
			t.Error = "Thư mục đích không tồn tại: " + t.DestDir
		case "notdir":
			t.Error = "Đường dẫn cha không phải thư mục: " + t.DestDir
		case "nowrite":
			t.Error = "Không có quyền ghi vào: " + t.DestDir
		}
		return t
	}

	info, err := statRemoteFile(client, destPath)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	if info.State == "dir" {
		t.Error = "Đường dẫn đích là thư mục: " + destPath
		return t
	}
	if info.State == "file" {
		t.Exists = true
		t.Size = info.Size
		t.Hash = info.Hash
		t.Same = srcHash != "" && info.Hash == srcHash
	}
	t.OK = true
	return t
}

// ========================== Sync job ==========================

// handleSyncStart — POST /api/sync/start
// Đọc file từ nguồn 1 lần rồi đẩy song song tới tất cả máy đích
func (app *App) handleSyncStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SourceID   string   `json:"source_id"`
		SourcePath string   `json:"source_path"`
		DestPath   string   `json:"dest_path"`
		TargetIDs  []string `json:"target_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	srcPath, err := cleanRemotePath(req.SourcePath)
	if err != nil {
		httpError(w, "Đường dẫn nguồn: "+err.Error(), http.StatusBadRequest)
		return
	}
	dstPath := srcPath
	if strings.TrimSpace(req.DestPath) != "" {
		dstPath, err = cleanRemotePath(req.DestPath)
		if err != nil {
			httpError(w, "Đường dẫn đích: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if strings.TrimSpace(req.SourceID) == "" {
		httpError(w, "Chưa chọn máy nguồn", http.StatusBadRequest)
		return
	}
	if len(req.TargetIDs) == 0 {
		httpError(w, "Chưa chọn máy đích nào", http.StatusBadRequest)
		return
	}
	for _, tid := range req.TargetIDs {
		if tid == req.SourceID {
			httpError(w, "Máy nguồn không thể là máy đích", http.StatusBadRequest)
			return
		}
	}

	// Resolve label máy nguồn cho dễ đọc trong UI
	srcCfg, _, err := app.sshTargetByID(req.SourceID)
	if err != nil {
		httpError(w, err.Error(), http.StatusBadRequest)
		return
	}
	srcName := srcCfg.Label
	if srcName == "" {
		srcName = srcCfg.Host
	}

	targets := make([]SyncTargetState, 0, len(req.TargetIDs))
	for _, tid := range req.TargetIDs {
		cfg, _, err := app.sshTargetByID(tid)
		if err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}
		label := cfg.Label
		if label == "" {
			label = cfg.Host
		}
		targets = append(targets, SyncTargetState{
			ID:     tid,
			Label:  label,
			Host:   cfg.Host,
			Status: "pending",
		})
	}

	job := &SyncJob{
		ID:         app.syncMgr.newJobID(),
		SourceID:   req.SourceID,
		SourceName: srcName,
		SourcePath: srcPath,
		DestPath:   dstPath,
		Status:     "running",
		Targets:    targets,
		CreatedAt:  time.Now().Unix(),
	}
	app.syncMgr.put(job)

	go app.runSyncJob(job)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID,
		"job":    job.snapshot(),
	})
}

// runSyncJob — Luồng chính: đọc file nguồn → fan-out ghi song song tới các đích
func (app *App) runSyncJob(job *SyncJob) {
	// Bước 1: đọc trọn file từ máy nguồn
	data, size, hash, err := app.readSourceFile(job.SourceID, job.SourcePath)
	if err != nil {
		job.mu.Lock()
		job.Status = "failed"
		job.Error = "Đọc file từ máy nguồn thất bại: " + err.Error()
		job.mu.Unlock()
		for i := range job.Targets {
			job.setTargetStatus(i, "failed", "Bỏ qua do không đọc được file nguồn")
		}
		log.Printf("[Sync] %s: source read failed: %v", job.ID, err)
		return
	}

	job.mu.Lock()
	job.FileSize = size
	job.FileHash = hash
	job.mu.Unlock()

	log.Printf("[Sync] %s: %s (%s, md5 %s) → %d máy đích",
		job.ID, job.SourcePath, humanBytes(size), hash, len(job.Targets))

	// Bước 2: đẩy song song tới từng máy đích
	var wg sync.WaitGroup
	for i := range job.Targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			app.syncOneTarget(job, i, data, size, hash)
		}(i)
	}
	wg.Wait()

	// Bước 3: tổng kết
	job.mu.Lock()
	if job.cancelled {
		job.Status = "cancelled"
	} else {
		failed := 0
		for _, t := range job.Targets {
			if t.Status == "failed" {
				failed++
			}
		}
		if failed == len(job.Targets) {
			job.Status = "failed"
			job.Error = "Tất cả máy đích đều lỗi"
		} else if failed > 0 {
			job.Status = "partial"
			job.Error = fmt.Sprintf("%d/%d máy đích lỗi", failed, len(job.Targets))
		} else {
			job.Status = "done"
		}
	}
	status := job.Status
	job.mu.Unlock()

	log.Printf("[Sync] %s: finished (%s)", job.ID, status)
}

// readSourceFile — Đọc trọn nội dung file từ máy nguồn, trả về bytes + size + md5
func (app *App) readSourceFile(id, path string) ([]byte, int64, string, error) {
	client, _, err := app.openSSH(id)
	if err != nil {
		return nil, 0, "", err
	}
	defer client.Close()

	// Kiểm tra trước để tránh kéo về file khổng lồ
	info, err := statRemoteFile(client, path)
	if err != nil {
		return nil, 0, "", err
	}
	if info.State != "file" {
		return nil, 0, "", fmt.Errorf("đường dẫn không phải file đọc được (trạng thái: %s)", info.State)
	}
	if info.Size > SyncMaxFileSize {
		return nil, 0, "", fmt.Errorf("file %s vượt giới hạn %s", humanBytes(info.Size), humanBytes(SyncMaxFileSize))
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, 0, "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// Đọc qua pipe + timeout để file lớn không treo vô hạn
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, 0, "", fmt.Errorf("stdout pipe: %w", err)
	}
	if err := session.Start("cat " + shellQuote(path)); err != nil {
		return nil, 0, "", fmt.Errorf("start cat: %w", err)
	}

	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		// Giới hạn cứng: không cho phép đọc vượt quá trần
		buf, err := io.ReadAll(io.LimitReader(stdout, SyncMaxFileSize+1))
		ch <- readResult{buf, err}
	}()

	var data []byte
	select {
	case res := <-ch:
		if res.err != nil {
			session.Close()
			return nil, 0, "", fmt.Errorf("đọc dữ liệu: %w", res.err)
		}
		data = res.data
	case <-time.After(syncCmdTimeout):
		session.Close()
		return nil, 0, "", fmt.Errorf("đọc file quá thời gian chờ %v", syncCmdTimeout)
	}

	if waitErr := session.Wait(); waitErr != nil {
		return nil, 0, "", fmt.Errorf("cat trên máy nguồn lỗi: %w", waitErr)
	}
	if int64(len(data)) > SyncMaxFileSize {
		return nil, 0, "", fmt.Errorf("file vượt giới hạn %s", humanBytes(SyncMaxFileSize))
	}

	sum := md5.Sum(data)
	return data, int64(len(data)), hex.EncodeToString(sum[:]), nil
}

// syncOneTarget — Ghi file lên 1 máy đích rồi kiểm tra lại md5
func (app *App) syncOneTarget(job *SyncJob, idx int, data []byte, size int64, srcHash string) {
	target := job.Targets[idx].ID
	job.setTargetStatus(idx, "copying", "")

	client, _, err := app.openSSH(target)
	if err != nil {
		job.setTargetStatus(idx, "failed", "Không kết nối được SSH: "+err.Error())
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		job.setTargetStatus(idx, "failed", "Tạo session lỗi: "+err.Error())
		return
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		job.setTargetStatus(idx, "failed", "Stdin pipe lỗi: "+err.Error())
		return
	}

	// Ghi vào file tạm rồi mv -f để việc ghi đè là nguyên tử (không để lại
	// file cụt nếu đứt giữa chừng), đồng thời giữ nguyên owner/quyền của file cũ.
	q := shellQuote(job.DestPath)
	cmd := fmt.Sprintf(`P=%s
T="$P.synctmp.$$"
trap 'rm -f "$T"' EXIT
cat > "$T" || exit 1
if [ "$(stat -c '%%s' "$T" 2>/dev/null | tr -d '[:space:]')" != "%d" ]; then
  echo "kích thước file ghi được không khớp" >&2
  exit 1
fi
if [ -f "$P" ]; then
  chown --reference="$P" "$T" 2>/dev/null
  chmod --reference="$P" "$T" 2>/dev/null
fi
mv -f "$T" "$P" || exit 1
trap - EXIT`, q, size)

	var stderr bytes.Buffer
	session.Stderr = &stderr

	if err := session.Start(cmd); err != nil {
		job.setTargetStatus(idx, "failed", "Chạy lệnh ghi file lỗi: "+err.Error())
		return
	}

	// Bơm dữ liệu, đếm tiến trình
	var progress int64
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		buf := make([]byte, 64*1024)
		r := bytes.NewReader(data)
		for {
			if job.isCancelled() {
				pw.CloseWithError(fmt.Errorf("đã hủy"))
				return
			}
			n, err := r.Read(buf)
			if n > 0 {
				if _, werr := pw.Write(buf[:n]); werr != nil {
					return
				}
				progress += int64(n)
				job.setTargetProgress(idx, progress)
			}
			if err != nil {
				return
			}
		}
	}()

	_, copyErr := io.Copy(stdin, pr)
	stdin.Close()

	waitErr := session.Wait()
	if copyErr != nil {
		job.setTargetStatus(idx, "failed", "Ghi dữ liệu lỗi: "+copyErr.Error())
		return
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		job.setTargetStatus(idx, "failed", "Ghi file lỗi: "+msg)
		return
	}

	// Kiểm chứng md5 sau khi ghi
	newInfo, err := statRemoteFile(client, job.DestPath)
	if err != nil {
		job.setTargetStatus(idx, "failed", "Đã ghi nhưng không kiểm tra lại được: "+err.Error())
		return
	}
	job.setTargetHash(idx, newInfo.Hash)

	if newInfo.State != "file" {
		job.setTargetStatus(idx, "failed", "File đích không tồn tại sau khi ghi")
		return
	}
	if srcHash != "" && newInfo.Hash != srcHash {
		job.setTargetStatus(idx, "failed",
			fmt.Sprintf("md5 không khớp (nguồn %s, đích %s)", short(srcHash), short(newInfo.Hash)))
		return
	}

	job.setTargetProgress(idx, size)
	job.setTargetStatus(idx, "done", "")
}

// handleSyncJobStatus — GET /api/sync/jobs/{id}
func (app *App) handleSyncJobStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := extractPathID(r.URL.Path, "/api/sync/jobs/")
	job := app.syncMgr.get(id)
	if job == nil {
		httpError(w, "Không tìm thấy job "+id, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"job": job.snapshot()})
}

// handleSyncCancel — POST /api/sync/cancel
func (app *App) handleSyncCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.JobID == "" {
		httpError(w, "Thiếu job_id", http.StatusBadRequest)
		return
	}
	job := app.syncMgr.get(req.JobID)
	if job == nil {
		httpError(w, "Không tìm thấy job", http.StatusNotFound)
		return
	}
	job.mu.Lock()
	if !job.cancelled {
		job.cancelled = true
	}
	job.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ========================== Helpers ==========================

// writeJSON — Ghi response JSON
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// humanBytes — Định dạng dung lượng dễ đọc
func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return strconv.FormatInt(b, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	val := float64(b) / float64(div)
	suffix := []string{"KB", "MB", "GB", "TB"}[exp]
	if val >= 100 {
		return fmt.Sprintf("%.0f %s", val, suffix)
	}
	return fmt.Sprintf("%.1f %s", val, suffix)
}

// short — Rút gọn hash cho dễ đọc trên UI
func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
