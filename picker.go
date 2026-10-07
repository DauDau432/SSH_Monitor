package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// handlePickFile — POST /api/pick-file
// Mở hộp thoại chọn file của Windows trên máy đang chạy app (app chỉ chạy local)
// và trả về đường dẫn tuyệt đối — trình duyệt không cho web đọc đường dẫn thật của file.
func (app *App) handlePickFile(w http.ResponseWriter, r *http.Request) {
	path, err := pickFile(r.Context(), defaultSSHDir())
	w.Header().Set("Content-Type", "application/json")
	switch {
	case errors.Is(err, errPickCancelled):
		json.NewEncoder(w).Encode(map[string]any{"cancelled": true})
	case err != nil:
		httpError(w, err.Error(), http.StatusInternalServerError)
	default:
		json.NewEncoder(w).Encode(map[string]string{"path": path})
	}
}

var errPickCancelled = errors.New("cancelled")

// defaultSSHDir — thư mục mở sẵn trong hộp thoại: ~/.ssh nếu có, không thì thư mục home
func defaultSSHDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if st, err := os.Stat(filepath.Join(home, ".ssh")); err == nil && st.IsDir() {
		return filepath.Join(home, ".ssh")
	}
	return home
}

// pickFile — mở OpenFileDialog qua PowerShell; Form TopMost làm owner để hộp thoại nổi lên trên trình duyệt
func pickFile(ctx context.Context, startDir string) (string, error) {
	script := `[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form -Property @{TopMost = $true; ShowInTaskbar = $false}
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Title = 'Chọn file SSH key'
$d.Filter = 'Tất cả file (*.*)|*.*'
$d.InitialDirectory = $env:PICK_START_DIR
if ($d.ShowDialog($owner) -eq 'OK') { $d.FileName }`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-STA", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "PICK_START_DIR="+startDir)

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return "", errPickCancelled
	}
	return path, nil
}
