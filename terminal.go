// ===========================================================================
// Web Terminal — SSH shell qua WebSocket (xterm.js ↔ PTY)
// ===========================================================================

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// terminalMessage — Protocol JSON giữa frontend và backend
// type: "input" (gõ phím), "resize" (đổi kích thước), "output" (server trả về)
type terminalMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// handleTerminalWS — GET /ws/terminal/{serverID}
// Mở SSH session độc lập (không dùng chung connection metrics), cấp PTY + shell
func (app *App) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	id := extractPathID(r.URL.Path, "/ws/terminal/")
	if id == "" {
		httpError(w, "Server ID is required", http.StatusBadRequest)
		return
	}

	// Lấy config server
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
	proxy := app.findProxy(cfg.ProxyID) // findProxy tự lock → gọi ngoài RLock

	if !found {
		httpError(w, "Server not found", http.StatusNotFound)
		return
	}

	// Upgrade lên WebSocket trước để gửi lỗi qua WS cho frontend hiển thị
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Terminal] Upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Xóa deadline do http.Server ReadTimeout/WriteTimeout đặt ra —
	// nếu không, kết nối WS sẽ bị kill sau 15 giây
	conn.UnderlyingConn().SetReadDeadline(time.Time{})
	conn.UnderlyingConn().SetWriteDeadline(time.Time{})

	sendError := func(msg string) {
		log.Printf("[Terminal] %s: %s", cfg.Label, msg)
		data, _ := json.Marshal(terminalMessage{Type: "output", Data: "\r\n\x1b[31m" + msg + "\x1b[0m\r\n"})
		conn.WriteMessage(websocket.TextMessage, data)
	}

	// Kết nối SSH mới (qua proxy nếu có)
	client, err := dialSSHClient(cfg, proxy)
	if err != nil {
		sendError("SSH connect failed: " + err.Error())
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		sendError("SSH session failed: " + err.Error())
		return
	}
	defer session.Close()

	// PTY mặc định 80x24 — frontend sẽ gửi resize ngay sau khi kết nối
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		sendError("Request PTY failed: " + err.Error())
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		sendError("Stdin pipe failed: " + err.Error())
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		sendError("Stdout pipe failed: " + err.Error())
		return
	}
	// Không lấy stderr pipe: shell chạy PTY đã gộp stderr vào stdout,
	// và gorilla/websocket không cho phép 2 goroutine ghi đồng thời 1 conn.

	if err := session.Shell(); err != nil {
		sendError("Start shell failed: " + err.Error())
		return
	}
	log.Printf("[Terminal] Shell started for %s (%s)", cfg.Label, cfg.Host)

	// SSH output → WebSocket
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				msg, _ := json.Marshal(terminalMessage{Type: "output", Data: string(buf[:n])})
				if werr := conn.WriteMessage(websocket.TextMessage, msg); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket → SSH stdin
	wsToSSH := func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var msg terminalMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			switch msg.Type {
			case "input":
				if _, err := stdin.Write([]byte(msg.Data)); err != nil {
					return
				}
			case "resize":
				if msg.Cols > 0 && msg.Rows > 0 {
					session.WindowChange(msg.Rows, msg.Cols)
				}
			}
		}
	}
	wsDone := make(chan struct{})
	go func() {
		defer close(wsDone)
		wsToSSH()
	}()

	// Chờ một trong hai phía kết thúc trước rồi dọn phía còn lại
	select {
	case <-done: // Shell thoát (user gõ exit, hoặc server ngắt)
		conn.Close() // unblock wsToSSH
		<-wsDone
	case <-wsDone: // Trình duyệt đóng tab/modal
		session.Close() // unblock stdout read
		<-done
	}
	log.Printf("[Terminal] Shell closed for %s (%s)", cfg.Label, cfg.Host)
}

// dialSSHClient — Tạo SSH client mới tới server (qua proxy nếu cấu hình)
func dialSSHClient(cfg ServerConfig, proxy *ProxyConfig) (*ssh.Client, error) {
	agent := NewMonitorAgent(cfg, proxy)
	sshConfig, err := agent.buildSSHConfig()
	if err != nil {
		return nil, fmt.Errorf("auth config: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	netConn, err := dialThroughProxy(addr, proxy, SSHDialTimeout)
	if err != nil {
		if proxy != nil {
			return nil, fmt.Errorf("proxy %s: %w", proxy.Name, err)
		}
		return nil, fmt.Errorf("dial: %w", err)
	}

	netConn.SetDeadline(time.Now().Add(SSHDialTimeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, sshConfig)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	netConn.SetDeadline(time.Time{})

	return ssh.NewClient(sshConn, chans, reqs), nil
}
