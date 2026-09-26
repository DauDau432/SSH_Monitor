// ===========================================================================
// SSH Monitor — Agentless VPS Monitoring (Golang Backend)
// Persistent SSH connections, real-time WebSocket broadcast, embedded frontend
// ===========================================================================

package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

//go:embed static
var staticFiles embed.FS

// ========================== Constants ==========================

const (
	CollectInterval   = 1 * time.Second  // Chu kỳ thu thập metrics
	BroadcastInterval = 1 * time.Second  // Chu kỳ đẩy dữ liệu WebSocket
	SSHDialTimeout    = 10 * time.Second // Timeout kết nối SSH
	CmdExecTimeout    = 8 * time.Second  // Timeout chạy lệnh
	ReconnectDelay    = 10 * time.Second // Delay giữa các lần reconnect
	WSPingInterval    = 30 * time.Second // Ping WebSocket clients
	WSWriteTimeout    = 5 * time.Second  // Timeout ghi WebSocket
	ServerPort        = ":8080"
	ConfigFileName    = "servers.json"
)

// Lệnh SSH gộp — lấy toàn bộ metrics trong 1 lần gọi
const metricsCommand = `head -1 /proc/stat; echo '---DELIM---'; grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached):' /proc/meminfo; echo '---DELIM---'; df -h / | tail -1; echo '---DELIM---'; cat /proc/net/dev; echo '---DELIM---'; cat /proc/uptime; echo '---DELIM---'; nproc; echo '---DELIM---'; cat /proc/diskstats; echo '---DELIM---'; grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null || head -1 /etc/redhat-release 2>/dev/null || echo 'Unknown'; echo '---DELIM---'; cat /proc/sys/kernel/osrelease 2>/dev/null || uname -r; echo '---DELIM---'; grep -m1 -iE '^(model name|Hardware)' /proc/cpuinfo 2>/dev/null`

// ========================== Data Structures ==========================

// ServerConfig — Cấu hình kết nối 1 server
type ServerConfig struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	KeyPath  string `json:"key_path"`
	Group    string `json:"group"`
	ProxyID  string `json:"proxy_id,omitempty"` // rỗng = kết nối trực tiếp
}

// ConfigFile — Cấu trúc file servers.json
type ConfigFile struct {
	Groups       []string       `json:"groups,omitempty"`
	Servers      []ServerConfig `json:"servers"`
	Proxies      []ProxyConfig  `json:"proxies,omitempty"`
	NextServerID int            `json:"next_server_id,omitempty"`
	NextProxyID  int            `json:"next_proxy_id,omitempty"`
}

// ServerMetrics — Số liệu giám sát gửi về frontend
type ServerMetrics struct {
	ID          string  `json:"id"`
	Label       string  `json:"label"`
	Host        string  `json:"host"`
	Group       string  `json:"group"`
	Status      string  `json:"status"` // online, offline, connecting
	Error       string  `json:"error,omitempty"`
	CPUPercent  float64 `json:"cpu_percent"`
	RAMTotalMB  uint64  `json:"ram_total_mb"`
	RAMUsedMB   uint64  `json:"ram_used_mb"`
	RAMFreeMB   uint64  `json:"ram_free_mb"` // MemAvailable thật từ /proc/meminfo
	RAMPercent  float64 `json:"ram_percent"`
	DiskTotal   string  `json:"disk_total"`
	DiskUsed    string  `json:"disk_used"`
	DiskAvail   string  `json:"disk_avail"` // Cột Avail thật từ df -h
	DiskPercent float64 `json:"disk_percent"`
	NetTXRate   float64 `json:"net_tx_rate"`   // bytes/s
	NetRXRate   float64 `json:"net_rx_rate"`   // bytes/s
	IOReadRate  float64 `json:"io_read_rate"`  // bytes/s
	IOWriteRate float64 `json:"io_write_rate"` // bytes/s
	Uptime      string  `json:"uptime"`
	CPUCores    int     `json:"cpu_cores"`
	CPUModel    string  `json:"cpu_model"` // Loại CPU (model name từ /proc/cpuinfo)
	OS          string  `json:"os"`        // Hệ điều hành (PRETTY_NAME từ /etc/os-release)
	Kernel      string  `json:"kernel"`    // Kernel (từ /proc/sys/kernel/osrelease)
	UpdatedAt   int64   `json:"updated_at"`
}

// CPUStats — Raw CPU jiffies từ /proc/stat
type CPUStats struct {
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
	Total   uint64
}

// NetStats — Raw bytes từ /proc/net/dev
type NetStats struct {
	RXBytes uint64
	TXBytes uint64
	Time    time.Time
}

// IOStats — Raw sectors từ /proc/diskstats
type IOStats struct {
	ReadSectors  uint64
	WriteSectors uint64
	Time         time.Time
}

// ========================== Monitor Agent ==========================
// Mỗi MonitorAgent giữ 1 persistent SSH connection cho 1 server

type MonitorAgent struct {
	config    ServerConfig
	proxy     *ProxyConfig // nil = kết nối trực tiếp
	client    *ssh.Client
	metrics   ServerMetrics
	prevCPU   *CPUStats
	prevNet   *NetStats
	prevIO    *IOStats
	nextRetry time.Time // Không dial lại trước thời điểm này (backoff khi offline)
	mu        sync.RWMutex
	stopCh    chan struct{}
}

// NewMonitorAgent — Khởi tạo agent cho 1 server
func NewMonitorAgent(cfg ServerConfig, proxy *ProxyConfig) *MonitorAgent {
	return &MonitorAgent{
		config: cfg,
		proxy:  proxy,
		metrics: ServerMetrics{
			ID:     cfg.ID,
			Label:  cfg.Label,
			Host:   cfg.Host,
			Group:  cfg.Group,
			Status: "connecting",
		},
		stopCh: make(chan struct{}),
	}
}

// Run — Vòng lặp chính: kết nối + thu thập metrics định kỳ
func (a *MonitorAgent) Run() {
	defer func() {
		if a.client != nil {
			a.client.Close()
		}
	}()

	// Thu thập lần đầu ngay lập tức
	a.connectAndCollect()

	ticker := time.NewTicker(CollectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.connectAndCollect()
		}
	}
}

// Stop — Dừng agent an toàn
func (a *MonitorAgent) Stop() {
	select {
	case <-a.stopCh:
		// Đã đóng rồi
	default:
		close(a.stopCh)
	}
}

// GetMetrics — Đọc metrics hiện tại (thread-safe)
func (a *MonitorAgent) GetMetrics() ServerMetrics {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.metrics
}

// connectAndCollect — Kết nối SSH nếu cần, thu thập metrics
func (a *MonitorAgent) connectAndCollect() {
	// Kết nối nếu chưa có connection (tôn trọng backoff khi đang offline)
	if a.client == nil {
		if time.Now().Before(a.nextRetry) {
			return
		}
		a.connect()
	}

	// Thu thập metrics nếu đã kết nối
	if a.client != nil {
		err := a.collectMetrics()
		if err != nil {
			log.Printf("[%s] Collect error: %v", a.config.ID, err)
			// Đóng connection bị hỏng
			a.client.Close()
			a.client = nil
			a.setStatus("offline", err.Error())
		}
	}
}

// connect — Thiết lập SSH connection (qua proxy nếu server có cấu hình)
func (a *MonitorAgent) connect() {
	a.setStatus("connecting", "")

	sshConfig, err := a.buildSSHConfig()
	if err != nil {
		a.nextRetry = time.Now().Add(ReconnectDelay)
		a.setStatus("offline", "Auth config error: "+err.Error())
		return
	}

	addr := fmt.Sprintf("%s:%d", a.config.Host, a.config.Port)

	conn, err := dialThroughProxy(addr, a.proxy, SSHDialTimeout)
	if err != nil {
		a.nextRetry = time.Now().Add(ReconnectDelay)
		if a.proxy != nil {
			err = fmt.Errorf("proxy %s: %w", a.proxy.Name, err)
		}
		a.setStatus("offline", "Dial failed: "+err.Error())
		return
	}

	// Deadline cho SSH handshake (ssh.Dial tự xử lý, NewClientConn thì không)
	conn.SetDeadline(time.Now().Add(SSHDialTimeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		a.nextRetry = time.Now().Add(ReconnectDelay)
		a.setStatus("offline", "SSH handshake failed: "+err.Error())
		return
	}
	conn.SetDeadline(time.Time{}) // gỡ deadline sau handshake

	a.client = ssh.NewClient(sshConn, chans, reqs)
	if a.proxy != nil {
		log.Printf("[%s] Connected to %s via proxy %s", a.config.ID, addr, a.proxy.Name)
	} else {
		log.Printf("[%s] Connected to %s", a.config.ID, addr)
	}
}

// buildSSHConfig — Tạo cấu hình SSH auth (key + password)
func (a *MonitorAgent) buildSSHConfig() (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	// Thử key-based auth trước
	if a.config.KeyPath != "" {
		keyPath := expandPath(a.config.KeyPath)
		keyBytes, err := os.ReadFile(keyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(keyBytes)
			if err != nil && a.config.Password != "" {
				// Key có passphrase → thử dùng password làm passphrase
				signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(a.config.Password))
			}
			if err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			} else {
				log.Printf("[%s] Key parse warning: %v", a.config.ID, err)
			}
		} else {
			log.Printf("[%s] Key read warning: %v", a.config.ID, err)
		}
	}

	// Password auth (fallback hoặc primary)
	if a.config.Password != "" {
		authMethods = append(authMethods, ssh.Password(a.config.Password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods configured (need password or key_path)")
	}

	return &ssh.ClientConfig{
		User:            a.config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         SSHDialTimeout,
	}, nil
}

// collectMetrics — Chạy lệnh SSH lấy metrics, parse kết quả
func (a *MonitorAgent) collectMetrics() error {
	session, err := a.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// Chạy với timeout
	type cmdResult struct {
		output []byte
		err    error
	}
	resultCh := make(chan cmdResult, 1)

	go func() {
		out, err := session.CombinedOutput(metricsCommand)
		resultCh <- cmdResult{out, err}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			return fmt.Errorf("command exec: %w", res.err)
		}
		a.parseAllMetrics(string(res.output))
		return nil
	case <-time.After(CmdExecTimeout):
		session.Close() // Force close session → goroutine sẽ exit
		return fmt.Errorf("command timeout after %v", CmdExecTimeout)
	}
}

// setStatus — Cập nhật trạng thái server (thread-safe)
func (a *MonitorAgent) setStatus(status, errMsg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.metrics.Status = status
	a.metrics.Error = errMsg
	a.metrics.UpdatedAt = time.Now().Unix()
}

// ========================== Metrics Parsing ==========================

// parseAllMetrics — Parse toàn bộ output từ lệnh gộp
func (a *MonitorAgent) parseAllMetrics(output string) {
	sections := strings.Split(output, "---DELIM---")
	if len(sections) < 5 {
		a.setStatus("offline", "Invalid metrics output format")
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Section 0: CPU — /proc/stat (dòng đầu)
	cpuStats := parseCPULine(strings.TrimSpace(sections[0]))
	if a.prevCPU != nil && cpuStats.Total > a.prevCPU.Total {
		a.metrics.CPUPercent = calculateCPUPercent(*a.prevCPU, cpuStats)
	}
	a.prevCPU = &cpuStats

	// Section 1: RAM — /proc/meminfo
	a.metrics.RAMTotalMB, a.metrics.RAMUsedMB, a.metrics.RAMFreeMB, a.metrics.RAMPercent = parseMemInfo(sections[1])

	// Section 2: Disk — df -h /
	a.metrics.DiskTotal, a.metrics.DiskUsed, a.metrics.DiskAvail, a.metrics.DiskPercent = parseDisk(strings.TrimSpace(sections[2]))

	// Section 3: Network — /proc/net/dev
	rxBytes, txBytes := parseNetDev(sections[3])
	now := time.Now()
	if a.prevNet != nil {
		elapsed := now.Sub(a.prevNet.Time).Seconds()
		if elapsed > 0 {
			// Tính rate, xử lý counter wrap
			if rxBytes >= a.prevNet.RXBytes {
				a.metrics.NetRXRate = float64(rxBytes-a.prevNet.RXBytes) / elapsed
			} else {
				a.metrics.NetRXRate = 0
			}
			if txBytes >= a.prevNet.TXBytes {
				a.metrics.NetTXRate = float64(txBytes-a.prevNet.TXBytes) / elapsed
			} else {
				a.metrics.NetTXRate = 0
			}
		}
	}
	a.prevNet = &NetStats{RXBytes: rxBytes, TXBytes: txBytes, Time: now}

	// Section 4: Uptime — /proc/uptime
	a.metrics.Uptime = parseUptime(strings.TrimSpace(sections[4]))

	// Section 5: CPU Cores — nproc
	if len(sections) > 5 {
		cores, err := strconv.Atoi(strings.TrimSpace(sections[5]))
		if err == nil && cores > 0 {
			a.metrics.CPUCores = cores
		}
	}

	// Section 6: Disk I/O — /proc/diskstats
	if len(sections) > 6 {
		readSectors, writeSectors := parseDiskStats(sections[6])
		ioNow := time.Now()
		if a.prevIO != nil {
			ioElapsed := ioNow.Sub(a.prevIO.Time).Seconds()
			if ioElapsed > 0 {
				if readSectors >= a.prevIO.ReadSectors {
					a.metrics.IOReadRate = float64(readSectors-a.prevIO.ReadSectors) * 512 / ioElapsed
				} else {
					a.metrics.IOReadRate = 0
				}
				if writeSectors >= a.prevIO.WriteSectors {
					a.metrics.IOWriteRate = float64(writeSectors-a.prevIO.WriteSectors) * 512 / ioElapsed
				} else {
					a.metrics.IOWriteRate = 0
				}
			}
		}
		a.prevIO = &IOStats{ReadSectors: readSectors, WriteSectors: writeSectors, Time: ioNow}
	}

	// Section 7: Hệ điều hành — PRETTY_NAME từ /etc/os-release
	if len(sections) > 7 {
		if osName := parseOSName(sections[7]); osName != "" {
			a.metrics.OS = osName
		}
	}

	// Section 8: Kernel — /proc/sys/kernel/osrelease
	if len(sections) > 8 {
		if kernel := strings.TrimSpace(sections[8]); kernel != "" {
			a.metrics.Kernel = kernel
		}
	}

	// Section 9: CPU Model — "model name" / "Hardware" từ /proc/cpuinfo
	if len(sections) > 9 {
		if model := parseCPUInfoValue(sections[9]); model != "" {
			a.metrics.CPUModel = model
		}
	}

	a.metrics.Status = "online"
	a.metrics.Error = ""
	a.metrics.UpdatedAt = time.Now().Unix()
}

// parseCPULine — Parse dòng "cpu ..." từ /proc/stat
func parseCPULine(line string) CPUStats {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return CPUStats{}
	}

	// Bỏ label "cpu"
	values := fields[1:]
	var s CPUStats
	if len(values) > 0 {
		s.User, _ = strconv.ParseUint(values[0], 10, 64)
	}
	if len(values) > 1 {
		s.Nice, _ = strconv.ParseUint(values[1], 10, 64)
	}
	if len(values) > 2 {
		s.System, _ = strconv.ParseUint(values[2], 10, 64)
	}
	if len(values) > 3 {
		s.Idle, _ = strconv.ParseUint(values[3], 10, 64)
	}
	if len(values) > 4 {
		s.IOWait, _ = strconv.ParseUint(values[4], 10, 64)
	}
	if len(values) > 5 {
		s.IRQ, _ = strconv.ParseUint(values[5], 10, 64)
	}
	if len(values) > 6 {
		s.SoftIRQ, _ = strconv.ParseUint(values[6], 10, 64)
	}
	if len(values) > 7 {
		s.Steal, _ = strconv.ParseUint(values[7], 10, 64)
	}

	s.Total = s.User + s.Nice + s.System + s.Idle + s.IOWait + s.IRQ + s.SoftIRQ + s.Steal
	return s
}

// calculateCPUPercent — Tính % CPU từ delta jiffies
func calculateCPUPercent(prev, curr CPUStats) float64 {
	totalDelta := curr.Total - prev.Total
	if totalDelta == 0 {
		return 0
	}
	idleDelta := (curr.Idle + curr.IOWait) - (prev.Idle + prev.IOWait)
	pct := (1.0 - float64(idleDelta)/float64(totalDelta)) * 100
	return math.Round(pct*10) / 10 // Làm tròn 1 chữ số thập phân
}

// parseMemInfo — Parse /proc/meminfo → total, used, available, percent
func parseMemInfo(output string) (totalMB, usedMB, availMB uint64, percent float64) {
	values := make(map[string]uint64)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.TrimSpace(parts[1])
		valStr = strings.TrimSuffix(valStr, " kB")
		valStr = strings.TrimSpace(valStr)
		val, _ := strconv.ParseUint(valStr, 10, 64)
		values[key] = val
	}

	total := values["MemTotal"]
	available := values["MemAvailable"]
	if available == 0 {
		// Fallback cho kernel cũ
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}

	totalMB = total / 1024
	availMB = available / 1024
	used := total - available
	usedMB = used / 1024

	if total > 0 {
		percent = math.Round(float64(used)/float64(total)*1000) / 10
	}
	return
}

// parseDisk — Parse output df -h / → total, used, avail, percent
func parseDisk(output string) (total, used, avail string, percent float64) {
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return "N/A", "N/A", "N/A", 0
	}

	// df -h: Filesystem Size Used Avail Use% Mounted
	// Tìm field chứa % và suy ngược ra size/used/avail
	for i, f := range fields {
		if strings.HasSuffix(f, "%") {
			pctStr := strings.TrimSuffix(f, "%")
			percent, _ = strconv.ParseFloat(pctStr, 64)
			if i >= 4 {
				total = fields[i-3]
				used = fields[i-2]
				avail = fields[i-1]
			} else if i >= 3 {
				total = fields[i-2]
				used = fields[i-1]
			}
			return
		}
	}
	return "N/A", "N/A", "N/A", 0
}

// parseNetDev — Parse /proc/net/dev → tổng RX/TX bytes (trừ loopback)
func parseNetDev(output string) (rxBytes, txBytes uint64) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") {
			continue
		}
		// Bỏ header "Inter-|..." và "face |..."
		if strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue // Bỏ loopback
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}

		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		rxBytes += rx
		txBytes += tx
	}
	return
}

// parseDiskStats — Parse /proc/diskstats → tổng read/write sectors (chỉ lấy disk chính)
func parseDiskStats(output string) (readSectors, writeSectors uint64) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 14 {
			continue
		}
		devName := fields[2]
		// Chỉ lấy disk chính: sda, vda, nvme0n1, xvda (bỏ partition như sda1, vda1...)
		if devName == "sda" || devName == "vda" || devName == "xvda" || devName == "nvme0n1" {
			rs, _ := strconv.ParseUint(fields[5], 10, 64) // sectors read
			ws, _ := strconv.ParseUint(fields[9], 10, 64) // sectors written
			readSectors += rs
			writeSectors += ws
		}
	}
	// Fallback: nếu không tìm thấy disk chính, lấy tất cả (trừ loop/ram)
	if readSectors == 0 && writeSectors == 0 {
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 14 {
				continue
			}
			devName := fields[2]
			if strings.HasPrefix(devName, "loop") || strings.HasPrefix(devName, "ram") {
				continue
			}
			// Lấy disk không có số ở cuối (là disk chính, không phải partition)
			lastChar := devName[len(devName)-1]
			if lastChar >= '0' && lastChar <= '9' {
				// Có thể là partition, bỏ qua
				continue
			}
			rs, _ := strconv.ParseUint(fields[5], 10, 64)
			ws, _ := strconv.ParseUint(fields[9], 10, 64)
			readSectors += rs
			writeSectors += ws
		}
	}
	return
}

// parseOSName — Parse tên hệ điều hành từ PRETTY_NAME="..." của /etc/os-release
func parseOSName(output string) string {
	s := strings.TrimSpace(output)
	if s == "" || s == "Unknown" {
		return ""
	}
	// Dạng PRETTY_NAME="Ubuntu 22.04 LTS"
	if idx := strings.Index(s, "="); idx >= 0 {
		s = strings.TrimSpace(s[idx+1:])
	}
	s = strings.Trim(s, `"`)
	return s
}

// parseCPUInfoValue — Parse giá trị sau dấu ':' từ 1 dòng /proc/cpuinfo
// ví dụ: "model name	: Intel(R) Xeon(R) CPU" → "Intel(R) Xeon(R) CPU"
func parseCPUInfoValue(output string) string {
	s := strings.TrimSpace(output)
	if idx := strings.Index(s, ":"); idx >= 0 {
		s = strings.TrimSpace(s[idx+1:])
	}
	return s
}

// parseUptime — Parse /proc/uptime → chuỗi human-readable
func parseUptime(output string) string {
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return "N/A"
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "N/A"
	}

	totalSec := int(seconds)
	days := totalSec / 86400
	hours := (totalSec % 86400) / 3600
	minutes := (totalSec % 3600) / 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// ========================== WebSocket Hub ==========================
// Single goroutine quản lý tất cả WebSocket clients — không cần mutex

type WebSocketHub struct {
	clients    map[*websocket.Conn]bool
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	broadcast  chan []byte
}

func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:    make(map[*websocket.Conn]bool),
		register:   make(chan *websocket.Conn, 16),
		unregister: make(chan *websocket.Conn, 16),
		broadcast:  make(chan []byte, 64),
	}
}

// Run — Vòng lặp xử lý events (chạy trong 1 goroutine duy nhất)
func (h *WebSocketHub) Run() {
	pingTicker := time.NewTicker(WSPingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case conn := <-h.register:
			h.clients[conn] = true
			log.Printf("[WS] Client connected (%d total)", len(h.clients))

		case conn := <-h.unregister:
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
				log.Printf("[WS] Client disconnected (%d remaining)", len(h.clients))
			}

		case message := <-h.broadcast:
			var failed []*websocket.Conn
			for conn := range h.clients {
				conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
				if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
					failed = append(failed, conn)
				}
			}
			for _, conn := range failed {
				delete(h.clients, conn)
				conn.Close()
			}

		case <-pingTicker.C:
			var failed []*websocket.Conn
			for conn := range h.clients {
				conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					failed = append(failed, conn)
				}
			}
			for _, conn := range failed {
				delete(h.clients, conn)
				conn.Close()
			}
		}
	}
}

// ========================== Application ==========================

type App struct {
	configPath string
	config     ConfigFile
	configMu   sync.RWMutex
	agents     map[string]*MonitorAgent
	agentsMu   sync.RWMutex
	hub        *WebSocketHub
	stopCh     chan struct{}
	syncMgr    *SyncManager
}

func NewApp(configPath string) *App {
	return &App{
		configPath: configPath,
		agents:     make(map[string]*MonitorAgent),
		hub:        NewWebSocketHub(),
		stopCh:     make(chan struct{}),
		syncMgr:    NewSyncManager(),
	}
}

// ========================== Config Management ==========================

// LoadConfig — Đọc servers.json
func (app *App) LoadConfig() error {
	app.configMu.Lock()
	defer app.configMu.Unlock()

	data, err := os.ReadFile(app.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Tạo file rỗng mặc định
			app.config = ConfigFile{Servers: []ServerConfig{}}
			return app.saveConfigLocked()
		}
		return fmt.Errorf("read config: %w", err)
	}

	if err := json.Unmarshal(data, &app.config); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	// Đảm bảo mỗi server có ID
	for i := range app.config.Servers {
		if app.config.Servers[i].ID == "" {
			app.config.Servers[i].ID = app.nextServerIDLocked()
		}
		if app.config.Servers[i].Port == 0 {
			app.config.Servers[i].Port = 22
		}
	}

	// Đảm bảo danh sách Groups có dữ liệu
	if len(app.config.Groups) == 0 {
		groupSet := make(map[string]bool)
		for _, s := range app.config.Servers {
			if s.Group != "" {
				groupSet[s.Group] = true
			}
		}
		for g := range groupSet {
			app.config.Groups = append(app.config.Groups, g)
		}
		if len(app.config.Groups) == 0 {
			app.config.Groups = []string{"Default"}
		}
	}
	return nil
}

// SaveConfig — Ghi servers.json (thread-safe)
func (app *App) SaveConfig() error {
	app.configMu.Lock()
	defer app.configMu.Unlock()
	return app.saveConfigLocked()
}

// saveConfigLocked — Ghi file (caller phải giữ configMu)
func (app *App) saveConfigLocked() error {
	data, err := json.MarshalIndent(app.config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(app.configPath, data, 0644)
}

// ========================== Agent Lifecycle ==========================

// StartAllAgents — Khởi động agent cho tất cả servers trong config
func (app *App) StartAllAgents() {
	app.configMu.RLock()
	servers := make([]ServerConfig, len(app.config.Servers))
	copy(servers, app.config.Servers)
	app.configMu.RUnlock()

	for _, cfg := range servers {
		app.startAgent(cfg)
	}
}

func (app *App) startAgent(cfg ServerConfig) {
	app.agentsMu.Lock()
	defer app.agentsMu.Unlock()

	// Dừng agent cũ nếu tồn tại
	if old, exists := app.agents[cfg.ID]; exists {
		old.Stop()
	}

	agent := NewMonitorAgent(cfg, app.findProxy(cfg.ProxyID))
	app.agents[cfg.ID] = agent
	go agent.Run()
	log.Printf("[Agent] Started monitoring %s (%s:%d)", cfg.Label, cfg.Host, cfg.Port)
}

func (app *App) stopAgent(id string) {
	app.agentsMu.Lock()
	defer app.agentsMu.Unlock()

	if agent, exists := app.agents[id]; exists {
		agent.Stop()
		delete(app.agents, id)
		log.Printf("[Agent] Stopped monitoring %s", id)
	}
}

// StopAllAgents — Dừng toàn bộ agents
func (app *App) StopAllAgents() {
	app.agentsMu.Lock()
	defer app.agentsMu.Unlock()

	for id, agent := range app.agents {
		agent.Stop()
		delete(app.agents, id)
	}
	log.Println("[Agent] All agents stopped")
}

// GetAllMetrics — Thu thập metrics từ tất cả agents theo đúng thứ tự cố định trong config
func (app *App) GetAllMetrics() []ServerMetrics {
	app.configMu.RLock()
	orderedIDs := make([]string, len(app.config.Servers))
	for i, s := range app.config.Servers {
		orderedIDs[i] = s.ID
	}
	app.configMu.RUnlock()

	app.agentsMu.RLock()
	defer app.agentsMu.RUnlock()

	metrics := make([]ServerMetrics, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		if agent, exists := app.agents[id]; exists {
			metrics = append(metrics, agent.GetMetrics())
		}
	}
	return metrics
}

// ========================== Broadcast Loop ==========================

// BroadcastLoop — Định kỳ đẩy metrics qua WebSocket
func (app *App) BroadcastLoop() {
	ticker := time.NewTicker(BroadcastInterval)
	defer ticker.Stop()

	for {
		select {
		case <-app.stopCh:
			return
		case <-ticker.C:
			metrics := app.GetAllMetrics()
			msg := map[string]interface{}{
				"type": "metrics",
				"data": metrics,
			}
			data, err := json.Marshal(msg)
			if err != nil {
				log.Printf("[Broadcast] Marshal error: %v", err)
				continue
			}
			app.hub.broadcast <- data
		}
	}
}

// ========================== HTTP Handlers ==========================

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // Cho phép mọi origin (local tool)
	},
}

// handleWebSocket — Upgrade HTTP → WebSocket
func (app *App) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Upgrade error: %v", err)
		return
	}

	// Gửi dữ liệu ban đầu TRƯỚC khi register (tránh race condition)
	metrics := app.GetAllMetrics()
	initMsg, _ := json.Marshal(map[string]interface{}{
		"type": "metrics",
		"data": metrics,
	})
	conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
	conn.WriteMessage(websocket.TextMessage, initMsg)

	// Đăng ký vào hub để nhận broadcast
	app.hub.register <- conn

	// Read loop — phát hiện client disconnect
	go func() {
		defer func() {
			app.hub.unregister <- conn
		}()
		conn.SetReadLimit(512)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

// handleGetServers — GET /api/servers
func (app *App) handleGetServers(w http.ResponseWriter, r *http.Request) {
	app.configMu.RLock()
	defer app.configMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	json.NewEncoder(w).Encode(app.config)
}

// fetchRemoteHostname — Kết nối SSH tạm (qua proxy nếu có), chạy lệnh hostname.
// Trả về chuỗi rỗng nếu thất bại (caller tự fallback).
func fetchRemoteHostname(cfg ServerConfig, proxy *ProxyConfig) string {
	agent := NewMonitorAgent(cfg, proxy)
	sshConfig, err := agent.buildSSHConfig()
	if err != nil {
		return ""
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	conn, err := dialThroughProxy(addr, proxy, SSHDialTimeout)
	if err != nil {
		log.Printf("[%s] Hostname probe dial failed: %v", cfg.Host, err)
		return ""
	}
	conn.SetDeadline(time.Now().Add(SSHDialTimeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		log.Printf("[%s] Hostname probe handshake failed: %v", cfg.Host, err)
		return ""
	}
	conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return ""
	}
	defer session.Close()

	out, err := session.Output("hostname")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// handleAddServer — POST /api/servers
func (app *App) handleAddServer(w http.ResponseWriter, r *http.Request) {
	var cfg ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validation
	if cfg.Host == "" {
		httpError(w, "Host is required", http.StatusBadRequest)
		return
	}

	// Gán giá trị mặc định
	cfg.ID = app.generateServerID()
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Group == "" {
		cfg.Group = "Default"
	}
	if cfg.Label == "" {
		// Không nhập label → lấy hostname thật của VPS qua SSH, fail thì dùng IP
		if hn := fetchRemoteHostname(cfg, app.findProxy(cfg.ProxyID)); hn != "" {
			cfg.Label = hn
		} else {
			cfg.Label = cfg.Host
		}
	}

	// Lưu vào config
	app.configMu.Lock()
	app.config.Servers = append(app.config.Servers, cfg)
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Khởi động agent cho server mới
	app.startAgent(cfg)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cfg)
}

// handleUpdateServer — PUT /api/servers/{id}
func (app *App) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := extractPathID(r.URL.Path, "/api/servers/")
	if id == "" {
		httpError(w, "Server ID is required", http.StatusBadRequest)
		return
	}
	if id == "reorder" {
		app.handleReorderServers(w, r)
		return
	}

	var cfg ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	cfg.ID = id
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Label == "" {
		// Không nhập label → lấy hostname thật của VPS qua SSH, fail thì dùng IP
		if hn := fetchRemoteHostname(cfg, app.findProxy(cfg.ProxyID)); hn != "" {
			cfg.Label = hn
		} else {
			cfg.Label = cfg.Host
		}
	}

	// Cập nhật config
	app.configMu.Lock()
	found := false
	for i, s := range app.config.Servers {
		if s.ID == id {
			app.config.Servers[i] = cfg
			found = true
			break
		}
	}
	if !found {
		app.configMu.Unlock()
		httpError(w, "Server not found", http.StatusNotFound)
		return
	}
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Restart agent với config mới
	app.stopAgent(id)
	app.startAgent(cfg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// handleDeleteServer — DELETE /api/servers/{id}
func (app *App) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := extractPathID(r.URL.Path, "/api/servers/")
	if id == "" {
		httpError(w, "Server ID is required", http.StatusBadRequest)
		return
	}

	// Xóa khỏi config
	app.configMu.Lock()
	found := false
	for i, s := range app.config.Servers {
		if s.ID == id {
			app.config.Servers = append(app.config.Servers[:i], app.config.Servers[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		app.configMu.Unlock()
		httpError(w, "Server not found", http.StatusNotFound)
		return
	}
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Dừng agent
	app.stopAgent(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleReorderServers — PUT /api/servers/reorder (Sắp xếp thứ tự server)
func (app *App) handleReorderServers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrderedIDs []string `json:"ordered_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.OrderedIDs) == 0 {
		httpError(w, "Danh sách ordered_ids không hợp lệ", http.StatusBadRequest)
		return
	}

	app.configMu.Lock()
	serverMap := make(map[string]ServerConfig)
	for _, s := range app.config.Servers {
		serverMap[s.ID] = s
	}

	var newServers []ServerConfig
	seen := make(map[string]bool)
	for _, id := range req.OrderedIDs {
		if s, ok := serverMap[id]; ok {
			newServers = append(newServers, s)
			seen[id] = true
		}
	}
	for _, s := range app.config.Servers {
		if !seen[s.ID] {
			newServers = append(newServers, s)
		}
	}

	app.config.Servers = newServers
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Lưu thứ tự thất bại: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ========================== Group Handlers ==========================

// handleGetGroups — GET /api/groups
func (app *App) handleGetGroups(w http.ResponseWriter, r *http.Request) {
	app.configMu.RLock()
	defer app.configMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	json.NewEncoder(w).Encode(map[string]interface{}{"groups": app.config.Groups})
}

// handleAddGroup — POST /api/groups
func (app *App) handleAddGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		httpError(w, "Tên cụm không được để trống", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)

	app.configMu.Lock()
	for _, g := range app.config.Groups {
		if strings.EqualFold(g, name) {
			app.configMu.Unlock()
			httpError(w, "Cụm này đã tồn tại", http.StatusConflict)
			return
		}
	}
	app.config.Groups = append(app.config.Groups, name)
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Lưu thất bại: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"name": name})
}

// handleUpdateGroup — PUT /api/groups/{name}
func (app *App) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	oldName := extractPathID(r.URL.Path, "/api/groups/")
	oldName = strings.TrimSpace(oldName)
	if oldName == "" {
		httpError(w, "Tên cụm cần sửa là bắt buộc", http.StatusBadRequest)
		return
	}
	if oldName == "reorder" {
		app.handleReorderGroups(w, r)
		return
	}

	var req struct {
		NewName string `json:"new_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.NewName) == "" {
		httpError(w, "Tên cụm mới không được để trống", http.StatusBadRequest)
		return
	}
	newName := strings.TrimSpace(req.NewName)

	app.configMu.Lock()
	found := false
	for i, g := range app.config.Groups {
		if g == oldName {
			app.config.Groups[i] = newName
			found = true
			break
		}
	}
	if !found {
		app.configMu.Unlock()
		httpError(w, "Không tìm thấy cụm máy chủ", http.StatusNotFound)
		return
	}

	// Cập nhật các server thuộc cụm này
	for i := range app.config.Servers {
		if app.config.Servers[i].Group == oldName {
			app.config.Servers[i].Group = newName
		}
	}

	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Lưu thất bại: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Cập nhật active agents
	app.agentsMu.Lock()
	for _, ag := range app.agents {
		ag.mu.Lock()
		if ag.config.Group == oldName {
			ag.config.Group = newName
			ag.metrics.Group = newName
		}
		ag.mu.Unlock()
	}
	app.agentsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"old_name": oldName, "new_name": newName})
}

// handleDeleteGroup — DELETE /api/groups/{name}
func (app *App) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := extractPathID(r.URL.Path, "/api/groups/")
	name = strings.TrimSpace(name)
	if name == "" {
		httpError(w, "Tên cụm cần xóa là bắt buộc", http.StatusBadRequest)
		return
	}

	app.configMu.Lock()
	found := false
	for i, g := range app.config.Groups {
		if g == name {
			app.config.Groups = append(app.config.Groups[:i], app.config.Groups[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		app.configMu.Unlock()
		httpError(w, "Không tìm thấy cụm máy chủ", http.StatusNotFound)
		return
	}

	// Chuyển các server thuộc cụm này về "Default"
	for i := range app.config.Servers {
		if app.config.Servers[i].Group == name {
			app.config.Servers[i].Group = "Default"
		}
	}

	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Lưu thất bại: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Cập nhật active agents
	app.agentsMu.Lock()
	for _, ag := range app.agents {
		ag.mu.Lock()
		if ag.config.Group == name {
			ag.config.Group = "Default"
			ag.metrics.Group = "Default"
		}
		ag.mu.Unlock()
	}
	app.agentsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleReorderGroups — PUT /api/groups/reorder (Sắp xếp thứ tự group)
func (app *App) handleReorderGroups(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrderedGroups []string `json:"ordered_groups"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.OrderedGroups) == 0 {
		httpError(w, "Danh sách ordered_groups không hợp lệ", http.StatusBadRequest)
		return
	}

	app.configMu.Lock()
	groupSet := make(map[string]bool)
	for _, g := range app.config.Groups {
		groupSet[g] = true
	}

	var newGroups []string
	seen := make(map[string]bool)
	for _, g := range req.OrderedGroups {
		if groupSet[g] && !seen[g] {
			newGroups = append(newGroups, g)
			seen[g] = true
		}
	}
	for _, g := range app.config.Groups {
		if !seen[g] {
			newGroups = append(newGroups, g)
		}
	}

	app.config.Groups = newGroups
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Lưu thứ tự thất bại: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ========================== HTTP Router ==========================

func (app *App) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Groups API
	mux.HandleFunc("/api/groups/reorder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			app.handleReorderGroups(w, r)
			return
		}
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/groups/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			app.handleUpdateGroup(w, r)
		case http.MethodDelete:
			app.handleDeleteGroup(w, r)
		default:
			httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.handleGetGroups(w, r)
		case http.MethodPost:
			app.handleAddGroup(w, r)
		default:
			httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Server API routes
	mux.HandleFunc("/api/servers/reorder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			app.handleReorderServers(w, r)
			return
		}
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/servers/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			app.handleUpdateServer(w, r)
		case http.MethodDelete:
			app.handleDeleteServer(w, r)
		default:
			httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/servers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.handleGetServers(w, r)
		case http.MethodPost:
			app.handleAddServer(w, r)
		default:
			httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Proxy API
	mux.HandleFunc("/api/proxies/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			app.handleTestProxy(w, r)
			return
		}
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/proxies/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			app.handleUpdateProxy(w, r)
		case http.MethodDelete:
			app.handleDeleteProxy(w, r)
		default:
			httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/proxies", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			app.handleGetProxies(w, r)
		case http.MethodPost:
			app.handleAddProxy(w, r)
		default:
			httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// File Sync API
	mux.HandleFunc("/api/fs/list", app.handleFSList)
	mux.HandleFunc("/api/sync/inspect", app.handleSyncInspect)
	mux.HandleFunc("/api/sync/start", app.handleSyncStart)
	mux.HandleFunc("/api/sync/cancel", app.handleSyncCancel)
	mux.HandleFunc("/api/sync/jobs/", app.handleSyncJobStatus)

	// Settings API (read-only — đường dẫn file cố định cạnh exe)
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			app.handleGetSettings(w, r)
			return
		}
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// Version & kiểm tra cập nhật
	mux.HandleFunc("/api/version", app.handleVersion)
	mux.HandleFunc("/api/update/check", app.handleUpdateCheck)

	// WebSocket
	mux.HandleFunc("/ws", app.handleWebSocket)
	mux.HandleFunc("/ws/terminal/", app.handleTerminalWS)

	// Static files: Serve from local disk if available (Dev Mode), else Embedded FS (Prod)
	var fileServer http.Handler
	if _, err := os.Stat("static/index.html"); err == nil {
		log.Println("Serving static files from local disk (Dev Mode)")
		fileServer = http.FileServer(http.Dir("static"))
	} else {
		log.Println("Serving static files from embedded FS (Prod Mode)")
		sub, err := fs.Sub(staticFiles, "static")
		if err != nil {
			log.Fatal("Failed to setup embedded static files:", err)
		}
		fileServer = http.FileServer(http.FS(sub))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		fileServer.ServeHTTP(w, r)
	})

	return mux
}

// ========================== Utility Functions ==========================

// generateServerID — Tạo ID dạng số tự động tăng
func (app *App) generateServerID() string {
	app.configMu.Lock()
	defer app.configMu.Unlock()
	return app.nextServerIDLocked()
}

// nextServerIDLocked — Tạo ID (caller phải giữ configMu; không ghi file, caller sẽ save)
func (app *App) nextServerIDLocked() string {
	if app.config.NextServerID == 0 {
		maxID := 0
		for _, s := range app.config.Servers {
			if id, err := strconv.Atoi(s.ID); err == nil && id > maxID {
				maxID = id
			}
		}
		app.config.NextServerID = maxID
	}
	app.config.NextServerID++
	return strconv.Itoa(app.config.NextServerID)
}

// expandPath — Mở rộng ~/... thành home directory
func expandPath(path string) string {
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

// extractPathID — Lấy ID từ URL path (ví dụ: /api/servers/abc → abc)
func extractPathID(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return strings.TrimPrefix(path, prefix)
}

// ========================== Settings API ==========================

// handleGetSettings — GET /api/settings
func (app *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"config_path": app.configPath,
	})
}

// httpError — Ghi lỗi HTTP JSON
func httpError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// getBaseDir — Xác định thư mục gốc (cạnh exe hoặc cwd cho go run)
func getBaseDir() string {
	exe, err := os.Executable()
	if err == nil && !strings.Contains(filepath.ToSlash(exe), "go-build") {
		return filepath.Dir(exe)
	}
	dir, _ := os.Getwd()
	return dir
}

// getConfigPath — Đường dẫn servers.json (cố định cạnh file exe)
func getConfigPath() string {
	return filepath.Join(getBaseDir(), ConfigFileName)
}

// ensureConfigFileExists — Tạo file servers.json rỗng nếu chưa tồn tại
func ensureConfigFileExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		emptyConfig := ConfigFile{
			Groups:       []string{},
			Servers:      []ServerConfig{},
			NextServerID: 1,
		}
		data, _ := json.MarshalIndent(emptyConfig, "", "  ")
		// Tạo thư mục cha nếu cần
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("cannot create directory %s: %w", dir, err)
		}
		return os.WriteFile(path, data, 0644)
	}
	return nil
}

// ========================== Main ==========================

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	configPath := getConfigPath()
	// Đảm bảo file servers.json tồn tại
	if err := ensureConfigFileExists(configPath); err != nil {
		log.Printf("Cannot create config file: %v", err)
	}
	app := NewApp(configPath)

	// Load cấu hình server
	if err := app.LoadConfig(); err != nil {
		log.Printf("Config warning: %v (starting with empty config)", err)
	}
	log.Printf("Loaded %d servers from %s", len(app.config.Servers), configPath)

	// Khởi động WebSocket hub
	go app.hub.Run()

	// Khởi động broadcast loop
	go app.BroadcastLoop()

	// Khởi động monitoring agents
	app.StartAllAgents()

	// Setup HTTP server
	handler := app.SetupRoutes()
	server := &http.Server{
		Addr:         ServerPort,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("\nReceived signal %v, shutting down...", sig)

		close(app.stopCh)
		app.StopAllAgents()
		server.Close()
	}()

	// Start server
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Printf("║  %-48s║\n", "SSH Monitor — VPS Dashboard")
	fmt.Printf("║  %-48s║\n", "URL: http://localhost"+ServerPort)
	fmt.Printf("║  %-48s║\n", "Config: "+filepath.Base(configPath))
	fmt.Printf("║  %-48s║\n", fmt.Sprintf("Monitoring: %d servers", len(app.config.Servers)))
	fmt.Printf("║  %-48s║\n", "Press Ctrl+C to stop")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()

	// Tự động mở trình duyệt
	go func() {
		time.Sleep(1 * time.Second)
		url := "http://localhost" + ServerPort
		var err error
		switch runtime.GOOS {
		case "linux":
			err = exec.Command("xdg-open", url).Start()
		case "windows":
			err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		case "darwin":
			err = exec.Command("open", url).Start()
		default:
			err = fmt.Errorf("unsupported platform")
		}
		if err != nil {
			log.Printf("Could not open browser automatically: %v", err)
		} else {
			log.Printf("Opened browser at %s", url)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}

	log.Println("Server stopped gracefully")
}
