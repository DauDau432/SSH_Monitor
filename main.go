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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

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
	ServerPort        = ":8888"
	ConfigFileName    = "servers.json"
)

// Script gộp — lấy toàn bộ metrics trong 1 lần gọi. Chạy bằng /bin/sh (shCmd) nên
// không phụ thuộc shell đăng nhập (zsh trên TrueNAS, fish...). Chỉ dùng lệnh có cả
// trong GNU coreutils lẫn BusyBox để chạy được trên mọi distro Linux và NAS
// (Synology DSM, QNAP QTS, Unraid, TrueNAS SCALE, OpenMediaVault...).
// Phần khó (chọn ổ, card mạng, tên OS) để Go parse thay vì xử lý bằng shell.
// "exit 0" ở cuối: lệnh cuối không tìm thấy gì cũng không làm hỏng cả lần lấy.
const metricsScript = `export LC_ALL=C
D='---DELIM---'
head -1 /proc/stat
echo "$D"
grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SReclaimable):' /proc/meminfo
echo "$D"
if df -Pkl / >/dev/null 2>&1; then df -Pkl; else df -Pk; fi 2>/dev/null
echo "$D"
cat /proc/net/dev
echo "$D"
cat /proc/uptime
echo "$D"
nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || grep -c '^processor' /proc/cpuinfo
echo "$D"
cat /proc/diskstats
echo "$D"
for f in /etc.defaults/VERSION /etc/unraid-version /etc/os-release /usr/lib/os-release /etc/lsb-release /etc/redhat-release; do
  [ -r "$f" ] && { echo "@@$f"; cat "$f"; echo; }
done
[ -f /etc/config/uLinux.conf ] && { echo "@@qnap"; getcfg System Version; getcfg System 'Build Number'; } 2>/dev/null
[ -x /usr/bin/midclt ] && [ -r /etc/version ] && { echo "@@truenas"; cat /etc/version; echo; }
[ -d /etc/openmediavault ] && { echo "@@omv"; dpkg-query -W -f='${Version}\n' openmediavault; } 2>/dev/null
echo "$D"
cat /proc/sys/kernel/osrelease 2>/dev/null || uname -r
echo "$D"
grep -E '^(model name|cpu model|Processor|Hardware|Model)[[:space:]]*:' /proc/cpuinfo 2>/dev/null
echo "@@lscpu"
lscpu 2>/dev/null | grep '^Model name:'
echo "@@dt"
cat /proc/device-tree/model 2>/dev/null
echo
echo "$D"
for i in /sys/class/net/*; do [ -e "$i/device" ] && echo "${i##*/}"; done
echo "$D"
for b in /sys/block/*; do [ -e "$b/device" ] && echo "${b##*/}"; done
echo "$D"
cat /proc/mounts
exit 0`

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
	DiskAvail   string  `json:"disk_avail"` // Dung lượng trống (tổng các ổ lưu trữ thật, theo df)
	DiskPercent float64 `json:"disk_percent"`
	NetTXRate   float64 `json:"net_tx_rate"`   // bytes/s
	NetRXRate   float64 `json:"net_rx_rate"`   // bytes/s
	IOReadRate  float64 `json:"io_read_rate"`  // bytes/s
	IOWriteRate float64 `json:"io_write_rate"` // bytes/s
	Uptime      string  `json:"uptime"`
	CPUCores    int     `json:"cpu_cores"`
	CPUModel    string  `json:"cpu_model"` // Loại CPU (/proc/cpuinfo, lscpu hoặc device-tree)
	OS          string  `json:"os"`        // Hệ điều hành (file version của NAS hoặc os-release)
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

	addr := hostPort(a.config.Host, a.config.Port)

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
		// Nhiều NAS/distro chỉ bật keyboard-interactive (PAM) thay cho password
		// → điền mật khẩu vào các prompt ẩn ký tự
		pw := a.config.Password
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					if !echos[i] {
						answers[i] = pw
					}
				}
				return answers, nil
			}))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods configured (need password or key_path)")
	}

	// Bật thêm thuật toán cũ (DH-SHA1, CBC...) cho NAS/thiết bị đời cũ chạy dropbear
	// hoặc OpenSSH cũ. Thuật toán mạnh vẫn đứng trước nên máy mới không bị ảnh hưởng.
	supported, insecure := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()

	return &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: append(supported.KeyExchanges, insecure.KeyExchanges...),
			Ciphers:      append(supported.Ciphers, insecure.Ciphers...),
			MACs:         append(supported.MACs, insecure.MACs...),
		},
		User:            a.config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         SSHDialTimeout,
	}, nil
}

// collectMetrics — Chạy lệnh SSH lấy metrics, parse kết quả
func (a *MonitorAgent) collectMetrics() error {
	// Chạy với timeout — cả NewSession cũng nằm trong timeout vì nó có thể treo
	// vô hạn khi kết nối chết im lặng (vd: proxy còn sống nhưng VPS đích đã mất)
	type cmdResult struct {
		output []byte
		err    error
	}
	resultCh := make(chan cmdResult, 1)
	client := a.client

	go func() {
		session, err := client.NewSession()
		if err != nil {
			resultCh <- cmdResult{nil, fmt.Errorf("new session: %w", err)}
			return
		}
		defer session.Close()
		// Chỉ lấy stdout: stderr (vd "df: Permission denied") lẫn vào sẽ làm sai các section
		out, err := session.Output(shCmd(metricsScript))
		if err != nil {
			err = fmt.Errorf("command exec: %w", err)
		}
		resultCh <- cmdResult{out, err}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			return res.err
		}
		a.parseAllMetrics(string(res.output))
		return nil
	case <-time.After(CmdExecTimeout):
		// Caller sẽ đóng client → goroutine trên được giải phóng
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

	// Section 10-12 (nếu có): card mạng vật lý, ổ đĩa vật lý, /proc/mounts
	section := func(i int) string {
		if i < len(sections) {
			return sections[i]
		}
		return ""
	}
	physNICs := parseNameList(section(10))
	physDisks := parseNameList(section(11))

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

	// Section 2: Disk — df -Pk (mọi filesystem) + loại fs từ /proc/mounts
	a.metrics.DiskTotal, a.metrics.DiskUsed, a.metrics.DiskAvail, a.metrics.DiskPercent = parseDiskUsage(sections[2], section(12))

	// Section 3: Network — /proc/net/dev
	rxBytes, txBytes := parseNetDev(sections[3], physNICs)
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
		readSectors, writeSectors := parseDiskStats(sections[6], physDisks)
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

	// Section 7: Hệ điều hành — file version của NAS hoặc /etc/os-release
	if len(sections) > 7 {
		if osName := parseOSInfo(sections[7]); osName != "" {
			a.metrics.OS = osName
		}
	}

	// Section 8: Kernel — /proc/sys/kernel/osrelease
	if len(sections) > 8 {
		if kernel := strings.TrimSpace(sections[8]); kernel != "" {
			a.metrics.Kernel = kernel
		}
	}

	// Section 9: CPU Model — /proc/cpuinfo, lscpu hoặc device-tree (ARM)
	if len(sections) > 9 {
		if model := parseCPUModel(sections[9]); model != "" {
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
	totalDelta := float64(curr.Total) - float64(prev.Total)
	if totalDelta <= 0 {
		return 0
	}
	// Tính bằng số thực: iowait trên một số kernel có thể giảm giữa 2 lần đọc,
	// trừ uint64 sẽ tràn thành số khổng lồ
	idleDelta := float64(curr.Idle+curr.IOWait) - float64(prev.Idle+prev.IOWait)
	pct := (1.0 - idleDelta/totalDelta) * 100
	pct = math.Max(0, math.Min(100, pct))
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
		// Fallback cho kernel cũ (< 3.14, hay gặp trên NAS đời cũ) — giống cách "free" tính
		available = values["MemFree"] + values["Buffers"] + values["Cached"] + values["SReclaimable"]
	}
	if available > total {
		available = total
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

// dfRow — 1 dòng của "df -Pk" (đơn vị KB)
type dfRow struct {
	src, mount        string
	size, used, avail uint64
}

// parseDfRow — Parse 1 dòng df -P: Filesystem 1024-blocks Used Available Capacity Mounted-on.
// Tìm cột "xx%" có 3 cột số đứng trước để chịu được tên/đường dẫn chứa dấu cách.
func parseDfRow(line string) (dfRow, bool) {
	f := strings.Fields(line)
	for i := 4; i < len(f); i++ {
		if !strings.HasSuffix(f[i], "%") {
			continue
		}
		size, e1 := strconv.ParseUint(f[i-3], 10, 64)
		used, e2 := strconv.ParseUint(f[i-2], 10, 64)
		avail, e3 := strconv.ParseUint(f[i-1], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		return dfRow{
			src:   strings.Join(f[:i-3], " "),
			mount: strings.Join(f[i+1:], " "),
			size:  size,
			used:  used,
			avail: avail,
		}, true
	}
	return dfRow{}, false
}

// skipFSTypes — Filesystem không phải dung lượng lưu trữ thật: ảo, ổ mạng,
// hoặc lớp phủ lên ổ khác (ecryptfs của Synology...) — tính vào sẽ bị trùng.
// Mọi loại "fuse.*" (shfs của Unraid, mergerfs, sshfs, rclone...) cũng bị bỏ.
var skipFSTypes = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "ramfs": true, "rootfs": true, "proc": true,
	"sysfs": true, "devpts": true, "cgroup": true, "cgroup2": true, "overlay": true,
	"aufs": true, "squashfs": true, "autofs": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "pstore": true, "bpf": true, "configfs": true, "efivarfs": true,
	"hugetlbfs": true, "mqueue": true, "fusectl": true, "binfmt_misc": true, "nsfs": true,
	"iso9660": true, "udf": true, "ecryptfs": true, "fuse": true,
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "9p": true,
	"virtiofs": true, "vboxsf": true, "vmhgfs": true, "drvfs": true, "ceph": true,
	"glusterfs": true, "afs": true, "davfs": true, "sshfs": true,
}

// isStorageMount — Mount này có phải dung lượng lưu trữ thật cần cộng vào không
func isStorageMount(r dfRow, fsType string) bool {
	if r.size == 0 || strings.HasPrefix(r.src, "/dev/loop") {
		return false // loop: snap, docker.img của Unraid... nằm sẵn trên ổ khác
	}
	if r.mount == "/boot" || strings.HasPrefix(r.mount, "/boot/") || r.mount == "/efi" {
		return false // phân vùng boot/EFI, USB flash của Unraid
	}
	if fsType == "" {
		return strings.HasPrefix(r.src, "/dev/")
	}
	return !skipFSTypes[fsType] && !strings.HasPrefix(fsType, "fuse.")
}

// unescapeMount — Giải mã \040 (dấu cách), \011... trong đường dẫn ở /proc/mounts
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if c, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(c))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseDiskUsage — Tổng dung lượng các ổ lưu trữ thật từ "df -Pk" + /proc/mounts.
// Cộng mọi ổ (NAS có /volume1, /share/..., /mnt/disk1... chứ không chỉ "/"),
// bỏ trùng theo thiết bị (bind mount, btrfs subvolume); ZFS gộp theo pool vì
// các dataset dùng chung dung lượng trống. Không có ổ nào hợp lệ → dùng "/".
func parseDiskUsage(dfOut, mountsOut string) (total, used, avail string, percent float64) {
	fsTypes := make(map[string]string)
	for _, line := range strings.Split(mountsOut, "\n") {
		if f := strings.Fields(line); len(f) >= 3 {
			fsTypes[unescapeMount(f[1])] = f[2]
		}
	}

	var sumSize, sumUsed, sumAvail uint64
	var root *dfRow
	seen := make(map[string]bool)
	zfsUsed := make(map[string]uint64)
	zfsAvail := make(map[string]uint64)

	for _, line := range strings.Split(dfOut, "\n") {
		r, ok := parseDfRow(line)
		if !ok {
			continue
		}
		if r.mount == "/" {
			rr := r
			root = &rr
		}
		fsType := fsTypes[r.mount]
		if !isStorageMount(r, fsType) {
			continue
		}
		if fsType == "zfs" {
			pool, _, _ := strings.Cut(r.src, "/")
			zfsUsed[pool] += r.used
			zfsAvail[pool] = max(zfsAvail[pool], r.avail)
			continue
		}
		if seen[r.src] {
			continue
		}
		seen[r.src] = true
		sumSize += r.size
		sumUsed += r.used
		sumAvail += r.avail
	}
	for pool, u := range zfsUsed {
		sumSize += u + zfsAvail[pool]
		sumUsed += u
		sumAvail += zfsAvail[pool]
	}

	if sumSize == 0 {
		if root == nil {
			return "N/A", "N/A", "N/A", 0
		}
		sumSize, sumUsed, sumAvail = root.size, root.used, root.avail
	}
	// Cùng cách tính Use% của df: used / (used + avail), làm tròn lên
	if sumUsed+sumAvail > 0 {
		percent = math.Ceil(float64(sumUsed) * 100 / float64(sumUsed+sumAvail))
	}
	return humanKB(sumSize), humanKB(sumUsed), humanKB(sumAvail), percent
}

// humanKB — Định dạng KB giống "df -h": làm tròn lên, dưới 10 giữ 1 chữ số lẻ
func humanKB(kb uint64) string {
	if kb == 0 {
		return "0"
	}
	units := []string{"K", "M", "G", "T", "P", "E"}
	v := float64(kb)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if v < 10 {
		if v = math.Ceil(v*10) / 10; v < 10 {
			return strconv.FormatFloat(v, 'f', 1, 64) + units[i]
		}
	}
	v = math.Ceil(v)
	if v >= 1024 && i < len(units)-1 {
		return "1.0" + units[i+1]
	}
	return strconv.FormatFloat(v, 'f', 0, 64) + units[i]
}

// parseNameList — Danh sách tên (mỗi dòng 1 tên) → set
func parseNameList(output string) map[string]bool {
	set := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			set[name] = true
		}
	}
	return set
}

// parseNetDev — Parse /proc/net/dev → tổng RX/TX bytes.
// Chỉ cộng card vật lý (physical, từ /sys/class/net/*/device): bridge, bond,
// VLAN, veth của Docker... chạy chồng lên card thật, cộng vào sẽ bị đếm 2 lần
// (rất hay gặp trên NAS: br0, bond0, ovs_eth0, docker0). Không có card vật lý
// nào (container, OpenVZ venet0) → cộng tất cả trừ loopback.
func parseNetDev(output string, physical map[string]bool) (rxBytes, txBytes uint64) {
	type ifaceStats struct {
		name   string
		rx, tx uint64
	}
	var ifaces []ifaceStats
	hasPhysical := false
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
		ifaces = append(ifaces, ifaceStats{iface, rx, tx})
		if physical[iface] {
			hasPhysical = true
		}
	}
	for _, s := range ifaces {
		if hasPhysical && !physical[s.name] {
			continue
		}
		rxBytes += s.rx
		txBytes += s.tx
	}
	return
}

// diskNameRe — Tên ổ đĩa nguyên (không phải phân vùng), dùng khi không đọc được /sys/block
var diskNameRe = regexp.MustCompile(`^(sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|sata[0-9]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)$`)

// parseDiskStats — Parse /proc/diskstats → tổng read/write sectors của mọi ổ vật lý.
// physical lấy từ /sys/block/*/device: chỉ ổ thật, tự loại phân vùng, md (RAID),
// dm (LVM/cache), loop, zram — các thiết bị này chồng lên ổ thật nên sẽ đếm trùng.
func parseDiskStats(output string, physical map[string]bool) (readSectors, writeSectors uint64) {
	sum := func(match func(dev string) bool) bool {
		found := false
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 14 || !match(fields[2]) {
				continue
			}
			found = true
			rs, _ := strconv.ParseUint(fields[5], 10, 64) // sectors read
			ws, _ := strconv.ParseUint(fields[9], 10, 64) // sectors written
			readSectors += rs
			writeSectors += ws
		}
		return found
	}
	if len(physical) > 0 && sum(func(dev string) bool { return physical[dev] }) {
		return
	}
	sum(diskNameRe.MatchString)
	return
}

// splitTagged — Tách output dạng "@@tên" + nội dung thành map tên → nội dung.
// Phần trước tag đầu tiên nằm ở key "".
func splitTagged(output string) map[string]string {
	blocks := make(map[string]string)
	tag := ""
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "@@") {
			tag = strings.TrimSpace(line[2:])
			continue
		}
		blocks[tag] += line + "\n"
	}
	return blocks
}

// parseKV — Parse các dòng KEY=value / KEY="value" (os-release, VERSION của Synology...)
func parseKV(s string) map[string]string {
	kv := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return kv
}

// firstLine — Dòng không rỗng đầu tiên
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// parseOSInfo — Tên hệ điều hành. NAS thường có os-release chung chung (hoặc
// không có) nên ưu tiên file version riêng: Synology, QNAP, Unraid, TrueNAS,
// OpenMediaVault; sau đó tới os-release, lsb-release, redhat-release.
func parseOSInfo(output string) string {
	b := splitTagged(output)

	if kv := parseKV(b["/etc.defaults/VERSION"]); len(kv) > 0 {
		ver := kv["productversion"]
		if ver == "" && kv["majorversion"] != "" {
			ver = kv["majorversion"] + "." + kv["minorversion"]
		}
		s := strings.TrimSpace("Synology DSM " + ver)
		if build := kv["buildnumber"]; build != "" && ver != "" {
			s += "-" + build
		}
		return s
	}
	if lines := strings.Fields(b["qnap"]); len(lines) > 0 {
		name := "QNAP QTS "
		if strings.HasPrefix(lines[0], "h") {
			name = "QNAP QuTS hero " // QuTS hero đánh số h5.x
		}
		s := name + lines[0]
		if len(lines) > 1 {
			s += " (" + lines[1] + ")"
		}
		return s
	}
	if ver := parseKV(b["/etc/unraid-version"])["version"]; ver != "" {
		return "Unraid OS " + ver
	}
	if ver := firstLine(b["truenas"]); ver != "" {
		if strings.Contains(strings.ToLower(ver), "truenas") {
			return ver
		}
		return "TrueNAS " + ver
	}
	if ver := firstLine(b["omv"]); ver != "" {
		return "OpenMediaVault " + ver
	}
	for _, f := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		kv := parseKV(b[f])
		if kv["PRETTY_NAME"] != "" {
			return kv["PRETTY_NAME"]
		}
		if kv["NAME"] != "" {
			return strings.TrimSpace(kv["NAME"] + " " + kv["VERSION"])
		}
	}
	if s := parseKV(b["/etc/lsb-release"])["DISTRIB_DESCRIPTION"]; s != "" {
		return s
	}
	return firstLine(b["/etc/redhat-release"])
}

// parseCPUModel — Tên CPU. x86 có "model name"; ARM (Graviton, Ampere, CPU của
// nhiều NAS) thường không có → thử lscpu, "Hardware", "Model" (Raspberry Pi),
// rồi tới /proc/device-tree/model.
func parseCPUModel(output string) string {
	b := splitTagged(output)

	info := make(map[string]string) // giá trị đầu tiên của mỗi key trong /proc/cpuinfo
	for _, line := range strings.Split(b[""], "\n") {
		k, v, ok := strings.Cut(line, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if ok && v != "" && info[k] == "" {
			info[k] = v
		}
	}
	lscpu := ""
	if _, v, ok := strings.Cut(firstLine(b["lscpu"]), ":"); ok {
		if lscpu = strings.TrimSpace(v); lscpu == "-" {
			lscpu = ""
		}
	}
	dt := strings.TrimSpace(strings.ReplaceAll(b["dt"], "\x00", ""))

	for _, v := range []string{info["model name"], info["cpu model"], info["Processor"], lscpu, info["Hardware"], info["Model"], dt} {
		if v != "" {
			return v
		}
	}
	return ""
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

// saveConfigLocked — Ghi file (caller phải giữ configMu).
// Ghi ra file tạm rồi rename để không bao giờ để lại servers.json bị cụt.
// Quyền 0600 vì file chứa mật khẩu SSH/proxy.
func (app *App) saveConfigLocked() error {
	data, err := json.MarshalIndent(app.config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := app.configPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, app.configPath); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
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

// CheckOrigin để mặc định: gorilla chỉ chấp nhận Origin trùng Host,
// chặn website lạ mở WebSocket tới localhost (WebSocket hijacking)
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
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
// normalizeHost — Bỏ khoảng trắng và cặp [] quanh IPv6 ("[2001:db8::1]" → "2001:db8::1")
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return h
}

// hostPort — Ghép host:port, tự thêm [] cho IPv6 ("[2001:db8::1]:22")
func hostPort(host string, port int) string {
	return net.JoinHostPort(normalizeHost(host), strconv.Itoa(port))
}

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

	addr := hostPort(cfg.Host, cfg.Port)
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

	out, err := session.Output(shCmd("hostname 2>/dev/null || cat /proc/sys/kernel/hostname"))
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
	cfg.Host = normalizeHost(cfg.Host)
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

	cfg.Host = normalizeHost(cfg.Host)
	if cfg.Host == "" {
		httpError(w, "Host is required", http.StatusBadRequest)
		return
	}

	cfg.ID = id
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
	for _, g := range app.config.Groups {
		if g != oldName && strings.EqualFold(g, newName) {
			app.configMu.Unlock()
			httpError(w, "Cụm này đã tồn tại", http.StatusConflict)
			return
		}
	}
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

// handleBulkServers — POST /api/servers/bulk
// action: "delete" | "set_group" (group) | "set_proxy" (proxy_id, "" = bỏ proxy)
func (app *App) handleBulkServers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs     []string `json:"ids"`
		Action  string   `json:"action"`
		Group   string   `json:"group"`
		ProxyID string   `json:"proxy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
		httpError(w, "Danh sách server không hợp lệ", http.StatusBadRequest)
		return
	}
	idSet := make(map[string]bool, len(req.IDs))
	for _, id := range req.IDs {
		idSet[id] = true
	}

	req.Group = strings.TrimSpace(req.Group)
	switch req.Action {
	case "delete":
	case "set_group":
		if req.Group == "" {
			req.Group = "Default"
		}
	case "set_proxy":
		if req.ProxyID != "" && app.findProxy(req.ProxyID) == nil {
			httpError(w, "Không tìm thấy proxy", http.StatusBadRequest)
			return
		}
	default:
		httpError(w, "Thao tác không hợp lệ", http.StatusBadRequest)
		return
	}

	app.configMu.Lock()
	if req.Action == "set_group" {
		exists := false
		for _, g := range app.config.Groups {
			if g == req.Group {
				exists = true
				break
			}
		}
		if !exists {
			app.configMu.Unlock()
			httpError(w, "Không tìm thấy cụm máy chủ", http.StatusBadRequest)
			return
		}
	}

	var affected []ServerConfig
	kept := app.config.Servers[:0:0]
	for _, s := range app.config.Servers {
		if !idSet[s.ID] {
			kept = append(kept, s)
			continue
		}
		switch req.Action {
		case "set_group":
			s.Group = req.Group
		case "set_proxy":
			s.ProxyID = req.ProxyID
		}
		affected = append(affected, s)
		if req.Action != "delete" {
			kept = append(kept, s)
		}
	}
	if len(affected) == 0 {
		app.configMu.Unlock()
		httpError(w, "Server not found", http.StatusNotFound)
		return
	}
	app.config.Servers = kept
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Lưu thất bại: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for _, s := range affected {
		switch req.Action {
		case "delete":
			app.stopAgent(s.ID)
		case "set_proxy":
			app.startAgent(s) // startAgent tự dừng agent cũ
		case "set_group":
			app.agentsMu.RLock()
			ag := app.agents[s.ID]
			app.agentsMu.RUnlock()
			if ag != nil {
				ag.mu.Lock()
				ag.config.Group = s.Group
				ag.metrics.Group = s.Group
				ag.mu.Unlock()
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"affected": len(affected)})
}

// handleBulkDeleteGroups — POST /api/groups/bulk {groups: [...]}
// Xóa nhiều cụm; server trong các cụm đó chuyển về "Default". Không xóa "Default".
func (app *App) handleBulkDeleteGroups(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Groups) == 0 {
		httpError(w, "Danh sách cụm không hợp lệ", http.StatusBadRequest)
		return
	}
	del := make(map[string]bool, len(req.Groups))
	for _, g := range req.Groups {
		if g != "Default" {
			del[g] = true
		}
	}

	app.configMu.Lock()
	var kept []string
	removed := 0
	for _, g := range app.config.Groups {
		if del[g] {
			removed++
			continue
		}
		kept = append(kept, g)
	}
	if removed == 0 {
		app.configMu.Unlock()
		httpError(w, "Không tìm thấy cụm máy chủ", http.StatusNotFound)
		return
	}
	moved := false
	for i := range app.config.Servers {
		if del[app.config.Servers[i].Group] {
			app.config.Servers[i].Group = "Default"
			moved = true
		}
	}
	// Server bị chuyển về "Default" thì cụm này phải tồn tại để còn hiện ở UI
	if moved && !slices.Contains(kept, "Default") {
		kept = append([]string{"Default"}, kept...)
	}
	app.config.Groups = kept
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Lưu thất bại: "+err.Error(), http.StatusInternalServerError)
		return
	}

	app.agentsMu.Lock()
	for _, ag := range app.agents {
		ag.mu.Lock()
		if del[ag.config.Group] {
			ag.config.Group = "Default"
			ag.metrics.Group = "Default"
		}
		ag.mu.Unlock()
	}
	app.agentsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"removed": removed})
}

// ========================== HTTP Router ==========================

func (app *App) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Groups API
	mux.HandleFunc("/api/groups/bulk", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			app.handleBulkDeleteGroups(w, r)
			return
		}
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

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

	mux.HandleFunc("/api/pick-file", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			app.handlePickFile(w, r)
			return
		}
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// Server API routes
	mux.HandleFunc("/api/servers/bulk", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			app.handleBulkServers(w, r)
			return
		}
		httpError(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

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

	return localOnly(mux)
}

// localOnly — Chỉ phục vụ request từ chính dashboard local:
// Host phải là localhost/loopback (chống DNS rebinding),
// Origin nếu có phải trùng Host (chống CSRF từ website khác).
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			httpError(w, "Forbidden host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				httpError(w, "Forbidden origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackHost — Host header (có thể kèm port) là localhost hoặc IP loopback
func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ========================== Utility Functions ==========================

// setConsoleTitle — Đặt tiêu đề cửa sổ terminal (hiện trên thanh title của cmd).
// Windows: gọi SetConsoleTitleW của kernel32. Linux/macOS: gửi chuỗi escape OSC.
func setConsoleTitle(title string) {
	switch runtime.GOOS {
	case "windows":
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		proc := kernel32.NewProc("SetConsoleTitleW")
		p, err := syscall.UTF16PtrFromString(title)
		if err == nil {
			proc.Call(uintptr(unsafe.Pointer(p)))
		}
	default:
		fmt.Printf("\033]0;%s\007", title)
	}
}

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
		return os.WriteFile(path, data, 0600)
	}
	return nil
}

// ========================== Main ==========================

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Đặt tiêu đề cửa sổ terminal: SSH Monitor vX.X.X
	setConsoleTitle("SSH Monitor v" + AppVersion)

	configPath := getConfigPath()
	// Đảm bảo file servers.json tồn tại
	if err := ensureConfigFileExists(configPath); err != nil {
		log.Printf("Cannot create config file: %v", err)
	}
	app := NewApp(configPath)

	// Load cấu hình server
	// Không chạy tiếp với config rỗng: lần lưu đầu tiên sẽ ghi đè mất toàn bộ server
	if err := app.LoadConfig(); err != nil {
		log.Fatalf("Config error: %v — hãy sửa %s rồi chạy lại", err, configPath)
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
		Addr:         "127.0.0.1" + ServerPort, // chỉ nghe local, không mở ra LAN
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
