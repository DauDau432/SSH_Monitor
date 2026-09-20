// ===========================================================================
// Proxy support — SOCKS4/4A, SOCKS5 (RFC 1928/1929), HTTP/HTTPS CONNECT
// Tự cài đặt handshake, không phụ thuộc thư viện ngoài
// ===========================================================================

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ProxyConfig — 1 proxy trong danh sách (lưu trong servers.json)
type ProxyConfig struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"` // socks4, socks5, http, https
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// ProxyTypes — Danh sách loại proxy hỗ trợ
var ProxyTypes = []string{"socks5", "socks4", "http", "https"}

// dialThroughProxy — Tạo TCP connection tới target, đi qua proxy nếu có.
// proxy == nil → dial trực tiếp.
func dialThroughProxy(targetAddr string, p *ProxyConfig, timeout time.Duration) (net.Conn, error) {
	if p == nil {
		return net.DialTimeout("tcp", targetAddr, timeout)
	}

	proxyAddr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))

	var conn net.Conn
	var err error
	if p.Type == "https" {
		// Proxy endpoint chạy TLS
		d := &net.Dialer{Timeout: timeout}
		raw, err := d.Dial("tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("connect to proxy %s: %w", proxyAddr, err)
		}
		tlsConn := tls.Client(raw, &tls.Config{ServerName: p.Host})
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			raw.Close()
			return nil, err
		}
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS handshake with proxy: %w", err)
		}
		conn = tlsConn
	} else {
		conn, err = net.DialTimeout("tcp", proxyAddr, timeout)
		if err != nil {
			return nil, fmt.Errorf("connect to proxy %s: %w", proxyAddr, err)
		}
	}

	// Deadline chung cho toàn bộ handshake
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	switch p.Type {
	case "socks5":
		err = socks5Handshake(conn, targetAddr, p)
	case "socks4":
		err = socks4Handshake(conn, targetAddr, p)
	case "http", "https":
		err = httpConnectHandshake(conn, targetAddr, p)
	default:
		err = fmt.Errorf("unsupported proxy type: %s", p.Type)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Gỡ deadline — connection giờ là tunnel raw
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// ========================== SOCKS5 (RFC 1928 + RFC 1929) ==========================

func socks5Handshake(conn net.Conn, targetAddr string, p *ProxyConfig) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid target port %q", portStr)
	}

	hasAuth := p.Username != "" || p.Password != ""

	// Bước 1: chào phương thức auth
	var greeting []byte
	if hasAuth {
		greeting = []byte{0x05, 2, 0x00, 0x02} // no-auth + username/password
	} else {
		greeting = []byte{0x05, 1, 0x00} // no-auth
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 greeting reply: %w", err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("socks5: bad version %d from proxy", reply[0])
	}

	switch reply[1] {
	case 0x00:
		// Proxy cho phép no-auth
	case 0x02:
		if !hasAuth {
			return fmt.Errorf("socks5: proxy yêu cầu username/password nhưng chưa cấu hình")
		}
		if err := socks5AuthUserPass(conn, p.Username, p.Password); err != nil {
			return err
		}
	case 0xFF:
		return fmt.Errorf("socks5: proxy từ chối mọi phương thức auth")
	default:
		return fmt.Errorf("socks5: proxy chọn phương thức auth không hỗ trợ (0x%02x)", reply[1])
	}

	// Bước 2: gửi yêu cầu CONNECT
	req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01) // ATYP = IPv4
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04) // ATYP = IPv6
			req = append(req, ip...)
		}
	} else {
		req = append(req, 0x03) // ATYP = DOMAINNAME
		req = append(req, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port&0xFF))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect request: %w", err)
	}

	// Bước 3: đọc reply (VER, REP, RSV, ATYP, BND.ADDR, BND.PORT)
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5 connect reply: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks5: bad reply version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: proxy từ chối kết nối tới %s (mã lỗi 0x%02x: %s)",
			targetAddr, head[1], socks5ErrorText(head[1]))
	}

	// Đọc nốt BND.ADDR + BND.PORT theo ATYP (bỏ qua, không dùng)
	switch head[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			return fmt.Errorf("socks5: đọc bind address lỗi: %w", err)
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			return fmt.Errorf("socks5: đọc bind address lỗi: %w", err)
		}
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("socks5: đọc bind address lỗi: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil {
			return fmt.Errorf("socks5: đọc bind address lỗi: %w", err)
		}
	default:
		return fmt.Errorf("socks5: ATYP lạ 0x%02x trong reply", head[3])
	}
	return nil
}

func socks5AuthUserPass(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("socks5: username/password quá dài (tối đa 255 ký tự)")
	}
	req := []byte{0x01, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 auth request: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 auth reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks5: proxy từ chối username/password")
	}
	return nil
}

func socks5ErrorText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown"
	}
}

// ========================== SOCKS4 / SOCKS4A ==========================

func socks4Handshake(conn net.Conn, targetAddr string, p *ProxyConfig) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid target port %q", portStr)
	}

	// SOCKS4 không có auth — username chỉ được dùng làm "user ID" gửi kèm
	userID := p.Username

	req := []byte{0x04, 0x01} // VN, CD=CONNECT
	req = append(req, byte(port>>8), byte(port&0xFF))

	ip := net.ParseIP(host)
	useDomain := false // SOCKS4A: proxy tự resolve domain
	if ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return fmt.Errorf("socks4: không hỗ trợ IPv6 (%s)", host)
		}
		req = append(req, ip4...)
	} else {
		// Thử resolve cục bộ trước (SOCKS4 thuần)
		if resolved, err := net.ResolveIPAddr("ip4", host); err == nil && resolved.IP != nil {
			req = append(req, resolved.IP.To4()...)
		} else {
			// SOCKS4A: gửi IP giả 0.0.0.1 để proxy tự resolve
			req = append(req, 0x00, 0x00, 0x00, 0x01)
			useDomain = true
		}
	}

	req = append(req, userID...)
	req = append(req, 0x00)

	// SOCKS4A: domain nối tiếp sau user ID
	if useDomain {
		req = append(req, host...)
		req = append(req, 0x00)
	}

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks4 request: %w", err)
	}

	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks4 reply: %w", err)
	}
	// CD nằm ở byte 1: 90 = granted
	if reply[1] != 90 {
		return fmt.Errorf("socks4: proxy từ chối kết nối tới %s (mã %d: %s)",
			targetAddr, reply[1], socks4ErrorText(reply[1]))
	}
	return nil
}

func socks4ErrorText(code byte) string {
	switch code {
	case 91:
		return "request rejected or failed"
	case 92:
		return "request rejected — proxy không kết nối được identd"
	case 93:
		return "request rejected — identd không xác nhận user"
	default:
		return "unknown"
	}
}

// ========================== HTTP/HTTPS CONNECT ==========================

func httpConnectHandshake(conn net.Conn, targetAddr string, p *ProxyConfig) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	// Chuẩn hóa: port mặc định theo URL không áp dụng cho CONNECT — bắt buộc có port
	if _, err := strconv.Atoi(portStr); err != nil {
		return fmt.Errorf("invalid target port %q", portStr)
	}
	hostPort := net.JoinHostPort(host, portStr)

	var sb strings.Builder
	sb.WriteString("CONNECT " + hostPort + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + hostPort + "\r\n")
	if p.Username != "" || p.Password != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		sb.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	sb.WriteString("\r\n")

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return fmt.Errorf("http CONNECT request: %w", err)
	}

	// Đọc response header
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("http CONNECT reply: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		if resp.StatusCode == 407 {
			return fmt.Errorf("http proxy: yêu cầu xác thực (407) — kiểm tra lại username/password proxy")
		}
		return fmt.Errorf("http proxy: từ chối CONNECT tới %s (HTTP %d)", targetAddr, resp.StatusCode)
	}

	// Nếu proxy trả body thừa sau header (hiếm), tunnel sẽ hỏng — báo lỗi rõ ràng
	if br.Buffered() > 0 {
		return fmt.Errorf("http proxy: gửi %d byte thừa sau CONNECT response", br.Buffered())
	}
	return nil
}

// ========================== Proxy API Handlers ==========================

// handleGetProxies — GET /api/proxies
func (app *App) handleGetProxies(w http.ResponseWriter, r *http.Request) {
	app.configMu.RLock()
	defer app.configMu.RUnlock()

	proxies := app.config.Proxies
	if proxies == nil {
		proxies = []ProxyConfig{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	json.NewEncoder(w).Encode(map[string]interface{}{"proxies": proxies})
}

// handleAddProxy — POST /api/proxies
func (app *App) handleAddProxy(w http.ResponseWriter, r *http.Request) {
	var p ProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateProxy(&p); err != nil {
		httpError(w, err.Error(), http.StatusBadRequest)
		return
	}

	app.configMu.Lock()
	p.ID = app.nextProxyIDLocked()
	app.config.Proxies = append(app.config.Proxies, p)
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(p)
}

// handleUpdateProxy — PUT /api/proxies/{id}
func (app *App) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/proxies/")
	if id == "" {
		httpError(w, "Proxy ID is required", http.StatusBadRequest)
		return
	}

	var p ProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateProxy(&p); err != nil {
		httpError(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.ID = id

	app.configMu.Lock()
	found := false
	for i, old := range app.config.Proxies {
		if old.ID == id {
			app.config.Proxies[i] = p
			found = true
			break
		}
	}
	if !found {
		app.configMu.Unlock()
		httpError(w, "Proxy not found", http.StatusNotFound)
		return
	}
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Restart các agent đang dùng proxy này để nhận cấu hình mới
	app.restartAgentsUsingProxy(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

// handleDeleteProxy — DELETE /api/proxies/{id}
func (app *App) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/proxies/")
	if id == "" {
		httpError(w, "Proxy ID is required", http.StatusBadRequest)
		return
	}

	app.configMu.Lock()
	found := false
	for i, p := range app.config.Proxies {
		if p.ID == id {
			app.config.Proxies = append(app.config.Proxies[:i], app.config.Proxies[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		app.configMu.Unlock()
		httpError(w, "Proxy not found", http.StatusNotFound)
		return
	}
	// Gỡ proxy khỏi các server đang dùng → về kết nối trực tiếp
	affectedServers := []ServerConfig{}
	for i := range app.config.Servers {
		if app.config.Servers[i].ProxyID == id {
			app.config.Servers[i].ProxyID = ""
			affectedServers = append(affectedServers, app.config.Servers[i])
		}
	}
	err := app.saveConfigLocked()
	app.configMu.Unlock()

	if err != nil {
		httpError(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Restart agent của các server bị ảnh hưởng
	for _, s := range affectedServers {
		app.stopAgent(s.ID)
		app.startAgent(s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleTestProxy — POST /api/proxies/test (test proxy chưa cần lưu)
func (app *App) handleTestProxy(w http.ResponseWriter, r *http.Request) {
	var p ProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateProxy(&p); err != nil {
		httpError(w, err.Error(), http.StatusBadRequest)
		return
	}

	elapsed, err := testProxy(&p)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusOK) // lỗi proxy là kết quả test, không phải lỗi HTTP
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"latency": elapsed.Milliseconds(),
	})
}

// validateProxy — Kiểm tra dữ liệu proxy hợp lệ
func validateProxy(p *ProxyConfig) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Host = strings.TrimSpace(p.Host)
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))

	if p.Host == "" {
		return fmt.Errorf("Host proxy là bắt buộc")
	}
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("Port proxy không hợp lệ (1-65535)")
	}
	valid := false
	for _, t := range ProxyTypes {
		if p.Type == t {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("Loại proxy không hỗ trợ: %s (chọn: %s)", p.Type, strings.Join(ProxyTypes, ", "))
	}
	if p.Name == "" {
		p.Name = p.Type + "://" + p.Host + ":" + strconv.Itoa(p.Port)
	}
	return nil
}

// restartAgentsUsingProxy — Restart các agent của server đang dùng proxy này
func (app *App) restartAgentsUsingProxy(proxyID string) {
	app.configMu.RLock()
	var affected []ServerConfig
	for _, s := range app.config.Servers {
		if s.ProxyID == proxyID {
			affected = append(affected, s)
		}
	}
	app.configMu.RUnlock()

	for _, s := range affected {
		app.stopAgent(s.ID)
		app.startAgent(s)
	}
}

// ========================== Proxy test ==========================

// testProxy — Kiểm tra proxy có sống không bằng cách CONNECT tới 1 target công khai
func testProxy(p *ProxyConfig) (time.Duration, error) {
	start := time.Now()
	conn, err := dialThroughProxy("1.1.1.1:443", p, 10*time.Second)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

// helper cho API: parse proxy id → config
func (app *App) findProxy(id string) *ProxyConfig {
	if id == "" {
		return nil
	}
	app.configMu.RLock()
	defer app.configMu.RUnlock()
	for i := range app.config.Proxies {
		if app.config.Proxies[i].ID == id {
			p := app.config.Proxies[i]
			return &p
		}
	}
	return nil
}

// generateProxyID — ID dạng số cho proxy (dùng chung counter next_server_id? không — counter riêng)
func (app *App) nextProxyIDLocked() string {
	if app.config.NextProxyID == 0 {
		maxID := 0
		for _, p := range app.config.Proxies {
			if id, err := strconv.Atoi(p.ID); err == nil && id > maxID {
				maxID = id
			}
		}
		app.config.NextProxyID = maxID
	}
	app.config.NextProxyID++
	return strconv.Itoa(app.config.NextProxyID)
}
