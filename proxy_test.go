package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ===================== Mock SOCKS5 proxy =====================

func startMockSocks5(t *testing.T, requireUser, requirePass string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSocks5(conn, requireUser, requirePass)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func handleMockSocks5(conn net.Conn, requireUser, requirePass string) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	// Greeting: VER + NMETHODS (phải consume, không Peek)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return
	}
	nm := int(head[1])
	methods := make([]byte, nm)
	io.ReadFull(br, methods)

	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
		}
	}
	if requireUser != "" {
		if !hasUserPass {
			conn.Write([]byte{0x05, 0xFF}) // no acceptable methods
			return
		}
		conn.Write([]byte{0x05, 0x02})
		// Auth sub-negotiation
		ver, _ := br.ReadByte()
		ulen, _ := br.ReadByte()
		user := make([]byte, ulen)
		io.ReadFull(br, user)
		plen, _ := br.ReadByte()
		pass := make([]byte, plen)
		io.ReadFull(br, pass)
		if ver != 0x01 || string(user) != requireUser || string(pass) != requirePass {
			conn.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		conn.Write([]byte{0x01, 0x00}) // auth success
	} else {
		conn.Write([]byte{0x05, 0x00})
	}

	// CONNECT request: đọc VER, CMD, RSV, ATYP (consume đầy đủ)
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		return
	}
	atyp := req[3]
	switch atyp {
	case 0x01: // IPv4: 4 byte addr + 2 byte port
		io.ReadFull(br, make([]byte, 4+2))
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	case 0x03: // domain: 1 byte len + len + 2 byte port
		lenBuf := make([]byte, 1)
		io.ReadFull(br, lenBuf)
		io.ReadFull(br, make([]byte, int(lenBuf[0])+2))
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Echo mode: sau handshake, proxy echo lại data để test tunnel hoạt động
	io.Copy(conn, br)
}

// ===================== Mock SOCKS4 proxy =====================

func startMockSocks4(t *testing.T, granted bool) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				// VN=4, CD=1, 2 byte port, 4 byte IP
				head := make([]byte, 8)
				if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x04 {
					return
				}
				// userid: chuỗi NUL-terminated
				for {
					b, err := br.ReadByte()
					if err != nil || b == 0x00 {
						break
					}
				}
				// SOCKS4A: IP 0.0.0.x → có thêm domain NUL-terminated
				if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
					for {
						b, err := br.ReadByte()
						if err != nil || b == 0x00 {
							break
						}
					}
				}
				if granted {
					c.Write([]byte{0x00, 90, 0, 0, 0, 0, 0, 0})
					io.Copy(c, br)
				} else {
					c.Write([]byte{0x00, 91, 0, 0, 0, 0, 0, 0})
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// ===================== Mock HTTP CONNECT proxy =====================

func startMockHTTPConnect(t *testing.T, requireUser, requirePass string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				reqLine, err := br.ReadString('\n')
				if err != nil {
					c.Close()
					return
				}
				headers := map[string]string{}
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
					line = strings.TrimRight(line, "\r\n")
					if idx := strings.Index(line, ":"); idx > 0 {
						headers[strings.ToLower(line[:idx])] = strings.TrimSpace(line[idx+1:])
					}
				}
				if !strings.HasPrefix(reqLine, "CONNECT ") {
					c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
					c.Close()
					return
				}
				if requireUser != "" {
					auth := headers["proxy-authorization"]
					expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(requireUser+":"+requirePass))
					if auth != expected {
						c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
						c.Close()
						return
					}
				}
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				io.Copy(c, br) // echo
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// ===================== Tests =====================

func TestSocks5NoAuth(t *testing.T) {
	addr := startMockSocks5(t, "", "")
	host, port, _ := net.SplitHostPort(addr)
	pint, _ := strconv.Atoi(port)
	p := &ProxyConfig{Type: "socks5", Host: host, Port: pint}

	conn, err := dialThroughProxy("93.184.216.34:22", p, 5*time.Second)
	if err != nil {
		t.Fatalf("socks5 no-auth dial: %v", err)
	}
	defer conn.Close()

	// Tunnel phải echo được data
	msg := []byte("hello tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

func TestSocks5UserPass(t *testing.T) {
	addr := startMockSocks5(t, "user1", "pass1")
	host, port, _ := net.SplitHostPort(addr)
	pint, _ := strconv.Atoi(port)

	// Đúng credentials
	p := &ProxyConfig{Type: "socks5", Host: host, Port: pint, Username: "user1", Password: "pass1"}
	conn, err := dialThroughProxy("1.2.3.4:22", p, 5*time.Second)
	if err != nil {
		t.Fatalf("socks5 auth dial: %v", err)
	}
	conn.Close()

	// Sai credentials → phải lỗi
	pBad := &ProxyConfig{Type: "socks5", Host: host, Port: pint, Username: "user1", Password: "wrong"}
	if _, err := dialThroughProxy("1.2.3.4:22", pBad, 5*time.Second); err == nil {
		t.Fatal("socks5: mong đợi lỗi khi sai password, nhưng dial thành công")
	}

	// Không credentials khi proxy yêu cầu → phải lỗi
	pNone := &ProxyConfig{Type: "socks5", Host: host, Port: pint}
	if _, err := dialThroughProxy("1.2.3.4:22", pNone, 5*time.Second); err == nil {
		t.Fatal("socks5: mong đợi lỗi khi thiếu credentials")
	}
}

func TestSocks4GrantedAndRejected(t *testing.T) {
	addrOK := startMockSocks4(t, true)
	host, port, _ := net.SplitHostPort(addrOK)
	pint, _ := strconv.Atoi(port)
	p := &ProxyConfig{Type: "socks4", Host: host, Port: pint}

	conn, err := dialThroughProxy("93.184.216.34:22", p, 5*time.Second)
	if err != nil {
		t.Fatalf("socks4 granted dial: %v", err)
	}
	conn.Close()

	addrBad := startMockSocks4(t, false)
	host2, port2, _ := net.SplitHostPort(addrBad)
	pint2, _ := strconv.Atoi(port2)
	p2 := &ProxyConfig{Type: "socks4", Host: host2, Port: pint2}
	if _, err := dialThroughProxy("93.184.216.34:22", p2, 5*time.Second); err == nil {
		t.Fatal("socks4: mong đợi lỗi khi proxy reject (91)")
	}
}

func TestHTTPConnect(t *testing.T) {
	addr := startMockHTTPConnect(t, "", "")
	host, port, _ := net.SplitHostPort(addr)
	pint, _ := strconv.Atoi(port)
	p := &ProxyConfig{Type: "http", Host: host, Port: pint}

	conn, err := dialThroughProxy("93.184.216.34:22", p, 5*time.Second)
	if err != nil {
		t.Fatalf("http CONNECT dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping")
	conn.Write(msg)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch")
	}
}

func TestHTTPConnectAuth(t *testing.T) {
	addr := startMockHTTPConnect(t, "puser", "ppass")
	host, port, _ := net.SplitHostPort(addr)
	pint, _ := strconv.Atoi(port)

	pOK := &ProxyConfig{Type: "http", Host: host, Port: pint, Username: "puser", Password: "ppass"}
	conn, err := dialThroughProxy("1.2.3.4:22", pOK, 5*time.Second)
	if err != nil {
		t.Fatalf("http CONNECT auth dial: %v", err)
	}
	conn.Close()

	pBad := &ProxyConfig{Type: "http", Host: host, Port: pint, Username: "puser", Password: "wrong"}
	_, err = dialThroughProxy("1.2.3.4:22", pBad, 5*time.Second)
	if err == nil {
		t.Fatal("http CONNECT: mong đợi lỗi 407 khi sai password")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Fatalf("mong đợi thông báo 407, nhận: %v", err)
	}
}

func TestValidateProxy(t *testing.T) {
	cases := []struct {
		name    string
		p       ProxyConfig
		wantErr bool
	}{
		{"socks5 ok", ProxyConfig{Type: "socks5", Host: "1.1.1.1", Port: 1080}, false},
		{"http ok", ProxyConfig{Type: "http", Host: "proxy.example.com", Port: 8080}, false},
		{"thiếu host", ProxyConfig{Type: "socks5", Host: "", Port: 1080}, true},
		{"port sai", ProxyConfig{Type: "socks5", Host: "1.1.1.1", Port: 0}, true},
		{"type lạ", ProxyConfig{Type: "ftp", Host: "1.1.1.1", Port: 21}, true},
		{"type hoa", ProxyConfig{Type: "SOCKS5", Host: "1.1.1.1", Port: 1080}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateProxy(&c.p)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateProxy(%+v) = %v, wantErr=%v", c.p, err, c.wantErr)
			}
		})
	}
}
