# SSH Monitor

Ứng dụng web tự host để giám sát và quản lý nhiều VPS Linux qua SSH mà không cần cài agent trên máy đích.

## Tính năng

- Theo dõi CPU, RAM, disk, network, disk I/O, uptime, OS và kernel theo thời gian thực.
- Kết nối SSH lâu dài, tự reconnect khi máy đích mất kết nối.
- Dashboard web và cập nhật qua WebSocket.
- Web terminal SSH dựa trên xterm.js.
- Quản lý server theo group.
- Kết nối trực tiếp hoặc qua SOCKS4/4A, SOCKS5, HTTP/HTTPS CONNECT proxy.
- Duyệt file remote và đồng bộ một file từ VPS nguồn tới nhiều VPS đích.
- Frontend được nhúng trong binary Go duy nhất.

## Yêu cầu

- Go `1.26.1` trở lên để build theo `go.mod` hiện tại.
- Máy chạy SSH Monitor có thể kết nối tới cổng SSH của các VPS.
- Máy đích dùng Linux và cung cấp các lệnh/thông tin chuẩn như `/proc`, `df`, `nproc`, `stat`, `md5sum`.

## Chạy từ source

```bash
git clone https://github.com/DauDau432/SSH_Monitor.git
cd SSH_Monitor
go mod download
go run .
```

Mở: <http://localhost:8080>

Nếu `servers.json` chưa tồn tại, ứng dụng sẽ tự tạo file khi cần. Bạn cũng có thể thêm server trực tiếp từ giao diện.

## Build

### Windows

```powershell
go build -o ssh-monitor.exe .
.\ssh-monitor.exe
```

### Linux

```bash
go build -o ssh-monitor .
./ssh-monitor
```

## Dữ liệu và security

`servers.json` lưu cấu hình kết nối, có thể gồm:

- IP/hostname và port SSH
- username/password
- đường dẫn private key
- proxy credentials

File này sẽ tự tạo cấu trúc chuẩn khi chạy ứng dụng nếu nó chưa có.

Ứng dụng hiện dùng `ssh.InsecureIgnoreHostKey()` và không xác minh host key. Chỉ chạy trong network tin cậy, không expose port `8080` trực tiếp ra Internet. Nên đặt sau firewall, VPN hoặc reverse proxy có authentication.

## Kiểm tra

```bash
gofmt -w .
go vet ./...
go test ./...
go build ./...
```

## License

[MIT](LICENSE)
