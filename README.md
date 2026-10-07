# SSH Monitor

Ứng dụng web chạy local trên Windows để giám sát và quản lý nhiều máy chủ Linux (VPS, NAS) qua SSH mà không cần cài agent trên máy đích.

## Tính năng

- Theo dõi CPU, RAM, disk, network, disk I/O, uptime, OS và kernel theo thời gian thực.
- Hỗ trợ các bản phân phối Linux phổ biến và NAS (Synology, Unraid, TrueNAS...): tự nhận diện ổ lưu trữ, card mạng và ổ đĩa vật lý.
- Kết nối SSH lâu dài, tự reconnect khi máy đích mất kết nối.
- Dashboard web và cập nhật qua WebSocket.
- Web terminal SSH dựa trên xterm.js.
- Quản lý server theo group, kéo thả để sắp xếp thứ tự.
- Chọn nhiều server/group để thao tác hàng loạt: xóa, đổi group, gán hoặc bỏ proxy.
- Kết nối trực tiếp hoặc qua SOCKS4/4A, SOCKS5, HTTP/HTTPS CONNECT proxy; xem nhanh danh sách server đang dùng từng proxy.
- Chọn file SSH key bằng hộp thoại của Windows.
- Duyệt file remote và đồng bộ một file từ VPS nguồn tới nhiều VPS đích.
- Frontend được nhúng trong binary Go duy nhất.

## Yêu cầu

- Windows (ứng dụng chỉ build và chạy trên Windows).
- Go `1.26.1` trở lên để build theo `go.mod` hiện tại.
- Máy chạy SSH Monitor có thể kết nối tới cổng SSH của các máy đích.
- Máy đích dùng Linux và cung cấp các lệnh/thông tin chuẩn như `/proc`, `df`, `nproc`, `stat`, `md5sum`.

## Chạy từ source

```powershell
git clone https://github.com/DauDau432/SSH_Monitor.git
cd SSH_Monitor
go mod download
go run .
```

Mở: <http://localhost:8888>

Nếu `servers.json` chưa tồn tại, ứng dụng sẽ tự tạo file khi cần. Bạn cũng có thể thêm server trực tiếp từ giao diện.

## Build

```powershell
go build -o ssh-monitor.exe .
.\ssh-monitor.exe
```

Icon của file exe nằm trong `rsrc_windows_amd64.syso` (tạo từ `image/logo.png`), `go build` tự nhúng vào. Khi đổi logo, tạo lại bằng:

```powershell
go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --manifest cli --icon image/logo.png
```

## Dữ liệu và security

`servers.json` lưu cấu hình kết nối, có thể gồm:

- IP/hostname và port SSH
- username/password
- đường dẫn private key
- proxy credentials

File này sẽ tự tạo cấu trúc chuẩn khi chạy ứng dụng nếu nó chưa có.

Ứng dụng chỉ lắng nghe trên `127.0.0.1:8888` và từ chối request từ IP khác, từ website lạ (kiểm tra `Origin`) hay qua DNS rebinding — chỉ truy cập được từ chính máy đang chạy, không dùng được qua LAN hay reverse proxy.

Ứng dụng hiện dùng `ssh.InsecureIgnoreHostKey()` và không xác minh host key, nên chỉ kết nối tới máy đích qua network tin cậy.

## Kiểm tra

```powershell
gofmt -w .
go vet ./...
go test ./...
go build ./...
```

## License

[MIT](LICENSE)
