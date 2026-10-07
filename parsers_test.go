package main

import "testing"

func TestParseDiskUsage(t *testing.T) {
	cases := []struct {
		name                          string
		df, mounts                    string
		wantTotal, wantUsed, wantFree string
		wantPct                       float64
	}{
		{
			name: "VPS: chỉ / thật, bỏ tmpfs/boot/loop",
			df: `Filesystem     1024-blocks    Used Available Capacity Mounted on
/dev/vda1         41152736 10485760  28550000      27% /
tmpfs              1018000        0   1018000       0% /dev/shm
/dev/vda15          106858     6186    100672       6% /boot/efi
/dev/loop0           65536    65536         0     100% /snap/core/1`,
			mounts: `/dev/vda1 / ext4 rw 0 0
tmpfs /dev/shm tmpfs rw 0 0
/dev/vda15 /boot/efi vfat rw 0 0
/dev/loop0 /snap/core/1 squashfs ro 0 0`,
			wantTotal: "40G", wantUsed: "10G", wantFree: "28G", wantPct: 27,
		},
		{
			name: "Synology: cộng /volume1 + /volume2, bỏ ecryptfs và bind mount trùng",
			df: `Filesystem         1024-blocks       Used  Available Capacity Mounted on
/dev/md0               2385528    1468000     798744      65% /
/dev/mapper/cachedev_0 1073741824 536870912 536870912    50% /volume1
/dev/mapper/cachedev_0 1073741824 536870912 536870912    50% /volume1/@docker
/dev/mapper/cachedev_1 1073741824 268435456 805306368    25% /volume2
/volume1/@Secure  1073741824 536870912 536870912    50% /volume1/Secure`,
			mounts: `/dev/md0 / ext4 rw 0 0
/dev/mapper/cachedev_0 /volume1 btrfs rw 0 0
/dev/mapper/cachedev_0 /volume1/@docker btrfs rw 0 0
/dev/mapper/cachedev_1 /volume2 btrfs rw 0 0
/volume1/@Secure /volume1/Secure ecryptfs rw 0 0`,
			// 2.27G + 1T + 1T ≈ 2.01T
			wantTotal: "2.1T", wantUsed: "770G", wantFree: "1.3T", wantPct: 38,
		},
		{
			name: "Unraid: bỏ shfs (/mnt/user), USB /boot, docker.img loop",
			df: `Filesystem     1024-blocks       Used  Available Capacity Mounted on
rootfs             8000000     800000    7200000      10% /
/dev/sda1         15000000     500000   14500000       4% /boot
/dev/md1p1      3906250000 1953125000 1953125000      50% /mnt/disk1
/dev/md2p1      3906250000  976562500 2929687500      25% /mnt/disk2
shfs            7812500000 2929687500 4882812500      38% /mnt/user
/dev/loop2        20971520    5242880   15728640      25% /var/lib/docker`,
			mounts: `rootfs / rootfs rw 0 0
/dev/sda1 /boot vfat rw 0 0
/dev/md1p1 /mnt/disk1 xfs rw 0 0
/dev/md2p1 /mnt/disk2 xfs rw 0 0
shfs /mnt/user fuse.shfs rw 0 0
/dev/loop2 /var/lib/docker btrfs rw 0 0`,
			wantTotal: "7.3T", wantUsed: "2.8T", wantFree: "4.6T", wantPct: 38,
		},
		{
			name: "TrueNAS: ZFS gộp theo pool, dung lượng trống không cộng lặp",
			df: `Filesystem             1024-blocks     Used  Available Capacity Mounted on
boot-pool/ROOT/24.04      20000000  3000000   17000000      15% /
tank                    1000000000 100000000 900000000     10% /mnt/tank
tank/media              1100000000 200000000 900000000     19% /mnt/tank/media
tank/my data            1000000000 100000000 900000000     10% /mnt/tank/my data`,
			mounts: `boot-pool/ROOT/24.04 / zfs rw 0 0
tank /mnt/tank zfs rw 0 0
tank/media /mnt/tank/media zfs rw 0 0
tank/my\040data /mnt/tank/my\040data zfs rw 0 0`,
			// boot-pool: 3M + 17M; tank: 400M used + 900M avail
			wantTotal: "1.3T", wantUsed: "385G", wantFree: "875G", wantPct: 31,
		},
		{
			name: "Container overlay: không có ổ thật → dùng /",
			df: `Filesystem     1024-blocks    Used Available Capacity Mounted on
overlay           41152736 10485760  28550000      27% /
tmpfs                65536        0     65536       0% /dev`,
			mounts: `overlay / overlay rw 0 0
tmpfs /dev tmpfs rw 0 0`,
			wantTotal: "40G", wantUsed: "10G", wantFree: "28G", wantPct: 27,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			total, used, avail, pct := parseDiskUsage(c.df, c.mounts)
			if total != c.wantTotal || used != c.wantUsed || avail != c.wantFree || pct != c.wantPct {
				t.Fatalf("got %s/%s/%s %.0f%%, want %s/%s/%s %.0f%%",
					total, used, avail, pct, c.wantTotal, c.wantUsed, c.wantFree, c.wantPct)
			}
		})
	}
}

func TestParseDiskUsageEmpty(t *testing.T) {
	if total, _, _, _ := parseDiskUsage("", ""); total != "N/A" {
		t.Fatalf("total = %q, want N/A", total)
	}
}

func TestHumanKB(t *testing.T) {
	cases := map[uint64]string{
		0:                  "0",
		512:                "512K",
		1024:               "1.0M",
		1536:               "1.5M",
		10 * 1024 * 1024:   "10G",
		1023 * 1024 * 1024: "1023G",
		1024*1024*1024 - 1: "1.0T",
		41152736:           "40G",
	}
	for kb, want := range cases {
		if got := humanKB(kb); got != want {
			t.Errorf("humanKB(%d) = %q, want %q", kb, got, want)
		}
	}
}

const netDevSample = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999 10 0 0 0 0 0 0 9999 10 0 0 0 0 0 0
  eth0: 1000 10 0 0 0 0 0 0 2000 10 0 0 0 0 0 0
  eth1: 3000 10 0 0 0 0 0 0 4000 10 0 0 0 0 0 0
 bond0: 4000 20 0 0 0 0 0 0 6000 20 0 0 0 0 0 0
   br0: 4000 20 0 0 0 0 0 0 6000 20 0 0 0 0 0 0
docker0: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0`

func TestParseNetDev(t *testing.T) {
	rx, tx := parseNetDev(netDevSample, map[string]bool{"eth0": true, "eth1": true})
	if rx != 4000 || tx != 6000 {
		t.Fatalf("card vật lý: rx=%d tx=%d, want 4000/6000", rx, tx)
	}
	// Không đọc được /sys/class/net (container) → cộng tất cả trừ lo
	rx, tx = parseNetDev(netDevSample, nil)
	if rx != 12500 || tx != 18500 {
		t.Fatalf("fallback: rx=%d tx=%d, want 12500/18500", rx, tx)
	}
}

const diskStatsSample = `   8       0 sda 100 0 1000 0 100 0 2000 0 0 0 0
   8       1 sda1 50 0 500 0 50 0 1000 0 0 0 0
 259       0 nvme0n1 10 0 300 0 10 0 400 0 0 0 0
 259       1 nvme0n1p1 10 0 300 0 10 0 400 0 0 0 0
   9       0 md0 90 0 900 0 90 0 1900 0 0 0 0
 253       0 dm-0 90 0 900 0 90 0 1900 0 0 0 0
   7       0 loop0 5 0 50 0 0 0 0 0 0 0 0`

func TestParseDiskStats(t *testing.T) {
	r, w := parseDiskStats(diskStatsSample, map[string]bool{"sda": true, "nvme0n1": true, "loop0": false})
	if r != 1300 || w != 2400 {
		t.Fatalf("ổ vật lý: r=%d w=%d, want 1300/2400", r, w)
	}
	// Không có /sys/block → nhận diện theo tên, bỏ phân vùng/md/dm/loop
	r, w = parseDiskStats(diskStatsSample, nil)
	if r != 1300 || w != 2400 {
		t.Fatalf("fallback: r=%d w=%d, want 1300/2400", r, w)
	}
}

func TestParseOSInfo(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"Synology", "@@/etc.defaults/VERSION\nmajorversion=\"7\"\nminorversion=\"2\"\nproductversion=\"7.2.1\"\nbuildnumber=\"69057\"\n@@/etc/os-release\nPRETTY_NAME=\"Linux\"\n", "Synology DSM 7.2.1-69057"},
		{"QNAP QTS", "@@qnap\n5.1.4\n20231128\n", "QNAP QTS 5.1.4 (20231128)"},
		{"QNAP QuTS hero", "@@qnap\nh5.1.2\n", "QNAP QuTS hero h5.1.2"},
		{"Unraid", "@@/etc/unraid-version\nversion=\"6.12.4\"\n@@/etc/os-release\nNAME=Slackware\n", "Unraid OS 6.12.4"},
		{"TrueNAS SCALE", "@@/etc/os-release\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n@@truenas\n24.04.2\n", "TrueNAS 24.04.2"},
		{"OpenMediaVault", "@@/etc/os-release\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n@@omv\n7.4.3-1\n", "OpenMediaVault 7.4.3-1"},
		{"Ubuntu", "@@/etc/os-release\nNAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n", "Ubuntu 24.04.1 LTS"},
		{"Chỉ NAME+VERSION", "@@/usr/lib/os-release\nNAME='Alpine Linux'\nVERSION=3.20\n", "Alpine Linux 3.20"},
		{"CentOS 6", "@@/etc/redhat-release\nCentOS release 6.10 (Final)\n", "CentOS release 6.10 (Final)"},
		{"Không có gì", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseOSInfo(c.in); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseCPUModel(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"x86", "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n@@lscpu\nModel name:  Intel Xeon\n@@dt\n\n", "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"},
		{"aarch64 (Graviton) qua lscpu", "@@lscpu\nModel name:                      Neoverse-N1\n@@dt\n\n", "Neoverse-N1"},
		{"lscpu '-' → device-tree", "@@lscpu\nModel name: -\n@@dt\nRaspberry Pi 4 Model B Rev 1.4\x00\n", "Raspberry Pi 4 Model B Rev 1.4"},
		{"Raspberry Pi cpuinfo", "Hardware\t: BCM2835\nModel\t\t: Raspberry Pi 3 Model B Rev 1.2\n@@lscpu\n@@dt\n", "BCM2835"},
		{"MIPS", "cpu model\t\t: MIPS 1004Kc V2.15\n@@lscpu\n@@dt\n", "MIPS 1004Kc V2.15"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseCPUModel(c.in); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestCalculateCPUPercentClamp(t *testing.T) {
	// iowait giảm giữa 2 lần đọc → không được tràn số / vượt 100%
	prev := CPUStats{Total: 1000, Idle: 500, IOWait: 200}
	curr := CPUStats{Total: 1100, Idle: 650, IOWait: 150}
	if got := calculateCPUPercent(prev, curr); got < 0 || got > 100 {
		t.Fatalf("got %v, want trong [0,100]", got)
	}
	curr = CPUStats{Total: 1100, Idle: 550, IOWait: 200}
	if got := calculateCPUPercent(prev, curr); got != 50 {
		t.Fatalf("got %v, want 50", got)
	}
}
