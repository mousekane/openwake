package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// OpenWake v1.0.0 配置模型。配置文件只存在容器内 /data/config.json，
// 不要把 data 目录公开分享：里面有 PC/OpenWrt 的 SSH 凭据和 Cloudflare Token。

type PCConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	BroadcastIP string `json:"broadcast_ip"` // 为空时自动用 255.255.255.255 + IP 所在 /24 广播
	SSHUser     string `json:"ssh_user"`
	SSHPassword string `json:"ssh_password"`
	SSHKey      string `json:"ssh_key"` // PEM 私钥文本（可选，优先于密码）
	SSHPort     int    `json:"ssh_port"`
}

type SSHHostConfig struct {
	Host     string `json:"host"` // OpenWrt 宿主机 LAN IP，留空则自动取容器默认网关
	User     string `json:"user"`
	Password string `json:"password"`
	Key      string `json:"key"`
	Port     int    `json:"port"`
}

type DDNSConfig struct {
	Enabled     bool   `json:"enabled"`
	Token       string `json:"token"` // 仅 Cloudflare API Token，权限 Zone:DNS:Edit
	Domain      string `json:"domain"`
	EnableV4    bool   `json:"enable_v4"`
	EnableV6    bool   `json:"enable_v6"`
	IntervalSec int    `json:"interval_sec"`
}

type Config struct {
	AdminHash string         `json:"admin_hash"` // bcrypt，空 = 未设置，需先走 /setup
	Port      int            `json:"port"`       // 管理页：仅内网访问，路由器只转发 PublicPort，不转发本端口
	PublicPort int           `json:"public_port"` // 外网操作页：无密码、无设置，仅状态+4 个动作，路由器只转发本端口
	TLSMode   string         `json:"tls_mode"` // http | https（https 且无证书时自动生成自签名证书），两个端口共用
	DDNS      DDNSConfig     `json:"ddns"`
	PCs       []PCConfig     `json:"pcs"`
	OpenWrt   SSHHostConfig  `json:"openwrt"`
}

var (
	cfgMu     sync.RWMutex
	cfg       *Config
	cfgPath   string
	dataDir   string
	sessions  = map[string]bool{}
	sessionMu sync.Mutex
)

func dataDirFromEnv() string {
	if v := os.Getenv("OW_DATA_DIR"); v != "" {
		return v
	}
	return "/data"
}

func defaultConfig() *Config {
	return &Config{
		Port:       5155,
		PublicPort: 5055,
		TLSMode:    "http",
		DDNS: DDNSConfig{
			EnableV4: true, EnableV6: true, IntervalSec: 300,
		},
		PCs: []PCConfig{{
			ID: "pc1", Name: "Win PC", SSHPort: 22,
		}},
		OpenWrt: SSHHostConfig{User: "root", Port: 22},
	}
}

func loadConfig() *Config {
	dataDir = dataDirFromEnv()
	_ = os.MkdirAll(dataDir, 0o755)
	cfgPath = filepath.Join(dataDir, "config.json")
	c := defaultConfig()
	if b, err := os.ReadFile(cfgPath); err == nil {
		_ = json.Unmarshal(b, c)
	}
	// 环境变量只做初始填充，不覆盖已保存的页面配置（页面保存优先）。
	if v := os.Getenv("OW_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &c.Port)
	}
	if c.Port == 0 {
		c.Port = 5155
	}
	if v := os.Getenv("OW_PUBLIC_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &c.PublicPort)
	}
	if c.PublicPort == 0 {
		c.PublicPort = 5055
	}
	if v := os.Getenv("CF_TOKEN"); v != "" && c.DDNS.Token == "" {
		c.DDNS.Token = v
	}
	if v := os.Getenv("CF_DOMAIN"); v != "" && c.DDNS.Domain == "" {
		c.DDNS.Domain = v
	}
	if v := os.Getenv("OW_ADMIN_PASSWORD"); v != "" && c.AdminHash == "" {
		if h, err := hashPassword(v); err == nil {
			c.AdminHash = h
		}
	}
	if c.DDNS.IntervalSec < 60 {
		c.DDNS.IntervalSec = 300
	}
	for i := range c.PCs {
		if c.PCs[i].SSHPort == 0 {
			c.PCs[i].SSHPort = 22
		}
		if c.PCs[i].ID == "" {
			c.PCs[i].ID = fmt.Sprintf("pc%d", i+1)
		}
	}
	if c.OpenWrt.Port == 0 {
		c.OpenWrt.Port = 22
	}
	if c.OpenWrt.User == "" {
		c.OpenWrt.User = "root"
	}
	cfg = c
	return c
}

func saveConfigLocked() error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := cfgPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, cfgPath)
}

func getConfig() *Config {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	cp := *cfg
	return &cp
}

// defaultGateway 从 /proc/net/route 读默认网关（host 网络模式下就是 OpenWrt 宿主机）。
func defaultGateway() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == "00000000" {
			// 小端序十六进制，如 0101A8C0 -> 192.168.1.1
			if len(f[2]) == 8 {
				var parts [4]byte
				for i := 0; i < 4; i++ {
					var v int
					fmt.Sscanf(f[2][i*2:i*2+2], "%02x", &v)
					parts[i] = byte(v)
				}
				// route 文件是小端存储，上面按字节顺序读出来正好是反的，需倒置
				return net.IPv4(parts[3], parts[2], parts[1], parts[0]).String()
			}
		}
	}
	return ""
}

func openWrtHost(c *Config) string {
	if c.OpenWrt.Host != "" {
		return c.OpenWrt.Host
	}
	if gw := defaultGateway(); gw != "" {
		return gw
	}
	return "192.168.1.1"
}

func newSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// maskedConfig 给前端的脱敏配置：Token/密码只给“已设置”标记，不回传原文。
func maskedConfig(c *Config) map[string]any {
	pcs := make([]map[string]any, 0, len(c.PCs))
	for _, p := range c.PCs {
		pcs = append(pcs, map[string]any{
			"id": p.ID, "name": p.Name, "ip": p.IP, "mac": p.MAC,
			"broadcast_ip": p.BroadcastIP, "ssh_user": p.SSHUser,
			"ssh_password_set": p.SSHPassword != "", "ssh_key_set": p.SSHKey != "",
			"ssh_port": p.SSHPort,
		})
	}
	return map[string]any{
		"port": c.Port, "public_port": c.PublicPort, "tls_mode": c.TLSMode,
		"ddns": map[string]any{
			"enabled": c.DDNS.Enabled, "domain": c.DDNS.Domain,
			"token_set": c.DDNS.Token != "", "enable_v4": c.DDNS.EnableV4,
			"enable_v6": c.DDNS.EnableV6, "interval_sec": c.DDNS.IntervalSec,
		},
		"pcs": pcs,
		"openwrt": map[string]any{
			"host": c.OpenWrt.Host, "host_resolved": openWrtHost(c),
			"user": c.OpenWrt.User, "password_set": c.OpenWrt.Password != "",
			"key_set": c.OpenWrt.Key != "", "port": c.OpenWrt.Port,
		},
	}
}
