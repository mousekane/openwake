package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed web/index.html
var indexHTML []byte

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func checkPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func authed(r *http.Request) bool {
	c, err := r.Cookie("ow_session")
	if err != nil {
		return false
	}
	sessionMu.Lock()
	defer sessionMu.Unlock()
	return sessions[c.Value]
}

func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if getConfig().AdminHash == "" {
		return true // 未设密码前只允许 setup 流程，前端会引导
	}
	if !authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录"})
		return false
	}
	return true
}

// ---- 状态缓存：每 15 秒后台刷新一次，页面秒开，不用每次点按钮都等 ping 超时 ----
type pcStatus struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Online   bool   `json:"online"`
	Method   string `json:"method"`
	LastSeen string `json:"last_seen"`
}

var (
	statusMu     sync.RWMutex
	pcStatuses   []pcStatus
	owOnline     bool
	owMethod     string
	owLastUpdate string
)

func refreshStatuses() {
	c := getConfig()
	var list []pcStatus
	for _, pc := range c.PCs {
		online, method := hostOnline(pc.IP)
		st := pcStatus{ID: pc.ID, Name: pc.Name, IP: pc.IP, MAC: pc.MAC, Online: online, Method: method}
		if online {
			st.LastSeen = time.Now().Format("15:04:05")
		}
		list = append(list, st)
	}
	owHost := openWrtHost(c)
	online, method := hostOnline(owHost)
	statusMu.Lock()
	pcStatuses = list
	owOnline, owMethod = online, method
	owLastUpdate = time.Now().Format("15:04:05")
	statusMu.Unlock()
	// 把本次在线结果回填 last_seen：简单做法是保留上一次的 LastSeen
	_ = owHost
}

func statusLoop() {
	refreshStatuses()
	for range time.Tick(15 * time.Second) {
		refreshStatuses()
	}
}

func findPC(c *Config, id string) *PCConfig {
	for i := range c.PCs {
		if c.PCs[i].ID == id {
			return &c.PCs[i]
		}
	}
	return nil
}

func routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "version": "1.0.0"})
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		c := getConfig()
		writeJSON(w, 200, map[string]any{
			"needs_setup": c.AdminHash == "", "authed": authed(r),
		})
	})
	mux.HandleFunc("/api/setup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]any{"error": "method"})
			return
		}
		if getConfig().AdminHash != "" {
			writeJSON(w, 400, map[string]any{"error": "已设置过密码，请登录"})
			return
		}
		var in struct {
			Password string `json:"password"`
		}
		if err := readJSON(r, &in); err != nil || len(in.Password) < 4 {
			writeJSON(w, 400, map[string]any{"error": "密码至少 4 位"})
			return
		}
		h, _ := hashPassword(in.Password)
		cfgMu.Lock()
		cfg.AdminHash = h
		_ = saveConfigLocked()
		cfgMu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]any{"error": "method"})
			return
		}
		var in struct {
			Password string `json:"password"`
		}
		_ = readJSON(r, &in)
		if !checkPassword(getConfig().AdminHash, in.Password) {
			writeJSON(w, 401, map[string]any{"error": "密码错误"})
			return
		}
		tok := newSessionToken()
		sessionMu.Lock()
		sessions[tok] = true
		sessionMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "ow_session", Value: tok, Path: "/", MaxAge: 7 * 24 * 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("ow_session"); err == nil {
			sessionMu.Lock()
			delete(sessions, c.Value)
			sessionMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "ow_session", Value: "", Path: "/", MaxAge: -1})
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		c := getConfig()
		statusMu.RLock()
		pcs := pcStatuses
		owOn, owM, owT := owOnline, owMethod, owLastUpdate
		statusMu.RUnlock()
		if pcs == nil {
			pcs = []pcStatus{}
		}
		ddns.mu.RLock()
		dIPv4, dIPv6, dUpd, dErr, dOk := ddns.IPv4, ddns.IPv6, ddns.LastUpdate, ddns.LastError, ddns.LastSuccess
		ddns.mu.RUnlock()
		writeJSON(w, 200, map[string]any{
			"pcs": pcs,
			"openwrt": map[string]any{
				"host": openWrtHost(c), "online": owOn, "method": owM, "checked_at": owT,
			},
			"ddns": map[string]any{
				"enabled": c.DDNS.Enabled, "domain": c.DDNS.Domain,
				"ipv4": dIPv4, "ipv6": dIPv6,
				"last_update": dUpd, "last_error": dErr,
				"last_success": dOk,
			},
			"port": c.Port, "tls_mode": c.TLSMode,
			"access_url": func() string {
				if c.DDNS.Domain != "" {
					scheme := "http"
					if c.TLSMode == "https" {
						scheme = "https"
					}
					return fmt.Sprintf("%s://%s:%d", scheme, c.DDNS.Domain, c.Port)
				}
				return ""
			}(),
		})
	})

	// PC 动作：POST /api/pc/{id}/{wake|shutdown|restart}
	mux.HandleFunc("/api/pc/", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) || r.Method != "POST" {
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/pc/"), "/")
		if len(parts) != 2 {
			writeJSON(w, 404, map[string]any{"error": "not found"})
			return
		}
		pc := findPC(getConfig(), parts[0])
		if pc == nil {
			writeJSON(w, 404, map[string]any{"error": "找不到该 PC"})
			return
		}
		var err error
		var msg string
		switch parts[1] {
		case "wake":
			err = sendWOL(*pc)
			msg = "魔术包已发送，等待 PC 启动（约 10-60 秒）"
		case "shutdown":
			err = windowsShutdown(*pc)
			msg = "关机命令已发送"
		case "restart":
			err = windowsRestart(*pc)
			msg = "重启命令已发送"
		default:
			writeJSON(w, 404, map[string]any{"error": "未知动作"})
			return
		}
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		// 动作后 3 秒刷新一次状态（关机/开机状态不会立刻变，前端会继续轮询）
		go func() { time.Sleep(3 * time.Second); refreshStatuses() }()
		writeJSON(w, 200, map[string]any{"ok": true, "message": msg})
	})

	mux.HandleFunc("/api/openwrt/poweroff", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) || r.Method != "POST" {
			return
		}
		if err := openWrtPoweroff(getConfig()); err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "message": "OpenWrt 关机命令已发送"})
	})

	mux.HandleFunc("/api/ddns/refresh", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) || r.Method != "POST" {
			return
		}
		go runDDNSOnce()
		writeJSON(w, 200, map[string]any{"ok": true, "message": "DDNS 刷新中，稍后查看结果"})
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		if r.Method == "GET" {
			writeJSON(w, 200, maskedConfig(getConfig()))
			return
		}
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]any{"error": "method"})
			return
		}
		var in struct {
			Port    int    `json:"port"`
			TLSMode string `json:"tls_mode"`
			DDNS    struct {
				Enabled     bool   `json:"enabled"`
				Token       string `json:"token"`
				TokenChange bool   `json:"token_change"`
				Domain      string `json:"domain"`
				EnableV4    bool   `json:"enable_v4"`
				EnableV6    bool   `json:"enable_v6"`
				IntervalSec int    `json:"interval_sec"`
			} `json:"ddns"`
			PCs []struct {
				ID              string `json:"id"`
				Name            string `json:"name"`
				IP              string `json:"ip"`
				MAC             string `json:"mac"`
				BroadcastIP     string `json:"broadcast_ip"`
				SSHUser         string `json:"ssh_user"`
				SSHPassword     string `json:"ssh_password"`
				PasswordChange  bool   `json:"password_change"`
				SSHKey          string `json:"ssh_key"`
				KeyChange       bool   `json:"key_change"`
				SSHPort         int    `json:"ssh_port"`
			} `json:"pcs"`
			OpenWrt struct {
				Host           string `json:"host"`
				User           string `json:"user"`
				Password       string `json:"password"`
				PasswordChange bool   `json:"password_change"`
				Key            string `json:"key"`
				KeyChange      bool   `json:"key_change"`
				Port           int    `json:"port"`
			} `json:"openwrt"`
			AdminPassword string `json:"admin_password"`
		}
		if err := readJSON(r, &in); err != nil {
			writeJSON(w, 400, map[string]any{"error": "配置 JSON 解析失败"})
			return
		}
		cfgMu.Lock()
		old := cfg
		if in.Port != 0 {
			cfg.Port = in.Port
		}
		if in.TLSMode == "http" || in.TLSMode == "https" {
			cfg.TLSMode = in.TLSMode
		}
		cfg.DDNS.Enabled = in.DDNS.Enabled
		if in.DDNS.TokenChange {
			cfg.DDNS.Token = in.DDNS.Token
		}
		cfg.DDNS.Domain = strings.TrimSpace(in.DDNS.Domain)
		cfg.DDNS.EnableV4 = in.DDNS.EnableV4
		cfg.DDNS.EnableV6 = in.DDNS.EnableV6
		if in.DDNS.IntervalSec >= 60 {
			cfg.DDNS.IntervalSec = in.DDNS.IntervalSec
		}
		var pcs []PCConfig
		for i, p := range in.PCs {
			if p.ID == "" {
				p.ID = fmt.Sprintf("pc%d", i+1)
			}
			if p.SSHPort == 0 {
				p.SSHPort = 22
			}
			np := PCConfig{ID: p.ID, Name: p.Name, IP: p.IP, MAC: p.MAC, BroadcastIP: p.BroadcastIP, SSHUser: p.SSHUser, SSHPort: p.SSHPort}
			// 保留旧凭据，除非前端标记改了
			for _, op := range old.PCs {
				if op.ID == p.ID {
					np.SSHPassword = op.SSHPassword
					np.SSHKey = op.SSHKey
				}
			}
			if p.PasswordChange {
				np.SSHPassword = p.SSHPassword
			}
			if p.KeyChange {
				np.SSHKey = p.SSHKey
			}
			pcs = append(pcs, np)
		}
		if len(pcs) > 0 {
			cfg.PCs = pcs
		}
		cfg.OpenWrt.Host = strings.TrimSpace(in.OpenWrt.Host)
		cfg.OpenWrt.User = in.OpenWrt.User
		if in.OpenWrt.PasswordChange {
			cfg.OpenWrt.Password = in.OpenWrt.Password
		}
		if in.OpenWrt.KeyChange {
			cfg.OpenWrt.Key = in.OpenWrt.Key
		}
		if in.OpenWrt.Port != 0 {
			cfg.OpenWrt.Port = in.OpenWrt.Port
		}
		if in.AdminPassword != "" {
			if h, err := hashPassword(in.AdminPassword); err == nil {
				cfg.AdminHash = h
			}
		}
		err := saveConfigLocked()
		cfgMu.Unlock()
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		go refreshStatuses()
		go runDDNSOnce()
		writeJSON(w, 200, map[string]any{"ok": true, "message": "已保存（改端口/TLS 需重启容器生效）"})
	})
	return mux
}

func ensureTLS(domain string) (certFile, keyFile string, err error) {
	certFile = filepath.Join(dataDir, "cert.pem")
	keyFile = filepath.Join(dataDir, "key.pem")
	if _, e1 := os.Stat(certFile); e1 == nil {
		if _, e2 := os.Stat(keyFile); e2 == nil {
			return certFile, keyFile, nil
		}
	}
	// 无证书时自动生成自签名（域名用 DDNS 域名，无域名用 openwake.local）
	host := domain
	if host == "" {
		host = "openwake.local"
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	cf, _ := os.Create(certFile)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, _ := os.Create(keyFile)
	_ = pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	kf.Close()
	return certFile, keyFile, nil
}

func serve() error {
	c := getConfig()
	addr := fmt.Sprintf(":%d", c.Port)
	srv := &http.Server{Addr: addr, Handler: routes()}
	if c.TLSMode == "https" {
		certFile, keyFile, err := ensureTLS(c.DDNS.Domain)
		if err != nil {
			return err
		}
		// 顺便校验证书能加载
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return err
		}
		fmt.Printf("OpenWake listening on https://0.0.0.0:%d\n", c.Port)
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	fmt.Printf("OpenWake listening on http://0.0.0.0:%d\n", c.Port)
	return srv.ListenAndServe()
}
