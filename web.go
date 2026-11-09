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

// 外网操作页（5055）专用资源：与管理页完全分开的 handler，只挂这些文件。
//
//go:embed web/public.html
var publicHTML []byte

//go:embed web/icon.svg
var iconSVG []byte

//go:embed web/icon-192.png
var icon192 []byte

//go:embed web/icon-512.png
var icon512 []byte

//go:embed web/apple-touch-icon.png
var appleTouchIcon []byte

//go:embed web/manifest.webmanifest
var manifestJSON []byte

const appVersion = "1.5.0"

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
		writeJSON(w, 200, map[string]any{"ok": true, "version": appVersion})
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
			"port": c.Port, "public_port": c.PublicPort, "tls_mode": c.TLSMode,
			// 管理页 access_url 改为外网操作页：外网请走 DDNS:5055，内网请直接走 内网IP:5155
			"access_url": func() string {
				if c.DDNS.Domain != "" {
					scheme := "http"
					if c.TLSMode == "https" {
						scheme = "https"
					}
					return fmt.Sprintf("%s://%s:%d", scheme, c.DDNS.Domain, c.PublicPort)
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
			Port       int    `json:"port"`
			PublicPort int    `json:"public_port"`
			TLSMode    string `json:"tls_mode"`
			DDNS       struct {
				Enabled     bool   `json:"enabled"`
				Token       string `json:"token"`
				TokenChange bool   `json:"token_change"`
				Domain      string `json:"domain"`
				EnableV4    bool   `json:"enable_v4"`
				EnableV6    bool   `json:"enable_v6"`
				IntervalSec int    `json:"interval_sec"`
			} `json:"ddns"`
			PCs []struct {
				ID             string `json:"id"`
				Name           string `json:"name"`
				IP             string `json:"ip"`
				MAC            string `json:"mac"`
				BroadcastIP    string `json:"broadcast_ip"`
				SSHUser        string `json:"ssh_user"`
				SSHPassword    string `json:"ssh_password"`
				PasswordChange bool   `json:"password_change"`
				SSHKey         string `json:"ssh_key"`
				KeyChange      bool   `json:"key_change"`
				SSHPort        int    `json:"ssh_port"`
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
		if in.PublicPort != 0 {
			cfg.PublicPort = in.PublicPort
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

var (
	tlsCertFile, tlsKeyFile string
	tlsPrepared             bool
)

// prepareTLS 只在启动时跑一次，避免管理口和外网口同时生成自签名证书竞态。
func prepareTLS() error {
	c := getConfig()
	if c.TLSMode != "https" || tlsPrepared {
		return nil
	}
	certFile, keyFile, err := ensureTLS(c.DDNS.Domain)
	if err != nil {
		return err
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return err
	}
	tlsCertFile, tlsKeyFile, tlsPrepared = certFile, keyFile, true
	return nil
}

func serve() error {
	c := getConfig()
	addr := fmt.Sprintf(":%d", c.Port)
	srv := &http.Server{Addr: addr, Handler: routes()}
	if c.TLSMode == "https" {
		fmt.Printf("OpenWake management listening on https://0.0.0.0:%d (LAN only: router forwards only %d)\n", c.Port, c.PublicPort)
		return srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
	}
	fmt.Printf("OpenWake management listening on http://0.0.0.0:%d (LAN only: router forwards only %d)\n", c.Port, c.PublicPort)
	return srv.ListenAndServe()
}

func servePublic() error {
	c := getConfig()
	addr := fmt.Sprintf(":%d", c.PublicPort)
	srv := &http.Server{Addr: addr, Handler: publicRoutes()}
	if c.TLSMode == "https" {
		fmt.Printf("OpenWake public listening on https://0.0.0.0:%d (no password, no settings)\n", c.PublicPort)
		return srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
	}
	fmt.Printf("OpenWake public listening on http://0.0.0.0:%d (no password, no settings)\n", c.PublicPort)
	return srv.ListenAndServe()
}

// ---- 外网操作页（5055）：无密码、无设置，与管理页彻底隔离 ----
// 只挂：首页、图标/manifest、公开状态、PC 开机/关机（点大圆环切换，无重启按钮）+ OP 关机。
// 刻意不挂：/api/config、/api/login、/api/me、/api/status（完整版）、/api/ddns/*，
// 也不返回 PC 的 IP/MAC、OpenWrt 的 IP、任何 Token/密码。其他路径一律 404。
// 加固（不改变“无密码”体验）：POST 要求同源（Origin 与请求 Host 同域名时才放行，
// 跨站页面无法直接发请求）、不设 CORS 头、同一目标同一动作 5 秒内只放行一次防连点。

var (
	publicActionMu   sync.Mutex
	publicActionLast = map[string]time.Time{}
)

func publicPostGuard(w http.ResponseWriter, r *http.Request, key string) bool {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "method"})
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		// Origin 形如 https://example.com:5055，取 host 部分与请求 Host 的 host 部分比对（忽略端口）
		oh := origin
		if i := strings.Index(oh, "://"); i >= 0 {
			oh = oh[i+3:]
		}
		if i := strings.Index(oh, "/"); i >= 0 {
			oh = oh[:i]
		}
		oh, _, _ = strings.Cut(oh, ":")
		rh, _, _ := strings.Cut(r.Host, ":")
		if oh != "" && rh != "" && oh != rh {
			writeJSON(w, 403, map[string]any{"error": "跨站请求被拒绝"})
			return false
		}
	}
	publicActionMu.Lock()
	defer publicActionMu.Unlock()
	if last, ok := publicActionLast[key]; ok && time.Since(last) < 5*time.Second {
		writeJSON(w, 429, map[string]any{"error": "操作太频繁，请稍后再试"})
		return false
	}
	publicActionLast[key] = time.Now()
	return true
}

func publicRoutes() http.Handler {
	mux := http.NewServeMux()
	serveBytes := func(b []byte, ct string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Cache-Control", "public, max-age=86400")
			_, _ = w.Write(b)
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(publicHTML)
	})
	mux.HandleFunc("/manifest.webmanifest", serveBytes(manifestJSON, "application/manifest+json"))
	mux.HandleFunc("/icon.svg", serveBytes(iconSVG, "image/svg+xml"))
	mux.HandleFunc("/icon-192.png", serveBytes(icon192, "image/png"))
	mux.HandleFunc("/icon-512.png", serveBytes(icon512, "image/png"))
	mux.HandleFunc("/apple-touch-icon.png", serveBytes(appleTouchIcon, "image/png"))
	mux.HandleFunc("/favicon.ico", serveBytes(icon192, "image/png"))
	mux.HandleFunc("/api/public/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "version": appVersion})
	})
	// 公开状态：只给名字和开关机状态，不给 IP/MAC/主机地址
	mux.HandleFunc("/api/public/status", func(w http.ResponseWriter, r *http.Request) {
		statusMu.RLock()
		pcs := pcStatuses
		owOn := owOnline
		statusMu.RUnlock()
		if pcs == nil {
			pcs = []pcStatus{}
		}
		out := make([]map[string]any, 0, len(pcs))
		for _, p := range pcs {
			out = append(out, map[string]any{"id": p.ID, "name": p.Name, "online": p.Online})
		}
		writeJSON(w, 200, map[string]any{"pcs": out, "openwrt": map[string]any{"online": owOn}})
	})
	mux.HandleFunc("/api/public/pc/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/public/pc/"), "/")
		if len(parts) != 2 {
			writeJSON(w, 404, map[string]any{"error": "not found"})
			return
		}
		if !publicPostGuard(w, r, "pc:"+parts[0]+":"+parts[1]) {
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
			msg = "魔术包已发送"
		case "shutdown":
			err = windowsShutdown(*pc)
			msg = "关机命令已发送"
		default:
			// v1.2：外网页已删一键重启，公开接口也不再接受 restart（重启只在 5155 管理页，登录后可用）
			writeJSON(w, 404, map[string]any{"error": "未知动作"})
			return
		}
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		go func() { time.Sleep(3 * time.Second); refreshStatuses() }()
		writeJSON(w, 200, map[string]any{"ok": true, "message": msg})
	})
	mux.HandleFunc("/api/public/openwrt/poweroff", func(w http.ResponseWriter, r *http.Request) {
		if !publicPostGuard(w, r, "openwrt:poweroff") {
			return
		}
		if err := openWrtPoweroff(getConfig()); err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "message": "OpenWrt 关机命令已发送"})
	})

	return mux
}
