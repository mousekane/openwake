package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DDNS：仅 Cloudflare API Token。A 记录 = 公网 IPv4，AAAA = 公网 IPv6，
// 强制 proxied=false：Cloudflare 只代理 HTTP(S) 标准端口，5155 走代理反而
// 不通，且页面要直连宿主机，所以必须是 DNS only。

const cfAPI = "https://api.cloudflare.com/client/v4"

var httpClient = &http.Client{Timeout: 20 * time.Second}

type ddnsState struct {
	mu          sync.RWMutex
	IPv4        string `json:"ipv4"`
	IPv6        string `json:"ipv6"`
	LastUpdate  string `json:"last_update"`
	LastError   string `json:"last_error"`
	LastSuccess string `json:"last_success"`
}

var ddns = &ddnsState{}

func getPublicIP(v6 bool) (string, error) {
	urls := []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip"}
	if v6 {
		urls = []string{"https://api64.ipify.org", "https://ipv6.icanhazip.com", "https://ifconfig.me/ip"}
	}
	var lastErr error
	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		if v6 {
			// api64 在纯 v4 环境会失败，靠下一个源兜底
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if ip != "" && !strings.Contains(ip, "<") {
			return ip, nil
		}
		lastErr = fmt.Errorf("empty response from %s", u)
	}
	return "", lastErr
}

type cfResp struct {
	Success bool            `json:"success"`
	Errors  []any           `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

func cfRequest(token, method, path string, body any) (json.RawMessage, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cfAPI+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var cr cfResp
	if err := json.Unmarshal(b, &cr); err != nil {
		return nil, fmt.Errorf("cloudflare bad response: %s", string(b))
	}
	if !cr.Success {
		return nil, fmt.Errorf("cloudflare error: %s", string(b))
	}
	return cr.Result, nil
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func cfFindZone(token, domain string) (string, error) {
	// 逐级试 zone 名：a.b.example.com -> example.com, b.example.com...
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		zone := strings.Join(parts[i:], ".")
		// 至少保留两段
		if len(parts)-i < 2 {
			break
		}
		raw, err := cfRequest(token, "GET", "/zones?name="+zone, nil)
		if err != nil {
			continue
		}
		var zones []cfZone
		if err := json.Unmarshal(raw, &zones); err == nil && len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("zone not found for %s (token 需要 Zone:DNS:Edit 且域名已托管在该账号)", domain)
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func cfUpsert(token, zoneID, domain, rtype, ip string) error {
	raw, err := cfRequest(token, "GET", fmt.Sprintf("/zones/%s/dns_records?name=%s&type=%s", zoneID, domain, rtype), nil)
	if err != nil {
		return err
	}
	var recs []cfRecord
	_ = json.Unmarshal(raw, &recs)
	body := map[string]any{
		"type": rtype, "name": domain, "content": ip, "ttl": 120, "proxied": false,
	}
	if len(recs) == 0 {
		_, err = cfRequest(token, "POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), body)
		return err
	}
	_, err = cfRequest(token, "PUT", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recs[0].ID), body)
	return err
}

// runDDNSOnce 执行一次：两个开关独立，v4/v6 任一失败不影响另一个的结果记录。
func runDDNSOnce() {
	c := getConfig()
	if !c.DDNS.Enabled || c.DDNS.Token == "" || c.DDNS.Domain == "" {
		return
	}
	var errs []string
	if c.DDNS.EnableV4 {
		if ip, err := getPublicIP(false); err == nil {
			ddns.mu.Lock()
			ddns.IPv4 = ip
			ddns.mu.Unlock()
			if zoneID, err := cfFindZone(c.DDNS.Token, c.DDNS.Domain); err == nil {
				if err := cfUpsert(c.DDNS.Token, zoneID, c.DDNS.Domain, "A", ip); err != nil {
					errs = append(errs, "A: "+err.Error())
				}
			} else {
				errs = append(errs, err.Error())
			}
		} else {
			errs = append(errs, "IPv4 探测失败: "+err.Error())
		}
	}
	if c.DDNS.EnableV6 {
		if ip, err := getPublicIP(true); err == nil {
			ddns.mu.Lock()
			ddns.IPv6 = ip
			ddns.mu.Unlock()
			if zoneID, err := cfFindZone(c.DDNS.Token, c.DDNS.Domain); err == nil {
				if err := cfUpsert(c.DDNS.Token, zoneID, c.DDNS.Domain, "AAAA", ip); err != nil {
					errs = append(errs, "AAAA: "+err.Error())
				}
			} else {
				errs = append(errs, err.Error())
			}
		} else {
			errs = append(errs, "IPv6 探测失败: "+err.Error())
		}
	}
	ddns.mu.Lock()
	ddns.LastUpdate = time.Now().Format("2006-01-02 15:04:05")
	if len(errs) == 0 {
		ddns.LastError = ""
		ddns.LastSuccess = ddns.LastUpdate
	} else {
		ddns.LastError = strings.Join(errs, "; ")
	}
	ddns.mu.Unlock()
}

func ddnsLoop() {
	// 启动后先跑一次，再按间隔跑；配置变更后手动刷新走 runDDNSOnce，不重启循环。
	runDDNSOnce()
	for {
		c := getConfig()
		interval := c.DDNS.IntervalSec
		if interval < 60 {
			interval = 300
		}
		time.Sleep(time.Duration(interval) * time.Second)
		runDDNSOnce()
	}
}
