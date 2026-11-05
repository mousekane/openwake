package main

import (
	"fmt"
	"net"
	"strings"
)

// Wake-on-LAN：魔术包 = 6 字节 FF + MAC 重复 16 次，共 102 字节，UDP 广播。
// 关键：容器必须用 --network host（或 macvlan），桥接网络的广播到不了局域网，
// 这是 OpenWrt Docker 下 WOL 最常见的失败原因，部署文件已默认 host 模式。

func parseMAC(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", ":")
	return net.ParseMAC(s)
}

func buildMagicPacket(mac net.HardwareAddr) []byte {
	pkt := make([]byte, 6+16*6)
	for i := 0; i < 6; i++ {
		pkt[i] = 0xFF
	}
	for i := 0; i < 16; i++ {
		copy(pkt[6+i*6:], mac)
	}
	return pkt
}

func broadcastAddrs(pc PCConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	add(pc.BroadcastIP)
	add("255.255.255.255")
	if ip := net.ParseIP(pc.IP); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			// /24 广播兜底
			add(fmt.Sprintf("%d.%d.%d.255", v4[0], v4[1], v4[2]))
		}
	}
	return out
}

func sendWOL(pc PCConfig) error {
	mac, err := parseMAC(pc.MAC)
	if err != nil {
		return fmt.Errorf("MAC 格式错误（应为 AA:BB:CC:DD:EE:FF）: %w", err)
	}
	pkt := buildMagicPacket(mac)
	var lastErr error
	sent := 0
	for _, bcast := range broadcastAddrs(pc) {
		for _, port := range []int{9, 7} {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", bcast, port))
			if err != nil {
				lastErr = err
				continue
			}
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				lastErr = err
				continue
			}
			_, err = conn.Write(pkt)
			conn.Close()
			if err != nil {
				lastErr = err
			} else {
				sent++
			}
		}
	}
	if sent == 0 {
		return fmt.Errorf("魔术包全部发送失败: %v（检查容器是否为 host 网络模式）", lastErr)
	}
	return nil
}
