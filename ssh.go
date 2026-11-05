package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH：LAN 内可信网络，HostKey 不做严格校验（家用场景，OpenWrt/Windows
// 重装后 host key 常变，严格校验会反复卡住）。不要把本服务端口暴露给
// 公网以外的不可信网络，且管理页本身有密码登录保护。
//
// Windows 前置条件（PC 端做一次）：
//   设置 -> 应用 -> 可选功能 -> 添加 OpenSSH 服务器，服务设为自动启动，
//   防火墙放行 22 端口；关机/重启命令需要管理员账号。

func sshRun(host string, port int, user, password, keyPEM, cmd string) (string, error) {
	auth := []ssh.AuthMethod{}
	if keyPEM != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(keyPEM)); err == nil {
			auth = append(auth, ssh.PublicKeys(signer))
		} else if signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(keyPEM), []byte(password)); err == nil {
			auth = append(auth, ssh.PublicKeys(signer))
		}
	}
	if password != "" {
		auth = append(auth, ssh.Password(password))
	}
	if len(auth) == 0 {
		return "", fmt.Errorf("未配置 SSH 密码或私钥")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", fmt.Errorf("SSH 连接 %s 失败: %w（检查 PC 的 OpenSSH 服务、防火墙 22 端口、账号密码）", addr, err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out strings.Builder
	sess.Stdout = &out
	sess.Stderr = &out
	// Windows 的 shutdown 是异步返回的，命令发出即算成功，等待最多 15 秒。
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err := <-done:
		if err != nil {
			return out.String(), fmt.Errorf("远程命令执行失败: %w，输出: %s", err, out.String())
		}
		return out.String(), nil
	case <-time.After(15 * time.Second):
		return out.String(), nil
	}
}

func windowsShutdown(pc PCConfig) error {
	_, err := sshRun(pc.IP, pc.SSHPort, pc.SSHUser, pc.SSHPassword, pc.SSHKey, "shutdown /s /f /t 0")
	return err
}

func windowsRestart(pc PCConfig) error {
	_, err := sshRun(pc.IP, pc.SSHPort, pc.SSHUser, pc.SSHPassword, pc.SSHKey, "shutdown /r /f /t 0")
	return err
}

func openWrtPoweroff(c *Config) error {
	_, err := sshRun(openWrtHost(c), c.OpenWrt.Port, c.OpenWrt.User, c.OpenWrt.Password, c.OpenWrt.Key, "poweroff")
	return err
}

// pingOK：先 ping，ping 不可用时退化为 TCP 端口探测（3389/445/135/22 任一通即在线）。
func hostOnline(ip string) (bool, string) {
	if ip == "" {
		return false, "未配置 IP"
	}
	if err := exec.Command("ping", "-c", "1", "-W", "2", ip).Run(); err == nil {
		return true, "ping 通"
	}
	for _, port := range []int{3389, 445, 135, 22} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), 600*time.Millisecond)
		if err == nil {
			conn.Close()
			return true, fmt.Sprintf("端口 %d 通", port)
		}
	}
	return false, "ping 与常用端口均不通"
}
