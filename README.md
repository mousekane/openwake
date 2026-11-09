# OpenWake

OpenWrt Docker 程序：DDNS + Wake-on-LAN + SSH 开关机，全部收进一个 5155 管理页。

## v1.2 双端口分工（重要）

- **5155 管理页（仅内网）**：有密码登录、有全部设置。内网直接访问 `http://<OpenWrt-IP>:5155`，页面顶部有提示：外网访问请转发端口 5055，内网访问请直接访问 5155。
- **5055 外网操作页（仅外网转发）**：无密码、无设置内容，深色霓虹双大圆环：顶部居中 Logo + OpenWake（上边距 36px、下边距 38px），上面是电脑大圆环（环里 PC，环下方 NOW: ON 绿色 / OFF 灰色，绿呼吸 = 开机、红 = 关机，点它弹开机/关机确认），下面是路由器大圆环（环里 OP，环下方永远是绿色 NOW: ON——OpenWrt 关了本页根本打不开，所以没有 OFF 状态，点它弹 OP关机确认）。没有一键重启（重启只在 5155 管理页），确认弹窗上方小字“请确认”、中间大字是动作本身、下面是取消/确认。支持保存到手机桌面：名称 OpenWake，绿色电源图标（favicon / apple-touch-icon / PWA manifest 齐全）。v1.2.1：圆环里的电源图标改用内联 SVG（之前用的 ⏻ 字符在部分安卓手机浏览器上不显示，还会把 PC/OP 文字顶到圆环底部）。
- **路由器只转发 5055，不要转发 5155。** 这就是 5155 仅限内网的实现方式：不转发，外网就到不了 5155。
- 安全提醒（请先认清再用 5055）：5055 无密码，知道域名的人点确认就能关机/关 OpenWrt，确认弹窗不是身份验证。公开页不返回任何配置、IP/MAC、Token/密码，不开放跨域请求，同一动作 5 秒内只放行一次。域名不要公开传播。

| 需求 | 实现 |
|---|---|
| 01 DDNS（IPv4 + IPv6，仅 Cloudflare API Token） | A / AAAA 记录独立开关，Token 权限 Zone:DNS:Edit，记录强制 DNS only，公网 IP 多源探测，默认 300 秒一轮 |
| 02 Wake-on-LAN | 魔术包（FF×6 + MAC×16）发往配置广播地址 + 255.255.255.255 + /24 广播，端口 9 和 7 双发 |
| 03 SSH 连局域网 Win PC | OpenSSH 直连，`shutdown /s /f /t 0` 关机、`shutdown /r /f /t 0` 重启，密码或私钥二选一 |
| 04 HTTP(S) 管理页，端口 5155，网址指向 DDNS 网址 | 内网 `http(s)://<内网IP>:5155`（管理），外网 `http(s)://<DDNS域名>:5055`（操作页，无密码无设置）；http 默认，https 可用自带证书或自动生成自签名证书 |
| a 绑定 Win PC 开关机状态 | 每 15 秒 ping + 3389/445/135/22 端口探测，页面实时轮询 |
| b 一键开机 Win PC | WOL |
| c 一键关机 Win PC | SSH |
| d 一键重启 Win PC | SSH |
| e 一键关机 OpenWrt | SSH 到宿主机执行 `poweroff`（二次确认） |

额外加了一层本该有的东西：**管理页登录密码**。否则 DDNS 域名一公开，任何人都能远程关你的电脑。首次打开页面先设密码（bcrypt 存于容器内 `/data/config.json`），之后所有开关机接口都要登录态。

## v1.3 Agent API（供 AI 调用）

为 AI agent 接管预留的版本化接口，挂在 **5055 公网入口**，路径 `/api/v1/agent/*`，全部要求 `Authorization: Bearer <密钥>`。无密钥时接口返回 503（未启用），密钥错误返回 401。统一返回 `{"ok":bool, "data"/"message", "error"}`；写操作同一目标同一动作 5 秒冷却，全部记审计日志（最近 100 条，管理页可见，也可调接口查）。

密钥在 5155 管理页“Agent API”卡片里生成、吊销：生成即轮换旧密钥，**新密钥只显示一次**，请立即复制保存。密钥等同于整机开关机权限，泄露立即轮换。

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/v1/agent/health` | GET | 健康检查，返回版本号 |
| `/api/v1/agent/status` | GET | 全部 PC 开关机状态 + OP 状态（不返回 IP/MAC/主机地址） |
| `/api/v1/agent/audit` | GET | 最近 Agent 操作审计记录 |
| `/api/v1/agent/pc/{id}/wake` | POST | 发送 WOL 魔术包 |
| `/api/v1/agent/pc/{id}/shutdown` | POST | SSH 关机 Win PC |
| `/api/v1/agent/pc/{id}/restart` | POST | SSH 重启 Win PC（公开页没有这个，agent 有） |
| `/api/v1/agent/openwrt/poweroff` | POST | SSH 关机 OpenWrt |
| `/api/v1/agent/ddns/refresh` | POST | 立即刷新一次 DDNS |

示例（把 `KEY` 换成你生成的密钥，域名换成你自己的）：

```bash
curl -H "Authorization: Bearer KEY" http://openwake.555554444.xyz:5055/api/v1/agent/status
curl -X POST -H "Authorization: Bearer KEY" http://openwake.555554444.xyz:5055/api/v1/agent/pc/pc1/wake
```

安全提醒：agent 接口和 5055 操作页共用一个公网入口，安全全靠 Bearer 密钥守。**不要把密钥写进公开仓库、聊天记录或交给不可信的 agent**；密钥只给受信任的 agent。5155 管理页依然不转发，只走内网。

## v1.4 MCP Server（供只认 MCP 的 agent）

REST API 只有具备 HTTP 调用能力的 agent 能直接调；Claude Desktop、Cherry Studio 等只认 MCP 的 agent 需要一个 MCP Server。v1.4 把 MCP Server 直接做进 OpenWake，包同一批能力、同一把密钥，不用另起服务。

- 地址：`http://<DDNS域名>:5055/mcp`，走 Streamable HTTP（无状态，每次 POST 直接回 JSON-RPC 响应）
- 认证：请求头 `Authorization: Bearer <密钥>`，与 v1.3 同一把密钥；未生成密钥时返回 503，密钥错误返回 401
- 工具（8 个，与 REST 接口一一对应）：`openwake_health`、`openwake_status`、`openwake_audit`、`openwake_pc_wake`、`openwake_pc_shutdown`、`openwake_pc_restart`、`openwake_openwrt_poweroff`、`openwake_ddns_refresh`；写操作同样 5 秒冷却并记审计日志

支持远程 MCP 的客户端（如 Cherry Studio），直接填地址 + 请求头就能接管：

```json
{
  "mcpServers": {
    "openwake": {
      "url": "http://openwake.555554444.xyz:5055/mcp",
      "headers": { "Authorization": "Bearer 你的密钥" }
    }
  }
}
```

只支持本地 stdio 的客户端（如旧版 Claude Desktop），用桥接工具转接，例如：

```bash
npx -y mcp-remote http://openwake.555554444.xyz:5055/mcp --header "Authorization: Bearer 你的密钥"
```

两种接入方式的能力、认证、审计完全一致：REST 给能发 HTTP 的 agent，MCP 给只认 MCP 的 agent。

## 一键部署（OpenWrt / Linux Docker）

```sh
curl -fsSL https://raw.githubusercontent.com/mousekane/openwake/main/install.sh | sh
# 之后打开 http://<OpenWrt-IP>:5155，首次设置管理密码
```

或手动：

```sh
mkdir -p /opt/openwake && cd /opt/openwake
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/mousekane/openwake/main/docker-compose.yml
docker compose pull && docker compose up -d
```

更新：`docker compose pull && docker compose up -d`

镜像：`ghcr.io/mousekane/openwake:latest`，多架构 `linux/amd64, linux/arm64, linux/arm/v7`，由 GitHub Actions 自动构建推送（`.github/workflows/docker.yml`）。

## 最关键的一条：必须用 host 网络

`docker-compose.yml` 已默认 `network_mode: host`，不要改成桥接。

原因：WOL 魔术包是局域网广播，桥接网络的广播到不了局域网，WOL 一定失败；host 模式下容器与宿主机同网段，广播、ping、网关探测才都正常。host 模式下 `ports` 段无效，服务直接占宿主机 5155 + 5055。

## 部署后配置（页面里填，不用改 compose）

1. **DDNS**：填 Cloudflare API Token + 域名（如 `wake.example.com`）。
   Token 在 Cloudflare 后台建：My Profile → API Tokens → Create Token，权限 `Zone → DNS → Edit`，限定到该域名所在 Zone。域名须已托管在该 Cloudflare 账号。
   记录强制 `proxied=false`：Cloudflare 只代理标准 HTTP(S) 端口，5155 走代理反而不同，且页面要直连宿主机。
2. **Win PC**：填 IP、MAC、SSH 用户名/密码（或私钥）。
   PC 端先做一次：设置 → 应用 → 可选功能 → 添加 **OpenSSH 服务器**，服务设自动启动，防火墙放行 22 端口，用管理员账号。
   开机前置：BIOS 开 Wake-on-LAN、网卡属性开“允许此设备唤醒计算机”，并**关闭 Windows 快速启动**（快速启动下关机是混合休眠，WOL 常失效）。
3. **OpenWrt 关机**：宿主机 IP 留空时自动取容器默认网关（host 模式下即 OpenWrt 本身），填 root + 密码/私钥。
4. **路由器转发**：只把 `5055` 转发到 OpenWrt，不要转发 `5155`，外网操作地址即 `http(s)://<DDNS域名>:5055`，内网管理地址是 `http://<OpenWrt-IP>:5155`。
   外网访问务必开 HTTPS：页面配置里把协议切到 `https`，无证书时自动生成自签名证书（浏览器会提示不安全，点继续即可；要去掉提示就把正式证书放到 `/data/cert.pem` + `/data/key.pem` 并重启）。

## 本地开发

```sh
go build -o openwake .
OW_DATA_DIR=./data ./openwake   # 打开 http://127.0.0.1:5155
```

## 目录结构

```
main.go / config.go   配置与持久化（/data/config.json）
ddns.go               Cloudflare DDNS（A/AAAA 独立）
wol.go                魔术包构造与广播发送
ssh.go                SSH 执行 + ping/端口状态探测
web.go                HTTP API + 登录态 + TLS（自签名兜底）
web/index.html        管理页（无构建步骤，纯 HTML/JS）
Dockerfile            多架构静态编译，alpine 运行时
docker-compose.yml    host 网络一键部署
install.sh            一键拉取部署脚本
```

## 排错速查

| 现象 | 先查 |
|---|---|
| WOL 发了但 PC 不开机 | 容器是不是 host 网络；BIOS/网卡 WOL；快速启动关了没；MAC 对不对；PC 是真关机还是休眠 |
| SSH 关机失败 | PC 的 OpenSSH 服务在跑吗；22 端口防火墙；账号是不是管理员；密码/私钥对不对 |
| DDNS 不更新 | Token 权限是不是 Zone:DNS:Edit 且 Zone 对；域名托管在该账号吗；页面 DDNS 错误栏写了什么 |
| 外网打不开 5055 | 路由器 5055 转发到 OpenWrt 了吗；DDNS 解析到的 IP 是不是当前公网 IP；记录是不是 DNS only；注意外网不要用 5155，那是内网管理口 |
| OpenWrt 关机按钮没反应 | 宿主机 SSH 能连吗（root 密码/私钥）；容器是不是 host 网络（网关探测才准） |

## 安全提醒

- 配置文件 `/data/config.json` 含 SSH 密码和 Cloudflare Token，只存在容器数据卷里，不要公开分享该目录。
- 不要把 5155 以外、或本服务以外的端口一并暴露；管理页密码不要与 PC/路由器密码复用。
- SSH HostKey 本服务不做严格校验（家用 LAN 内重装换 key 频繁），前提是只在可信局域网内使用。
