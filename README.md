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

## AI控制-网页POST

POST模拟点击，地址：http://<DDNS域名>:5055 接口：

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/public/health` | GET | 健康检查，返回版本号 |
| `/api/public/status` | GET | 全部 PC 开关机状态 + OP 状态（只给名字和状态，不返回 IP/MAC/主机地址） |
| `/api/public/pc/{id}/wake` | POST | 发送 WOL 魔术包 |
| `/api/public/pc/{id}/shutdown` | POST | SSH 关机 Win PC |
| `/api/public/openwrt/poweroff` | POST | SSH 关机 OpenWrt |

示例：

```bash
curl -X POST http://<DDNS域名>:5055/api/public/pc/pc1/wake
curl -X POST http://<DDNS域名>:5055/api/public/pc/pc1/shutdown
curl http://<DDNS域名>:5055/api/public/status
```

注意：

- 明文 HTTP 即可，不用密钥、不用 HTTPS——请求里没有任何敏感信息，接口本身就是公开的（和网页按钮同一个）。
- 没有重启接口：重启只在 5155 管理页（登录后可用）。
- 同一目标同一动作 5 秒内只放行一次（防连点）；POST 有同源检查：带 Origin 但域名对不上的跨站请求会被拒绝，不带 Origin 的服务端调用直接放行。
- 不记审计日志。谁点了、什么时候点的，服务器不再记录。

### OpenWake-豆包开关机技能-纯文本提示词（修改域名后直接粘贴给豆包）

```
请用 skill-creator-for-work 帮我创建一个名为 pc-power-control 的技能，通过 OpenWake 的 HTTP API 远程查询电脑状态、开机（网络唤醒）和关机。我的环境：服务入口是 http://【这里换成你的DDNS域名】:5055，端口固定 5055（Docker 部署的 OpenWake 默认端口，不要改），受控电脑 ID 固定 pc1。三个接口是：状态查询 GET /api/public/status，开机 POST /api/public/pc/pc1/wake，关机 POST /api/public/pc/pc1/shutdown，健康检查 GET /api/public/health，返回都是 JSON，status 形如 {"openwrt":{"online":true},"pcs":[{"id":"pc1","name":"Win PC","online":true}]}。请把口令映射写进技能描述，保证我用自然语言就能触发：说开机、打开电脑、电脑开机、帮我开机、帮我打开电脑就执行 wake；说关机、关闭电脑、电脑关机、帮我关机、帮我关闭电脑就执行 shutdown；说状态、查看状态、状态查看、电脑状态、查询电脑状态就执行 status；同时适用于远程唤醒、远程关机、判断电脑是否在线、开机或关机后的状态确认。以下是必须遵守的技术要求，都是踩过坑总结的，请务必落地：一、只走云端公网入口，禁止拿局域网 IP（如 192.168.x.x）做兜底，能走局域网说明人在家就不需要远程开关机，局域网入口要做硬拦截，不给显式放行参数就拒绝并报错退出。二、绝不写死 IP，也不缓存解析结果，家庭宽带是动态 IP 会变，唯一稳定的是 DDNS 域名，每次请求包括动作后轮询的每一轮都要重新解析。三、解析要绕过过期的 DNS 缓存，优先直接 UDP 查询公共 DNS，顺序 223.5.5.5、119.29.29.29、114.114.114.114、8.8.8.8，全都不通再回落到系统解析。四、多 IP 容错，把解析到的全部 A 和 AAAA 记录去重，IPv4 优先 IPv6 兜底，逐个 IP 尝试，请求时带上原域名的 Host 头。五、重试要分级，只有连接被拒（连接都没建立）才换下一个 IP 重发，超时或连接被重置视为可能已送达，关机这类不可逆操作绝不能重复发送。六、不经环境代理，用 http.client 直连解析出的 IP，不要依赖 urllib 加环境代理变量，沙箱代理会拦自有主机。七、开机和关机后要自动确认，动作只发一次请求，然后用 status 轮询确认，开机等到 online 为 true，关机等到 online 为 false 或 status 不可达，开机到上线通常几十秒，期间 online 为 false 属正常不要重发。八、状态判断口径只看 pcs 数组里 id 等于 pc1 的 online 字段，openwrt.online 只表示路由器是否在线，为 false 时先查网络，别当成电脑状态。九、连通性探测只用 GET status 和 GET /api/public/health，不要用 GET 去探 wake 和 shutdown 路径，有的实现不校验方法，GET 会真的触发开关机。交付要求：给我 SKILL.md 和 scripts/pc_power.py 两个文件，放在 .doubao/agent_mode/workspace/.user_skills/pc-power-control/ 目录下；脚本用 Python 3 标准库、不引入第三方依赖，子命令包含 status、wake、shutdown、init；域名和端口要支持配置，命令行参数 --host 和 --port、环境变量 OPENWAKE_HOST 和 OPENWAKE_PORT、技能目录下的 config.json，优先级是命令行大于环境变量大于 config.json 大于内置默认值，init --host 域名 用于一次性写入本机配置；支持 --wait 指定动作后轮询确认秒数，支持 --dry-run 只打印解析结果和将要发送的请求而不真正发送；输出用 KEY=VALUE 形式便于排查，至少包含 RESOLVE 显示域名解析到的 IP 列表和解析来源、每个 IP 的 attempt 结果、HTTP、RESULT、VERIFY；失败时要明确区分 DNS 解析失败（域名写错或 DDNS 未生效）和全部 IP 连接被拒（端口转发或服务有问题），并在 SKILL.md 里写清排查顺序。完成后用 status 实测一次确认能拿到状态 JSON，不要为了测试去真的关机或开机。
```

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
4. **路由器转发**：只把 `5055` 转发到 OpenWrt，不要转发 `5155`，外网操作地址即 `http://<DDNS域名>:5055`，内网管理地址是 `http://<OpenWrt-IP>:5155`。
   公开页是明文 HTTP，不用配 HTTPS（没有登录、没有密钥，请求里没敏感信息）；想给公开页加 HTTPS 可在页面配置里把协议切到 `https`（无证书时自动生成自签名证书，浏览器会提示不安全；要去掉提示就把正式证书放到 `/data/cert.pem` + `/data/key.pem` 并重启），或在前面挂反代。

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
web.go                管理页 API + 公开页接口 + 登录态 + TLS（自签名兜底）
web/index.html        管理页（无构建步骤，纯 HTML/JS）
web/public.html       外网操作页（双大圆环，无构建步骤，纯 HTML/JS）
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
