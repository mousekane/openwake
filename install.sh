#!/bin/sh
# OpenWake 一键部署：在 OpenWrt / Linux 上执行
#   curl -fsSL https://raw.githubusercontent.com/mousekane/openwake/main/install.sh | sh
# 之后：打开 http://<OpenWrt-IP>:5155，首次设置管理密码，再填 DDNS/PC 配置。
set -e
DIR="${OPENWAKE_DIR:-/opt/openwake}"
echo "==> 安装目录：$DIR"
mkdir -p "$DIR/data"
cd "$DIR"
if [ ! -f docker-compose.yml ]; then
  echo "==> 下载 docker-compose.yml"
  curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/mousekane/openwake/main/docker-compose.yml
fi
echo "==> 拉取并启动（host 网络模式，端口 5155）"
docker compose pull
docker compose up -d
echo ""
echo "完成！访问：http://<OpenWrt-IP>:5155"
echo "首次打开先设置管理密码；然后在页面填：Cloudflare Token + 域名、Win PC 的 IP/MAC/SSH 账号。"
echo "路由器需转发 5155 到 OpenWrt，外网地址就是：http(s)://<你的DDNS域名>:5155"
echo "更新：cd $DIR && docker compose pull && docker compose up -d"
