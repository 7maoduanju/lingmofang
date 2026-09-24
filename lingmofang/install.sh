#!/bin/bash
set -Eeuo pipefail

APP_DIR="/opt/indexnow_auto"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 执行安装脚本" >&2
  exit 1
fi

command -v python3 >/dev/null 2>&1 || {
  apt-get update
  apt-get install -y python3
}

mkdir -p "$APP_DIR"/{logs,state,reports,backup}
install -m 0755 "$SOURCE_DIR/main.py" "$APP_DIR/main.py"

if [[ ! -f "$APP_DIR/config.ini" ]]; then
  install -m 0644 "$SOURCE_DIR/config.ini" "$APP_DIR/config.ini"
else
  echo "保留现有配置：$APP_DIR/config.ini"
fi

if [[ ! -f "$APP_DIR/domain.txt" && ! -f "$APP_DIR/domian.txt" ]]; then
  cat > "$APP_DIR/domain.txt" <<'EOF'
# 每行一个基础域名，不写协议和路径
# example.com
EOF
  chmod 0644 "$APP_DIR/domain.txt"
fi

python3 -m py_compile "$APP_DIR/main.py"

echo "安装完成：$APP_DIR"
echo "下一步：编辑 $APP_DIR/domain.txt，然后运行："
echo "  python3 $APP_DIR/main.py --dry-run --verbose"
echo "  python3 $APP_DIR/main.py --no-push --verbose"
echo "  python3 $APP_DIR/main.py --verbose"
