#!/bin/bash
# 打 fnOS 应用包并发布到 GitHub Releases。
#
#   ./scripts/release.sh                 # 用 manifest 的 version 打 tag（v<version>）并发版
#   ./scripts/release.sh --dry-run       # 只打包 + 打印要发布的正文，不碰 GitHub
#   ./scripts/release.sh --notes-file notes.md   # 用自定义说明（小红书风格那种）代替自动生成的
#   ./scripts/release.sh --tag v1.2.8-test       # 覆盖 tag（调试用）
#   FNPACK=/path/to/fnpack ./scripts/release.sh  # fnpack 不在 PATH 时指定路径
#
# 凭据：优先读 GH_TOKEN / GITHUB_TOKEN，否则用 git 里已保存的 GitHub 凭据（git credential fill）。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

PY=""
for candidate in python3 python; do
  # Windows 上 python3 可能只是应用商店占位程序，要真跑一下才算数
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY="$candidate"
    break
  fi
done
if [ -z "$PY" ]; then echo "需要 python3 才能发布（读 manifest / 调 GitHub API）" >&2; exit 1; fi

FNPACK_BIN="${FNPACK:-fnpack}"
if ! command -v "$FNPACK_BIN" >/dev/null 2>&1 && [ ! -x "$FNPACK_BIN" ]; then
  echo "找不到 fnpack：把它放进 PATH，或用 FNPACK=/path/to/fnpack 指定" >&2
  exit 1
fi

APP_NAME=$("$PY" - <<'EOF'
import re
for line in open('manifest', encoding='utf-8'):
    m = re.match(r'\s*appname\s*=\s*(.+)', line)
    if m:
        print(m.group(1).strip())
        break
EOF
)
VERSION=$("$PY" - <<'EOF'
import re
for line in open('manifest', encoding='utf-8'):
    m = re.match(r'\s*version\s*=\s*(.+)', line)
    if m:
        print(m.group(1).strip())
        break
EOF
)

if [ -z "$APP_NAME" ] || [ -z "$VERSION" ]; then
  echo "manifest 里读不到 appname / version" >&2
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "⚠️  工作区有未提交的改动，发布会包含未提交的代码（tag 仍指向最后一次提交）。"
fi

# 清掉测试/预览跑出来的 pyc，否则会被 fnpack 打进包里（实测多出 60KB）
find "$ROOT" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$ROOT" -name "*.pyc" -delete 2>/dev/null || true

echo "==> 打包 $APP_NAME $VERSION"
BUILD_PARENT=$(dirname "$ROOT")
FPK="$BUILD_PARENT/$APP_NAME.fpk"
rm -f "$FPK"
(cd "$BUILD_PARENT" && "$FNPACK_BIN" build "$(basename "$ROOT")")
if [ ! -f "$FPK" ]; then
  echo "打包失败：没找到 $FPK" >&2
  exit 1
fi
echo "==> 产物 $FPK ($(wc -c < "$FPK") 字节)"

exec "$PY" "$ROOT/scripts/release_upload.py" \
  --app "$APP_NAME" \
  --version "$VERSION" \
  --asset "$FPK" \
  "$@"
