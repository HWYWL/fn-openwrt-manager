#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 .fpk 传到 GitHub Releases（给 scripts/release.sh 调用，也可单独用）。

    python3 scripts/release_upload.py --app fn-openwrt-manager --version 1.2.7 \
        --asset ../fn-openwrt-manager.fpk [--notes-file notes.md] [--tag v1.2.7] [--dry-run]

凭据：GH_TOKEN / GITHUB_TOKEN，否则取 git 已保存的 GitHub 凭据。token 不会被打印。
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_REPO = "HWYWL/fn-openwrt-manager"

# Windows 控制台默认 GBK，打印 emoji/中文标题会炸；统一成 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


# ---------------------------------------------------------------- 凭据 / API

def github_token():
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    try:
        proc = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return ""
    for line in (proc.stdout or "").splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1].strip()
    return ""


def api(token, method, url, payload=None, raw=None, content_type="application/json"):
    data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Accept", "application/vnd.github+json")
    if data is not None:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "ignore")


# ---------------------------------------------------------------- 说明正文

CHANGELOG_HINT = """## 🎉 {app} v{version} 来啦，家人们冲鸭✨

飞牛 fnOS 上的局域网路由器管理器更新了，装上就能扫内网、一键进 LuCI，面板还能看实时状态～

### 🔥 这次更新

{items}

### 📦 安装方法（超简单）

1. 下载下面的 `{asset_name}`
2. 飞牛 fnOS → **应用中心 → 右上角「手动安装」** → 选这个文件
3. 装完从桌面打开，点卡片就能用啦 ✨

### ⚠️ 小提示

- 需要和路由器在**同一局域网**；外网访问把「访问方式」切到 **中转**
- 面板要显示实时数据，需填一次路由器**账号密码**（只存在本机 `TRIM_PKGVAR/data`，权限 600，不上传服务器）
- `platform = all`：x86 / ARM 都能装，纯 Python，NAS 自带 `python3` 即可

### 🔐 校验

```
SHA256: {sha256}
文件大小: {size} 字节
```
"""


def read_changelog_items(manifest_path, version):
    """从 manifest 的 changelog 里拆出条目；只保留本版与前两版，避免正文太长。"""
    text = ""
    try:
        with open(manifest_path, encoding="utf-8") as fp:
            for line in fp:
                m = re.match(r"\s*changelog\s*=\s*(.+)", line)
                if m:
                    text = m.group(1).strip()
                    break
    except OSError:
        return []
    parts = [p.strip() for p in re.split(r"[；;]", text) if p.strip()]
    entries = []       # [[版本号, 说明], ...]
    for part in parts:
        m = re.match(r"(v?[0-9][0-9.\-a-zA-Z]*)\s*[：:]\s*(.+)", part)
        if m:
            entries.append([m.group(1), m.group(2).strip()])
        elif entries:
            # 没有版本号的片段是上一版的续写，接回去而不是单独一行
            entries[-1][1] += "；" + part
        else:
            entries.append(["", part])
    entries = entries[:3]
    if not entries:
        return ["- 详见仓库提交记录"]
    return ["- **%s** %s" % (ver, note) if ver else "- %s" % note for ver, note in entries]


def build_body(app, version, asset_path, manifest_path, notes_file):
    if notes_file:
        with open(notes_file, encoding="utf-8") as fp:
            return fp.read()
    raw = open(asset_path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    return CHANGELOG_HINT.format(
        app=app,
        version=version,
        asset_name=os.path.basename(asset_path),
        items="\n".join(read_changelog_items(manifest_path, version)),
        sha256=digest,
        size=len(raw),
    )


# ---------------------------------------------------------------- 主流程

def main():
    parser = argparse.ArgumentParser(description="把 fpk 发到 GitHub Releases")
    parser.add_argument("--app", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--repo", default=os.environ.get("GH_REPO") or DEFAULT_REPO)
    parser.add_argument("--tag", default="")
    parser.add_argument("--title", default="")
    parser.add_argument("--notes-file", default="")
    parser.add_argument("--manifest", default="manifest")
    parser.add_argument("--draft", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not os.path.isfile(args.asset):
        sys.exit("找不到产物：%s" % args.asset)

    tag = args.tag or ("v%s" % args.version)
    body = build_body(args.app, args.version, args.asset, args.manifest, args.notes_file)
    title = args.title or "🎉 %s ｜ v%s 更新" % (args.app, args.version)
    asset_name = os.path.basename(args.asset)
    size = os.path.getsize(args.asset)

    print("repo : %s" % args.repo)
    print("tag  : %s" % tag)
    print("title: %s" % title)
    print("asset: %s (%d 字节)" % (asset_name, size))
    print("sha256: %s" % hashlib.sha256(open(args.asset, "rb").read()).hexdigest())
    print("----- 正文预览（前 600 字）-----")
    print(body[:600])
    print("--------------------------------")

    if args.dry_run:
        print("--dry-run：没有调用 GitHub API")
        return 0

    token = github_token()
    if not token:
        sys.exit("拿不到 GitHub 凭据：设置 GH_TOKEN，或先用 git push 让凭据被记住")

    status, text = api(token, "POST", "https://api.github.com/repos/%s/releases" % args.repo, {
        "tag_name": tag,
        "target_commitish": "main",
        "name": title,
        "body": body,
        "draft": bool(args.draft),
        "prerelease": False,
    })
    if status == 422:          # tag 已存在 → 复用已有 release
        status, text = api(token, "GET",
                           "https://api.github.com/repos/%s/releases/tags/%s" % (args.repo, tag))
        if status == 200:
            print("release 已存在，复用：%s" % tag)
    if status not in (200, 201):
        sys.exit("创建 release 失败：HTTP %s\n%s" % (status, text[:400]))

    release = json.loads(text)
    release_id = release["id"]
    print("release: %s" % release["html_url"])

    for asset in release.get("assets", []):
        if asset["name"] == asset_name:
            api(token, "DELETE",
                "https://api.github.com/repos/%s/releases/assets/%d" % (args.repo, asset["id"]))
            print("已删除同名旧附件：%s" % asset_name)

    raw = open(args.asset, "rb").read()
    status, text = api(
        token, "POST",
        "https://uploads.github.com/repos/%s/releases/%d/assets?name=%s"
        % (args.repo, release_id, urllib.parse.quote(asset_name)),
        raw=raw, content_type="application/octet-stream")
    if status not in (200, 201):
        sys.exit("上传附件失败：HTTP %s\n%s" % (status, text[:400]))

    uploaded = json.loads(text)
    print("附件: %s (%d 字节)" % (uploaded["name"], uploaded["size"]))
    print("下载: %s" % uploaded["browser_download_url"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
