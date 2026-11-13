from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import stat
import sys
import time
import unicodedata
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import requests
except ImportError:  # 只有在用到 --vt 時才需要
    requests = None

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Magic number 資料庫： (offset, signature bytes, 類型名稱, 合法副檔名集合)
# --------------------------------------------------------------------------- #
ZIP_BASED = {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
             ".jar", ".apk", ".epub", ".xpi", ".war", ".aar", ".whl", ".nupkg"}
OLE_BASED = {".doc", ".xls", ".ppt", ".msi", ".msg"}
PE_BASED = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".efi"}
MP4_BASED = {".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".heic", ".avif"}

#magic number對照表
SIGNATURES: list[tuple[int, bytes, str, set[str]]] = [
    (0, b"\x89PNG\r\n\x1a\n",        "PNG image",            {".png"}),
    (0, b"\xff\xd8\xff",             "JPEG image",           {".jpg", ".jpeg", ".jpe", ".jfif"}),
    (0, b"GIF87a",                   "GIF image",            {".gif"}),
    (0, b"GIF89a",                   "GIF image",            {".gif"}),
    (0, b"BM",                       "BMP image",            {".bmp", ".dib"}),
    (0, b"II*\x00",                  "TIFF image (LE)",      {".tif", ".tiff"}),
    (0, b"MM\x00*",                  "TIFF image (BE)",      {".tif", ".tiff"}),
    (0, b"\x00\x00\x01\x00",         "ICO icon",             {".ico"}),
    (0, b"%PDF-",                    "PDF document",         {".pdf"}),
    (0, b"PK\x03\x04",               "ZIP container",        ZIP_BASED),
    (0, b"PK\x05\x06",               "ZIP container (empty)", ZIP_BASED),
    (0, b"Rar!\x1a\x07\x00",         "RAR archive v4",       {".rar"}),
    (0, b"Rar!\x1a\x07\x01\x00",     "RAR archive v5",       {".rar"}),
    (0, b"7z\xbc\xaf\x27\x1c",       "7-Zip archive",        {".7z"}),
    (0, b"\x1f\x8b",                 "GZIP archive",         {".gz", ".tgz"}),
    (0, b"BZh",                      "BZIP2 archive",        {".bz2", ".tbz2"}),
    (0, b"\xfd7zXZ\x00",             "XZ archive",           {".xz", ".txz"}),
    (257, b"ustar",                  "TAR archive",          {".tar"}),
    (0, b"MZ",                       "Windows PE executable", PE_BASED),
    (0, b"\x7fELF",                  "ELF executable",       {".elf", ".so", ".o", ".bin", ".out", ".axf", ""}),
    (0, b"\xca\xfe\xba\xbe",         "Java class / Mach-O fat", {".class", ".dylib", ".bin", ""}),
    (0, b"\xfe\xed\xfa\xce",         "Mach-O 32-bit",        {".dylib", ".bin", ""}),
    (0, b"\xfe\xed\xfa\xcf",         "Mach-O 64-bit",        {".dylib", ".bin", ""}),
    (0, b"\xcf\xfa\xed\xfe",         "Mach-O 64-bit (LE)",   {".dylib", ".bin", ""}),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 / MS Office legacy", OLE_BASED),
    (0, b"SQLite format 3\x00",      "SQLite database",      {".db", ".sqlite", ".sqlite3", ".db3"}),
    (0, b"ID3",                      "MP3 audio (ID3)",      {".mp3"}),
    (0, b"\xff\xfb",                 "MP3 audio",            {".mp3"}),
    (0, b"OggS",                     "OGG container",        {".ogg", ".oga", ".ogv", ".opus"}),
    (0, b"fLaC",                     "FLAC audio",           {".flac"}),
    (0, b"\x1a\x45\xdf\xa3",         "Matroska / WebM",      {".mkv", ".webm", ".mka"}),
    (4, b"ftyp",                     "ISO-BMFF (MP4/MOV…)",  MP4_BASED),
    (0, b"{\\rtf",                   "RTF document",         {".rtf"}),
    (0, b"\x00asm",                  "WebAssembly",          {".wasm"}),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)", {".lnk"}),
    (0, b"#!",                       "Script (shebang)",     {".sh", ".py", ".pl", ".rb", ".bash", ".zsh", ""}),
]

#若副檔名在此集合內，但檔頭沒有對應到 magic number，也視為可疑
EXT_REQUIRES_MAGIC = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf", ".zip", ".docx", ".xlsx",
    ".pptx", ".rar", ".7z", ".gz", ".exe", ".dll", ".doc", ".xls", ".ppt",
    ".mp3", ".mp4", ".ico", ".sqlite", ".db",
}

#RIFF 容器需看 offset 8-11 的子類型
RIFF_TYPES = {
    b"WAVE": ("WAV audio", {".wav"}),
    b"AVI ": ("AVI video", {".avi"}),
    b"WEBP": ("WebP image", {".webp"}),
}

#依檔頭位元組判斷實際類型；回傳 (類型名稱, 合法副檔名集合)
def detect_magic(header: bytes) -> tuple[Optional[str], Optional[set[str]]]:

    if header[:4] == b"RIFF" and len(header) >= 12:
        sub = header[8:12]
        if sub in RIFF_TYPES:
            return RIFF_TYPES[sub]
        return "RIFF container", {".wav", ".avi", ".webp"}
    for offset, sig, name, exts in SIGNATURES:
        if header[offset:offset + len(sig)] == sig:
            return name, exts
    return None, None

#讀取前 N bytes → 辨識 magic number → 與副檔名比對是否一致
def check_magic(path: Path, ext: str, read_len: int = 512) -> dict[str, Any]:
    with open(path, "rb") as f:
        header = f.read(read_len)
    detected, valid_exts = detect_magic(header)
    ext_l = ext.lower()

    if detected is None:
        mismatch = ext_l in EXT_REQUIRES_MAGIC and len(header) > 0
        note = (f"副檔名 {ext_l} 應有特定檔頭，但未找到已知 magic number"
                if mismatch else "未知/純文字類型（無已知 magic number）")
    else:
        mismatch = ext_l not in valid_exts
        note = (f"副檔名 {ext_l or '(無)'} 與實際類型 {detected} 不符"
                if mismatch else "OK")
    return {
        "magic_hex": header[:16].hex(" ").upper(),
        "detected_type": detected or "unknown",
        "extension_mismatch": mismatch,
        "magic_note": note,
    }


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #
# 處理時間格式，回傳utc、本地時間
def _ts(epoch: float) -> dict[str, str]:
    utc = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return {"utc": utc.isoformat(timespec="seconds"),
            "local": utc.astimezone().isoformat(timespec="seconds")}

#處理檔案大小格式，回傳易讀的檔案單位
def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)

# Windows 檔案屬性旗標（數值固定，這樣在任何平台都能解碼）
WIN_ATTR_FLAGS = [
    (0x0001, "READONLY"), (0x0002, "HIDDEN"), (0x0004, "SYSTEM"), (0x0010, "DIRECTORY"),
    (0x0020, "ARCHIVE"), (0x0040, "DEVICE"), (0x0100, "TEMPORARY"), (0x0200, "SPARSE"),
    (0x0400, "REPARSE_POINT"), (0x0800, "COMPRESSED"), (0x1000, "OFFLINE"),
    (0x2000, "NOT_INDEXED"), (0x4000, "ENCRYPTED"),
]
 
#把 st_file_attributes 數值轉成 READONLY|HIDDEN|... 字串。
def decode_win_attributes(attrs: int) -> str:
    names = [n for bit, n in WIN_ATTR_FLAGS if attrs & bit]
    return "|".join(names) if names else "NORMAL"

#取得metadata資料
def collect_metadata(path: Path) -> dict[str, Any]:
    st = path.lstat()
    ext = path.suffix
    created_epoch = getattr(st, "st_birthtime", None)  # macOS / BSD / Win(3.12+)
    if created_epoch is None:
        created_epoch = st.st_ctime  # Linux 沒有 birth time，這是 inode 變更時間

    win_attrs = getattr(st, "st_file_attributes", None)  # 只有 Windows 才有
    is_windows = win_attrs is not None

    meta: dict[str, Any] = {
        "filename": path.name,
        "path": str(path.resolve()),
        "directory": str(path.resolve().parent),
        "extension": ext.lower(),
        "size_bytes": st.st_size,
        "size_human": human_size(st.st_size),
        "mime_guess": mimetypes.guess_type(path.name)[0] or "unknown",
        "created_utc": _ts(created_epoch)["utc"],
        "created_local": _ts(created_epoch)["local"],
        "modified_utc": _ts(st.st_mtime)["utc"],
        "modified_local": _ts(st.st_mtime)["local"],
        "accessed_utc": _ts(st.st_atime)["utc"],
        "mode_octal": None if is_windows else oct(stat.S_IMODE(st.st_mode)),
        "mode_str": None if is_windows else stat.filemode(st.st_mode),
        "win_attributes": decode_win_attributes(win_attrs) if is_windows else None,
        "win_attributes_raw": hex(win_attrs) if is_windows else None,
        "is_symlink": stat.S_ISLNK(st.st_mode),
        "is_reparse_point": bool(is_windows and win_attrs & 0x0400), #補足偵測範圍，包含junction、雲端佔位檔
        "is_hidden": path.name.startswith(".") or bool(is_windows and win_attrs & 0x0002),
        "inode": st.st_ino,
        "hard_links": st.st_nlink,
        "uid": None if is_windows else getattr(st, "st_uid", None), # Windows 上 st_uid / st_gid 固定為 0，沒有意義 → 改為 None（請用 --acl）
        "gid": None if is_windows else getattr(st, "st_gid", None),
    }
    try:  # 轉成使用者名稱（僅 POSIX，適用Linux）
        import pwd
        meta["owner"] = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        meta["owner"] = None
    return meta

#用 icacls 取得 ACL、用 PowerShell Get-Acl 取得擁有者（僅 Windows，--acl 才會呼叫）。
def get_windows_acl(path: Path, timeout: int = 15) -> dict[str, Any]:
    if os.name != "nt":
        return {"acl_note": "--acl 僅支援 Windows"}
    out: dict[str, Any] = {}
    full = str(path.resolve())
 
    # 取得ACL：icacls 的輸出使用 OEM 字碼頁，須採用OEM編碼
    try:
        r = subprocess.run(["icacls", full], capture_output=True, text=True,
                           encoding="oem", errors="replace", timeout=timeout)
        lines = []
        for ln in r.stdout.splitlines():
            ln = ln.strip()
            if not ln or ln.lower().startswith(("successfully processed", "已成功處理")):
                continue
            if ln.startswith(full):          # 第一行會帶路徑，去掉
                ln = ln[len(full):].strip()
            lines.append(ln)
        out["acl"] = lines
        # 判斷是否任何人可寫（Everyone 擁有 Full / Modify / Write）
        out["acl_everyone_write"] = any(
            re.match(r"(?i)everyone:", ln) and re.search(r"\((F|M|W)\)", ln) for ln in lines)
    except (OSError, subprocess.SubprocessError) as e:
        out["acl_error"] = str(e)
 
    # 取得擁有者資訊
    try:
        ps = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
              "(Get-Acl -LiteralPath $env:TRIAGE_PATH).Owner")
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env={**os.environ, "TRIAGE_PATH": full}) #路徑以環境變數傳入，避免命令列引號/注入問題
        owner = r.stdout.strip()
        if owner:
            out["owner"] = owner
    except (OSError, subprocess.SubprocessError) as e:
        out["owner_error"] = str(e)
    return out

# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #
#將檔案轉換成Hash值(MD5、SHA1、SHA256)
def hash_file(path: Path, chunk: int = 1024 * 1024) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            md5.update(block) 
            sha1.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


# --------------------------------------------------------------------------- #
# VirusTotal (API v3)
# --------------------------------------------------------------------------- #
VT_URL = "https://www.virustotal.com/api/v3/files/{}"

#用 SHA-256 查詢 VT。只送雜湊，不上傳檔案本身。
def vt_lookup(sha256: str, api_key: str, timeout: int = 30, retries: int = 3) -> dict[str, Any]:
    if requests is None:
        return {"vt_status": "error", "vt_error": "請先安裝 requests: pip install requests"}

    for attempt in range(retries):
        try:
            r = requests.get(VT_URL.format(sha256), headers={"x-apikey": api_key}, timeout=timeout)
        except requests.RequestException as e:
            return {"vt_status": "error", "vt_error": str(e)}

        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
            total = sum(stats.values())
            threat = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
            return {
                "vt_status": "found",
                "vt_verdict": "MALICIOUS" if mal else "SUSPICIOUS" if sus else "CLEAN",
                "vt_malicious": mal,
                "vt_suspicious": sus,
                "vt_harmless": stats.get("harmless", 0),
                "vt_undetected": stats.get("undetected", 0),
                "vt_total_engines": total,
                "vt_detection": f"{mal + sus}/{total}",
                "vt_threat_label": threat,
                "vt_meaningful_name": attrs.get("meaningful_name"),
                "vt_type": attrs.get("type_description"),
                "vt_reputation": attrs.get("reputation"),
                "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        if r.status_code == 404:
            return {"vt_status": "not_found", "vt_verdict": "UNKNOWN",
                    "vt_detection": "-", "vt_link": f"https://www.virustotal.com/gui/file/{sha256}"}
        if r.status_code == 429:  # 超過速率限制
            wait = 60 * (attempt + 1)
            print(f"  [VT] 速率限制，{wait}s 後重試…", file=sys.stderr)
            time.sleep(wait)
            continue
        if r.status_code in (401, 403):
            return {"vt_status": "error", "vt_error": "API key 無效或無權限"}
        return {"vt_status": "error", "vt_error": f"HTTP {r.status_code}"}
    return {"vt_status": "error", "vt_error": "超過重試次數（rate limit）"}


# --------------------------------------------------------------------------- #
# 字串與 IOC 擷取（Regex）
# --------------------------------------------------------------------------- #
ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}")
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")

URL_RE = re.compile(r"\b(?:https?|ftp|sftp|ws|wss)://[^\s\"'<>\\^`{|}\x00-\x1f]{3,}", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b", re.I)

# 只接受常見 TLD，避免把 "kernel32.dll"、"main.py" 當成 domain
COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co", "me",
    "tv", "cc", "xyz", "top", "site", "online", "club", "shop", "app", "dev", "cloud",
    "tech", "store", "live", "pro", "vip", "ru", "cn", "tw", "jp", "kr", "hk", "sg",
    "in", "uk", "de", "fr", "it", "es", "nl", "br", "au", "ca", "us", "eu", "ch", "se",
    "no", "fi", "pl", "ua", "tk", "ml", "ga", "cf", "gq", "onion", "su", "ir", "pw",
}

#類似 Unix `strings`：同時抓 ASCII 與 UTF-16LE 可印字串
def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    out = [m.group().decode("ascii") for m in re.finditer(ASCII_RUN.pattern % min_len, data)]
    out += [m.group().decode("utf-16le") for m in re.finditer(UTF16_RUN.pattern % min_len, data)]
    return out

#判斷IP是否合法
def _valid_ipv4(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return False
    # 排除 0.0.0.0 / 全 0 或版本號形式（例如 1.0.0.0）
    return not (ip.is_unspecified or s.startswith("0."))

#從檔案中提取網路指標
def extract_iocs(path: Path, min_len: int = 6, max_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read(max_bytes)
    strings = extract_strings(data, min_len)
    blob = "\n".join(strings)

    urls = sorted({u.rstrip(".,;:)]}") for u in URL_RE.findall(blob)})
    emails = sorted(set(EMAIL_RE.findall(blob)))
    ips = sorted({ip for ip in IPV4_RE.findall(blob) if _valid_ipv4(ip)},
                 key=lambda s: ipaddress.IPv4Address(s))
    domains = set()
    for m in DOMAIN_RE.finditer(blob):
        if m.group(1).lower() in COMMON_TLDS:
            domains.add(m.group(0).lower())
    domains = sorted(domains)

    return {
        "string_count": len(strings),
        "truncated": path.stat().st_size > max_bytes,
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "emails": emails,
    }


# --------------------------------------------------------------------------- #
# 表格輸出（支援中日韓全形字寬）
# --------------------------------------------------------------------------- #
#判斷字元佔位大小
def _w(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)

#依欄位寬度回傳字串長度
def _fit(s: str, width: int) -> str:
    if _w(s) <= width:
        return s
    out, acc = "", 0
    for c in s:
        cw = _w(c)
        if acc + cw > width - 1:
            break
        out, acc = out + c, acc + cw
    return out + "…"

#輸入標題、資料，畫成表格
def render_table(headers: list[str], rows: list[list[str]], max_col: int = 40) -> str:
    rows = [[_fit(str(c), max_col) for c in r] for r in rows]
    widths = [max(_w(h), *(_w(r[i]) for r in rows)) if rows else _w(h) for i, h in enumerate(headers)]
    pad = lambda s, w: s + " " * (w - _w(s))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    line = lambda cells: "| " + " | ".join(pad(c, w) for c, w in zip(cells, widths)) + " |"
    return "\n".join([sep, line(headers), sep, *(line(r) for r in rows), sep])


# --------------------------------------------------------------------------- #
# 流程控制
# --------------------------------------------------------------------------- #
#迭代取得目標檔案
def iter_files(targets: list[str], recursive: bool) -> list[Path]:
    files: list[Path] = []
    for t in targets:
        p = Path(t)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            if recursive:
                for root, _dirs, names in os.walk(p):  # 預設不跟隨 symlink 目錄
                    files += [Path(root) / n for n in names] #取得目錄、子目錄裡所有檔案
            else:
                files += [c for c in sorted(p.iterdir()) if c.is_file()] #只取得目錄裡的檔案
        else:
            print(f"[!] 找不到路徑：{t}", file=sys.stderr)
    return files

#依指令執行各項檔案分析
def analyze(path: Path, args, vt_cache: dict[str, dict]) -> dict[str, Any]:
    rec: dict[str, Any] = {}
    try:
        rec.update(collect_metadata(path)) #metadata
        if args.acl:       
            rec.update(get_windows_acl(path)) #Windows ACL
        rec.update(check_magic(path, path.suffix)) #確認magic num
        rec["hashes"] = hash_file(path) #hash值

        if not args.no_strings:
            rec["iocs"] = extract_iocs(path, args.min_len, args.max_bytes) #IOC

        if args.vt: #Virus Total
            sha = rec["hashes"]["sha256"]
            if sha not in vt_cache:
                if vt_cache:  # 免費 API 限 4 次/分鐘 → 預設間隔 15 秒
                    time.sleep(args.vt_delay)
                vt_cache[sha] = vt_lookup(sha, args.api_key)
            rec["virustotal"] = vt_cache[sha]
    except (PermissionError, OSError) as e:
        rec.setdefault("filename", path.name)
        rec.setdefault("path", str(path))
        rec["error"] = str(e)
    return rec

#終端顯示結果
def print_report(results: list[dict[str, Any]], args) -> None:
    ok = [r for r in results if "error" not in r]

    # 表 1：總覽
    print("\n=== 檔案總覽 ===")
    headers = ["Filename", "Size", "Ext", "Detected type", "Magic", "SHA-256 (前16碼)"]
    if args.vt:
        headers += ["VT detect", "VT verdict"]
    rows = []
    for r in ok:
        row = [r["filename"], r["size_human"], r["extension"] or "-", r["detected_type"],
               "MISMATCH" if r["extension_mismatch"] else "ok", r["hashes"]["sha256"][:16]]
        if args.vt:
            vt = r.get("virustotal", {})
            row += [vt.get("vt_detection", "-"), vt.get("vt_verdict", vt.get("vt_status", "-"))]
        rows.append(row)
    print(render_table(headers, rows))

    # 副檔名 / magic number 不符
    bad = [r for r in ok if r["extension_mismatch"]]
    print(f"\n=== Magic number 與副檔名不符：{len(bad)} 個 ===")
    for r in bad:
        print(f"  [!] {r['path']}\n      {r['magic_note']}  (header: {r['magic_hex']})")

    # VT 詳細表
    if args.vt:
        print("\n=== VirusTotal 結果 ===")
        vh = ["Filename", "Verdict", "Malicious", "Suspicious", "Harmless", "Undetected", "Threat label", "Link"]
        vrows = []
        for r in ok:
            v = r.get("virustotal", {})
            vrows.append([r["filename"], v.get("vt_verdict", v.get("vt_status", "-")),
                          v.get("vt_malicious", "-"), v.get("vt_suspicious", "-"),
                          v.get("vt_harmless", "-"), v.get("vt_undetected", "-"),
                          v.get("vt_threat_label") or v.get("vt_error") or "-",
                          v.get("vt_link", "-")])
        print(render_table(vh, vrows, max_col=70))

    # IOC
    if not args.no_strings:
        print("\n=== 擷取到的字串 IOC ===")
        irows = []
        for r in ok:
            ioc = r.get("iocs")
            if not ioc:
                continue
            for kind in ("urls", "ips", "domains", "emails"):
                for val in ioc[kind]:
                    irows.append([r["filename"], kind[:-1].upper(), val])
        if irows:
            print(render_table(["Filename", "Type", "Value"], irows, max_col=80))
        else:
            print("  (沒有發現 URL / IP / Domain / Email)")

    errs = [r for r in results if "error" in r]
    if errs:
        print("\n=== 讀取失敗 ===")
        for r in errs:
            print(f"  {r['path']}: {r['error']}")

    if args.verbose:
        print("\n=== 完整 metadata ===")
        for r in ok:
            print(f"\n[{r['filename']}]")
            for k in ("path", "size_bytes", "extension", "mime_guess", "created_utc", "modified_utc",
                      "accessed_utc","win_attributes", "mode_str", "owner", "is_symlink","is_reparse_point", "is_hidden", "inode", "hard_links"):
                v = r.get(k)
                print(f"  {k:16}: {v if v is not None else '-'}")
            for ace in r.get("acl", []):
                print(f"  {'acl':16}: {ace}")
            if r.get("acl_everyone_write"):
                print(f"  {'[!]':16}: Everyone 對此檔案有寫入權限")
            for h, v in r["hashes"].items():
                print(f"  {h:16}: {v}")

#將結果存入Json/CSV檔
def save_reports(results: list[dict[str, Any]], outdir: Path) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jpath, cpath = outdir / f"triage_{stamp}.json", outdir / f"triage_{stamp}.csv"

    with open(jpath, "w", encoding="utf-8") as f:
        json.dump({"tool": "file_triage", "version": __version__,
                   "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "results": results}, f, ensure_ascii=False, indent=2)

    cols = ["filename", "path", "size_bytes", "extension", "mime_guess", "created_utc", "modified_utc",
            "accessed_utc", "mode_str", "owner", "detected_type", "extension_mismatch", "magic_note",
            "md5", "sha1", "sha256", "vt_status", "vt_verdict", "vt_detection", "vt_threat_label",
            "vt_link", "urls", "ips", "domains", "emails", "error"]
    with open(cpath, "w", encoding="utf-8-sig", newline="") as f:  # utf-8-sig 讓 Excel 正確顯示中文
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in results:
            flat = dict(r)
            flat.update(r.get("hashes", {}))
            flat.update(r.get("virustotal", {}))
            for k in ("urls", "ips", "domains", "emails"):
                flat[k] = ";".join(r.get("iocs", {}).get(k, []))
            w.writerow(flat)
    return [jpath, cpath]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="file_triage",
        description="File Triage CLI：metadata、magic number、雜湊、VirusTotal、字串 IOC 擷取",
        epilog="範例:\n  python main.py ./samples -r\n"
               "  python main.py a.exe b.pdf --vt\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="+", help="檔案或目錄（可多個）")                                                  #必填檔案或目錄
    p.add_argument("-r", "--recursive", action="store_true", help="遞迴掃描子目錄")                                 #如果是分析目錄所有檔案，-r
    p.add_argument("-o", "--output-dir", default="triage_reports", help="報告輸出目錄（預設 triage_reports）")       #決定輸出的目錄名稱
    p.add_argument("--no-save", action="store_true", help="不寫出 JSON/CSV")                                       #如果不要儲存結果檔案，--no-save
    p.add_argument("--vt", action="store_true", help="用 SHA-256 查詢 VirusTotal（只送雜湊；key 讀取環境變數 VT_API_KEY）")      #如果要查詢vt，--vt
    p.add_argument("--vt-delay", type=float, default=15.0, help="VT 查詢間隔秒數（免費版 4 次/分鐘 → 15）")           #預設vt查詢間隔
    p.add_argument("--no-strings", action="store_true", help="略過字串/IOC 擷取")                                   #如果不要字串/IOC 擷取，--no-string
    p.add_argument("--min-len", type=int, default=6, help="字串最短長度（預設 6）")                                   #篩掉太短的字串，再找IOC
    p.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024, help="IOC 擷取最多讀取位元組數（預設 64MB）")   #讀取大小限制
    p.add_argument("-v", "--verbose", action="store_true", help="顯示完整 metadata")                                 #如果要看metadata，-v
    p.add_argument("--acl", action="store_true", help="（僅 Windows）用 icacls/PowerShell 取得 ACL 與擁有者，較慢")   #如果要取得 ACL 與擁有者，--acl                     
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")                                #檢視版本，--version
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    args.api_key = os.environ.get("VT_API_KEY", "").strip()
    if args.vt and not args.api_key:
        print("[!] 使用 --vt 需要設定環境變數 VT_API_KEY", file=sys.stderr)
        return 2
    if args.vt and requests is None:
        print("[!] 需要 requests：pip install requests", file=sys.stderr)
        return 2

    files = iter_files(args.paths, args.recursive)
    if not files:
        print("沒有可分析的檔案。", file=sys.stderr)
        return 1
    print(f"共 {len(files)} 個檔案，開始分析…")

    vt_cache: dict[str, dict] = {}
    results = []
    for i, p in enumerate(files, 1):
        print(f"  [{i}/{len(files)}] {p}", file=sys.stderr)
        results.append(analyze(p, args, vt_cache))

    print_report(results, args)

    if not args.no_save:
        for path in save_reports(results, Path(args.output_dir)):
            print(f"\n報告已儲存：{path}")

    return 3 if any(r.get("extension_mismatch") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())