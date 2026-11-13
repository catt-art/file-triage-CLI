# File Triage CLI

對單一檔案或整個目錄做**初步 triage（快速篩檢）**的 Python 命令列工具：
蒐集 metadata → 
檢查 magic number 與副檔名是否相符 →
計算雜湊並查詢 VirusTotal → 
從檔案中擷取 URL / IP / Domain / Email → 
輸出表格並存成 JSON、CSV。

> 這是「篩檢」工具，結果是**線索，不是結論**。需搭配 VirusTotal 與人工判斷。


## 功能

| # | 功能 | 說明 | 對應技術 |
|---|---|---|---|
| 1 | 命令列工具 | 可輸入多個檔案或目錄，`-r` 遞迴掃描 | OS Automation |
| 2 | Metadata | 檔名、完整路徑、大小、副檔名、MIME、建立/修改/存取時間（UTC 與本地）、權限、擁有者、隱藏檔、符號連結等 | File I/O |
| 3 | Magic number | 讀取檔頭位元組，比對 30 多種檔案簽章；與副檔名不符時單獨列出 | Bytes |
| 4 | 雜湊與 VirusTotal | MD5 / SHA-1 / SHA-256；用 SHA-256 查詢 VirusTotal API v3，結果以表格呈現並存成 JSON、CSV | Hashing、HTTP/API、結構化資料 |
| 5 | 字串與 IOC 擷取 | 類似 `strings`（ASCII + UTF-16LE），再用 regex 找 URL、IP、Domain、Email | Regex、Encoding |

---

## 專案結構

```
file_triage_cli/
├── main.py            
├── README.md
└── .gitignore
```

執行後會產生(預設)：

```
triage_reports/
├── triage_YYYYMMDD_HHMMSS.json
└── triage_YYYYMMDD_HHMMSS.csv
```

---

## 安裝（Windows / VS Code）

需要 Python 3.9 以上。

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

- 提示字元前出現 `(.venv)` 代表虛擬環境已啟用。
- 若出現「禁止執行指令碼」，先執行一次：
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
- 如果**不使用 `--vt`**，完全不需要安裝任何套件，直接 `py main.py ...` 即可。
- 在 VS Code 按 `Ctrl+Shift+P` → `Python: Select Interpreter` → 選 `.venv`。

Linux / macOS：

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 設定 VirusTotal API key

程式**只從環境變數 `VT_API_KEY` 讀取** key，沒有命令列參數可以傳入（避免 key 留在指令歷史紀錄）。

```powershell
# 目前這個終端機有效
$env:VT_API_KEY = "你的key"

# 永久設定（需要重開 VS Code / 終端機才會生效）
setx VT_API_KEY "你的key"
```

```bash
# Linux / macOS
export VT_API_KEY="你的key"
```

> 不要把 key 寫進程式碼、`launch.json` 或上傳到 Git。

---

## 使用方式

```powershell
py main.py suspicious.exe                       # 單一檔案
py main.py .\samples                            # 目錄（只掃第一層）
py main.py D:\Downloads -r                      # 遞迴掃描所有子目錄
py main.py a.exe b.pdf C:\temp -r               # 混合多個路徑
py main.py D:\Downloads -r --vt -o reports      # 查詢 VirusTotal 並指定輸出資料夾
py main.py sample.dll -v --acl --no-save        # 完整 metadata + Windows ACL，不寫檔
```

### 參數

| 參數 | 說明 |
|---|---|
| `paths` | 一個或多個檔案或目錄 |
| `-r`, `--recursive` | 遞迴掃描子目錄（不跟隨符號連結目錄） |
| `-o`, `--output-dir` | 報告輸出資料夾，預設 `triage_reports` |
| `--no-save` | 只顯示在畫面上，不寫出 JSON / CSV |
| `--vt` | 以 SHA-256 查詢 VirusTotal（**只送雜湊，不上傳檔案**；需設定 `VT_API_KEY`） |
| `--vt-delay` | VT 查詢間隔秒數，預設 15（免費版限制約每分鐘 4 次） |
| `--acl` | （僅 Windows）用 `icacls` 與 PowerShell 取得 ACL 與擁有者，每個檔案較慢，需 |
| `--no-strings` | 略過字串 / IOC 擷取（掃大量檔案時可加快速度） |
| `--min-len` | 字串最短長度，預設 6 |
| `--max-bytes` | 字串擷取最多讀取的位元組數，預設 64 MB |
| `-v`, `--verbose` | 顯示每個檔案的完整 metadata 與雜湊 |
| `--version` | 顯示版本 |

### 結束碼（Exit code）

| 碼 | 意義 |
|---|---|
| `0` | 正常完成，沒有發現異常 |
| `1` | 沒有可分析的檔案 |
| `2` | 參數或使用方式錯誤（例如用了 `--vt` 但沒有設定 `VT_API_KEY`） |
| `3` | 分析完成，**發現副檔名與 magic number 不符** |

`3` 不是錯誤，而是「發現可疑檔案」的訊號，方便在腳本中判斷：

```powershell
py main.py D:\Downloads -r
if ($LASTEXITCODE -eq 3) { Write-Host "發現可疑檔案！" }
```

---

## 輸出範例

`py main.py samples`（沒有加 `--vt`）：

```
=== 檔案總覽 ===
+------------+------+-------+-----------------------+----------+------------------+
| Filename   | Size | Ext   | Detected type         | Magic    | SHA-256 (前16碼) |
+------------+------+-------+-----------------------+----------+------------------+
| doc.docx   | 6 B  | .docx | ZIP container         | ok       | d38f1f4a152ceb94 |
| fake.png   | 91 B | .png  | Windows PE executable | MISMATCH | ac2f584a1555484e |
| note.txt   | 66 B | .txt  | unknown               | ok       | 643e0ea825897e6b |
| real.png   | 16 B | .png  | PNG image             | ok       | 02a3e298f1533f62 |
| report.exe | 23 B | .exe  | PDF document          | MISMATCH | 2d4cd63d01c0f36d |
| wide.bin   | 56 B | .bin  | unknown               | ok       | 7588dd6abde26414 |
+------------+------+-------+-----------------------+----------+------------------+

=== Magic number 與副檔名不符：2 個 ===
  [!] .../samples/fake.png
      副檔名 .png 與實際類型 Windows PE executable 不符  (header: 4D 5A 90 00 ...)

=== 擷取到的字串 IOC ===
+----------+--------+-------------------------------------+
| Filename | Type   | Value                               |
+----------+--------+-------------------------------------+
| fake.png | URL    | http://evil.example.com/payload.bin |
| fake.png | IP     | 185.220.101.45                      |
| fake.png | DOMAIN | bad-site.ru                         |
| fake.png | EMAIL  | admin@bad-site.ru                   |
...
```

加上 `--vt` 後，總覽表會多出 `VT detect`、`VT verdict` 兩欄，並多一張 VirusTotal 明細表
（Malicious / Suspicious / Harmless / Undetected 數量、Threat label、網頁連結）。

---

## 偵測規則

### Magic number 與副檔名不符
讀取檔案前 512 bytes，比對已知簽章（PNG、JPEG、PDF、ZIP、Office、PE、ELF、RAR、7z、SQLite、MP4 等）。

- 辨識出類型，但副檔名不在該類型的合法清單內 → `MISMATCH`
- 副檔名要求特定檔頭（如 `.png`、`.pdf`、`.exe`），卻找不到任何已知簽章 → `MISMATCH`
- `.docx`、`.xlsx`、`.jar`、`.apk` 等本質上是 ZIP 的格式，不會誤報

### 字串 / IOC 擷取
- 同時抓 ASCII 與 UTF-16LE 字串（Windows 程式常用）
- URL、Email、IPv4（排除不合法與 `0.x.x.x`，依數值排序）、Domain（只接受常見 TLD，避免把 `kernel32.dll` 當網域）
- 檔案超過 `--max-bytes` 時只掃前面部分，JSON 內的 `iocs.truncated` 會是 `true`

---

## 報告欄位

**JSON**（完整資料，每個檔案一筆）：metadata、`detected_type`、`extension_mismatch`、`magic_note`、
`magic_hex`、`hashes`（md5 / sha1 / sha256）、
`virustotal`（有 `--vt` 時）、`iocs`（urls / ips / domains / emails）。

**CSV**（每個檔案一列，IOC 以 `;` 分隔）：以 UTF-8 with BOM 存檔，Excel 直接開啟中文不會亂碼。

VirusTotal 的 `vt_verdict`：

| 值 | 意義 |
|---|---|
| `MALICIOUS` | 至少一個引擎判定為惡意 |
| `SUSPICIOUS` | 沒有惡意判定，但至少一個引擎判定可疑 |
| `CLEAN` | 沒有惡意或可疑判定 |
| `UNKNOWN` | VirusTotal 資料庫沒有這個雜湊。**不代表安全**，只是沒人上傳過 |

---

## Windows 注意事項

- **權限欄位**：Windows 的 `st_mode` 只是模擬值，沒有參考價值，所以 `mode_octal`、`mode_str`、`uid`、`gid` 在 Windows 上是空值，改看 `win_attributes`（如 `READONLY|HIDDEN|ARCHIVE`）與 `is_reparse_point`。
- **擁有者與 ACL**：加 `--acl` 才會取得，JSON 內有 `owner`、`acl`、`acl_everyone_write`。
- **建立時間**：Windows 與 macOS 是真正的建立時間；Linux 沒有，顯示的是 inode 變更時間。
- **中文輸出亂碼**：使用 Windows Terminal 或 VS Code 內建終端機，必要時先執行
  `$env:PYTHONUTF8 = "1"`。

---

## 已知限制

- Magic number 只看檔頭；攻擊者可在檔案前面補上假檔頭。2 bytes 的簽章（`MZ`、`BM`）也可能誤判。
- 字串擷取只涵蓋 ASCII 與 UTF-16LE 的英數符號，不含中文字串；版本號（如 `1.2.3.4`）可能被誤判為 IP；`main.cc`、`build.pl` 這類檔名可能被誤判為網域。
- VirusTotal 免費 API 約每分鐘 4 次、每天 500 次；程式遇到 429 會自動等待重試。
- `--acl` 依賴 `icacls` 與 PowerShell。

## 授權與用途

MIT License