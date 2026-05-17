# yarGen GUI - Malware Family YARA Builder

<p align="center">
  <b>Công cụ desktop hỗ trợ tự động tạo chữ ký YARA từ đặc trưng chung của một họ mã độc</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" />
  <img src="https://img.shields.io/badge/GUI-Tkinter%2FTTK-green" />
  <img src="https://img.shields.io/badge/YARA-Rule%20Generation-red" />
  <img src="https://img.shields.io/badge/Use-Malware%20Analysis-orange" />
</p>

---

## Giới thiệu

**yarGen GUI - Malware Family YARA Builder** là công cụ desktop hỗ trợ quy trình tạo chữ ký YARA từ nhiều mẫu mã độc thuộc cùng một họ malware.

Công cụ này sử dụng `yarGen.py` làm engine chính để trích xuất đặc trưng và sinh YARA rule. GUI không thay đổi thuật toán lõi của yarGen, mà bổ sung giao diện, workflow, kiểm tra môi trường, giám sát tiến trình, validate rule, test false positive và xuất báo cáo.

Mục tiêu chính của project là phục vụ đề tài:

> **Xây dựng công cụ tự động tạo chữ ký YARA từ các đặc trưng chung của một họ mã độc**

---

## Công cụ này giải quyết vấn đề gì?

Trong môn **Phân tích mã độc**, sau khi phân tích nhiều mẫu malware cùng family, analyst thường cần tạo chữ ký phát hiện để nhận diện các biến thể tương tự.

Nếu làm thủ công, quy trình thường gồm:

1. Thu thập mẫu malware cùng họ.
2. Phân tích tĩnh từng mẫu.
3. Trích xuất strings, hash, PE info, import/export.
4. Tìm đặc trưng chung giữa các mẫu.
5. Viết YARA rule.
6. Validate cú pháp.
7. Test trên malware.
8. Test trên goodware để kiểm false positive.
9. Viết báo cáo.

Công cụ này tự động hóa và trực quan hóa workflow đó:

```text
Malware samples cùng family
→ phân tích sample
→ chạy yarGen.py
→ tạo YARA rule
→ giám sát tiến trình
→ validate syntax
→ test malware/goodware
→ chấm điểm rule
→ xuất báo cáo
```

---

## Tính năng chính

### 1. Workflow GUI dễ dùng

- Sidebar theo từng bước.
- Home Dashboard hướng dẫn người mới.
- Basic Mode cho người mới.
- Advanced Mode cho người dùng kỹ thuật.
- Light/Dark theme.
- Hỗ trợ Tiếng Việt và English.

### 2. Kiểm tra môi trường

Tab **Setup** kiểm tra:

- Python executable.
- Working directory.
- `yarGen.py`.
- `requirements.txt`.
- Folder `dbs/`.
- Folder `3rdparty/`.
- Các module Python cần thiết như `pefile`, `lxml`, `yara`.

### 3. Phân tích sample

Tab **Samples** hỗ trợ:

- Scan folder malware.
- Tính MD5.
- Tính SHA256.
- Nhận diện file type.
- Cảnh báo file nén chưa giải nén.
- Trích strings nhẹ để hỗ trợ clustering.
- Gom cụm các sample giống nhau.

### 4. Malware Family Workflow

Tab **Family** hỗ trợ:

- Nhập tên malware family.
- Tạo `identifier.txt`.
- Kiểm tra số lượng mẫu.
- Áp preset family rule.
- Đảm bảo người dùng đang tạo rule từ nhiều mẫu cùng họ.

### 5. Generate YARA rule

Tab **Generate** hỗ trợ:

- Chọn malware sample folder.
- Chọn output `.yar`.
- Chọn string export folder.
- Chọn preset.
- Chọn DB mode.
- Xem command yarGen trước khi chạy.
- Lưu command `.bat` hoặc `.sh`.
- Chạy `yarGen.py` bằng subprocess.

### 6. Monitor realtime

Tab **Monitor** hiển thị:

- Log realtime.
- Progress bar.
- Stage table.
- Preview file `.yar`.
- Thống kê số rule, simple rule, super rule và strings.

### 7. Validate và Test

Tab **Validate/Test** hỗ trợ:

- Validate syntax bằng `yara-python` hoặc `yarac`.
- Test rule trên malware folder.
- Test rule trên goodware folder.
- Phát hiện false positive.
- Export CSV/HTML report.

### 8. Database Inspector

Tab **Database** hỗ trợ:

- Xem trạng thái folder `dbs/`.
- Xem các nhóm DB:
  - `good-strings`
  - `good-opcodes`
  - `good-exports`
  - `good-imphashes`
- Xem size và số entry.
- Preview DB.
- Tạo/cập nhật goodware DB.

### 9. Rule Score Report

Tab **Reports** hỗ trợ:

- Đọc file `.yar/.yara`.
- Trích xuất score của từng string.
- Tính Max Score, Avg Score, Min Score.
- Đánh giá độ tin cậy của từng rule.
- Vẽ biểu đồ Max Score.
- Xuất Markdown/CSV report.

---

## Kiến trúc project

Project được tách theo kiến trúc modular để dễ sửa và mở rộng.

```text
.
├── main.py
├── app.py
├── requirements.txt
├── README.md
│
├── core/
│   ├── config.py
│   ├── settings.py
│   ├── i18n.py
│   ├── state.py
│   ├── utils.py
│   ├── yargen_command.py
│   ├── validators.py
│   ├── yara_score.py
│   ├── report_builder.py
│   └── runner.py
│
├── widgets/
│   ├── sidebar.py
│   ├── statusbar.py
│   └── cards.py
│
└── screens/
    ├── welcome_screen.py
    ├── home_screen.py
    ├── setup_screen.py
    ├── samples_screen.py
    ├── family_screen.py
    ├── generate_screen.py
    ├── monitor_screen.py
    ├── validate_screen.py
    ├── database_screen.py
    ├── reports_screen.py
    └── settings_screen.py
```

---

## Vai trò các module

| File/Folder | Chức năng |
|---|---|
| `main.py` | Entry point của app |
| `app.py` | Tạo main window, top bar, sidebar, status bar |
| `core/config.py` | Cấu hình chung, preset, extension, DB prefix |
| `core/settings.py` | Đọc/ghi `settings.json` |
| `core/i18n.py` | Hệ thống song ngữ Việt/Anh |
| `core/state.py` | Biến dùng chung trong GUI |
| `core/utils.py` | Hàm tiện ích về path, browse, open folder |
| `core/yargen_command.py` | Build command yarGen CLI |
| `core/validators.py` | Validate môi trường |
| `core/runner.py` | Chạy subprocess và đọc log realtime |
| `core/yara_score.py` | Phân tích score trong YARA rule |
| `core/report_builder.py` | Xuất report CSV/HTML |
| `widgets/` | Các widget dùng lại |
| `screens/` | Các màn hình chức năng |

---

## Cài đặt

### Yêu cầu

- Python 3.10+
- Windows 10/11 khuyến nghị
- `yarGen.py`
- Folder `dbs/`
- Folder `3rdparty/`
- Các package Python cần thiết

### Cài package

```powershell
pip install -r requirements.txt
```

Nếu thiếu `yara-python`:

```powershell
pip install yara-python
```

Nếu dùng yarGen cũ và gặp lỗi thiếu `scandir`:

```powershell
pip install scandir
```

---

## Cách chạy

Khuyến nghị đặt source GUI cùng thư mục với `yarGen.py`, `dbs/`, `samples/`.

Ví dụ:

```text
C:\DACK_MALWARE
├── main.py
├── app.py
├── core\
├── widgets\
├── screens\
├── yarGen.py
├── dbs\
├── 3rdparty\
├── samples\
├── rules\
├── strings_out\
└── reports\
```

Chạy app:

```powershell
cd C:\DACK_MALWARE
python main.py
```

Nếu dùng virtual environment:

```powershell
cd C:\DACK_MALWARE
.\venv\Scripts\python.exe main.py
```

---

## Workflow sử dụng

### Bước 1: Setup

Vào tab **Setup** và bấm:

```text
Validate environment
```

Mục tiêu là kiểm tra Python, `yarGen.py`, DB và các dependency.

### Bước 2: Samples

Vào tab **Samples**:

1. Chọn folder malware samples.
2. Bấm **Scan folder**.
3. Kiểm tra file type, MD5, SHA256.
4. Nếu cần, bấm **Cluster similar samples**.

### Bước 3: Family

Vào tab **Family**:

1. Nhập tên family, ví dụ `TrickBot`.
2. Tạo `identifier.txt`.
3. Bấm **Apply Family Rule preset**.

### Bước 4: Generate

Vào tab **Generate**:

1. Chọn preset.
2. Chọn DB mode.
3. Kiểm tra input/output.
4. Bấm **Preview command**.
5. Bấm **Generate YARA rule**.

### Bước 5: Monitor

Vào tab **Monitor** để xem:

- DB loading.
- Processing samples.
- Generate statistics.
- Generate simple/super rules.
- Preview rule.
- YARA summary.

### Bước 6: Validate/Test

Vào tab **Validate/Test**:

1. Bấm **Validate syntax**.
2. Bấm **Test malware**.
3. Bấm **Test goodware**.
4. Export CSV/HTML nếu cần.

### Bước 7: Reports

Vào tab **Reports**:

1. Chọn file `.yar`.
2. Bấm **Analyze Rule Scores**.
3. Xem bảng score và biểu đồ.
4. Export Markdown/CSV.

---

## Preset

| Preset | Mục đích |
|---|---|
| Beginner | Cấu hình cân bằng cho lần chạy đầu tiên |
| PE Deep | Phân tích PE sâu hơn, có thể chậm hơn |
| Script Malware | Dành cho PowerShell, JS, VBS, BAT/CMD |
| Webshell | Dành cho PHP, ASP, ASPX, JSP |
| Fast Scan | Chạy nhanh để demo hoặc triage |
| TrickBot Demo | Cấu hình cân bằng cho mẫu TrickBot |
| Loose Debug | Debug khi yarGen sinh 0 rule, không dùng làm rule cuối |

---

## DB Mode

| DB Mode | Ý nghĩa |
|---|---|
| Full quality DB | Dùng đầy đủ DB, chất lượng tốt hơn nhưng chậm hơn |
| Fast strings DB | Dùng DB strings nhẹ hơn |
| Fast no-opcodes DB | Bỏ opcodes DB nặng, phù hợp demo nhanh |

---

## Goodware DB

Goodware DB là database chứa đặc trưng của phần mềm sạch.

yarGen dùng Goodware DB để:

- Trừ điểm string phổ biến.
- Loại string dễ gây false positive.
- Tạo rule đáng tin cậy hơn.

Các nhóm DB thường gặp:

```text
good-strings-part*.db
good-opcodes-part*.db
good-exports-part*.db
good-imphashes-part*.db
```

---

## SIMPLE Rule và SUPER Rule

### SIMPLE Rule

Rule được tạo cho từng sample hoặc từng file cụ thể.

### SUPER Rule

Rule được tạo từ các đặc trưng chung xuất hiện trong nhiều sample.

Trong đề tài này, **SUPER Rule rất quan trọng** vì nó thể hiện việc tìm đặc trưng chung của một malware family.

---

## Rule Score

Khi bật `--score`, yarGen gắn điểm vào từng string.

Ví dụ:

```yara
$x1 = "ReflectiveLoader" ascii fullword /* score: '41.00' */
$s2 = "kernel32.dll" ascii fullword /* score: '-5.00' */
```

Ý nghĩa:

```text
Score cao  → string đặc trưng hơn
Score thấp → string bình thường
Score âm   → string phổ biến hoặc dễ false positive
```

Mức đánh giá trong GUI:

| Max Score | Đánh giá |
|---:|---|
| > 35 | Rất cao |
| > 25 | Cao |
| > 10 | Trung bình |
| <= 10 | Thấp |
| Không có score | Không đủ dữ liệu |

---

## Demo nhanh

```text
Setup
→ Validate environment

Samples
→ Chọn samples\TrickBot
→ Scan folder

Family
→ Family name = TrickBot
→ Apply Family Rule preset

Generate
→ Preset = TrickBot Demo
→ DB Mode = Fast no-opcodes DB hoặc Full quality DB
→ Generate YARA rule

Monitor
→ Xem log và progress

Validate/Test
→ Validate syntax
→ Test malware
→ Test goodware

Reports
→ Analyze Rule Scores
→ Export Markdown/CSV
```

---

## Lỗi thường gặp

### Không thấy DB

Nguyên nhân thường là sai Working directory.

Cách sửa:

```text
Setup → Working directory = thư mục chứa yarGen.py và dbs/
```

---

### Generate chạy lâu

Nguyên nhân:

- Full quality DB lớn.
- Opcode DB nặng.
- Sample nhiều.

Cách xử lý:

- Dùng `Fast no-opcodes DB` khi demo.
- Không bật `--opcodes` nếu không cần.
- Dùng Full quality DB khi tạo rule cuối.

---

### yarGen sinh 0 rule

Nguyên nhân có thể:

- Sample bị pack/encrypt.
- Sample quá ít strings.
- File chưa giải nén.
- Folder trộn nhiều family.
- Tham số quá chặt.

Cách xử lý:

- Dùng preset `Loose Debug`.
- Bật `--score`.
- Bật `--strings`.
- Giảm `-z`.
- Giảm `-x`.
- Tăng `-s`.
- Kiểm tra sample bằng tab Samples.

---

### Reports không có score

Nguyên nhân:

- Khi generate chưa bật `--score`.

Cách xử lý:

```text
Generate → bật --score → Generate lại
```

---

### Rule match goodware

Đây là false positive.

Cách xử lý:

- Tăng `-z`.
- Tăng `-x`.
- Loại string phổ biến.
- Dùng Full quality DB.
- Test lại goodware.

---

## Lưu ý an toàn

- Chỉ phân tích malware trong máy ảo hoặc sandbox.
- Không double-click/chạy malware thật.
- Không upload malware thật lên GitHub.
- Không commit folder `samples/`, `malware/`, `dbs/`, `venv/`.
- Project chỉ phục vụ học tập, nghiên cứu và phòng thủ.

---

## Gợi ý `.gitignore`

```gitignore
# Database files
dbs/
*.db

# Virtual environment
venv/
.venv/
env/

# Python cache
__pycache__/
*.pyc
*.pyo

# IDE files
.vscode/
.idea/

# OS files
.DS_Store
Thumbs.db
desktop.ini

# Logs and temporary files
logs/
*.log
*.tmp
*.temp

# Generated outputs
rules/
strings_out/
reports/
clusters/
_gui_runtime/

# Malware samples
samples/
malware/
goodware/

# Archives and binaries
*.zip
*.rar
*.7z
*.tar
*.gz
*.exe
*.dll
*.sys
*.scr
*.com
*.bin

# Local settings
settings.json
*.local.json
```

---

## Câu mô tả ngắn cho báo cáo

> Công cụ được xây dựng nhằm hỗ trợ tự động tạo chữ ký YARA từ nhiều mẫu thuộc cùng một họ mã độc. Hệ thống sử dụng `yarGen.py` làm engine để trích xuất đặc trưng và sinh rule, sau đó cung cấp GUI để kiểm tra môi trường, phân tích sample, giám sát tiến trình, validate cú pháp, test malware/goodware, đánh giá false positive, chấm điểm rule và xuất báo cáo.

---

## Disclaimer

Công cụ được xây dựng cho mục đích học tập, nghiên cứu và phòng thủ an toàn thông tin.

Không sử dụng công cụ để phát triển, phát tán hoặc vận hành mã độc.

`yarGen.py` là engine bên ngoài thuộc dự án/tác giả gốc. GUI này chỉ là lớp hỗ trợ workflow và không thay đổi thuật toán lõi của yarGen.

---

## 25. Quick Command

```powershell
cd C:\DACK_MALWARE
.\venv\Scripts\python.exe main.py
```

Nếu chạy lần đầu:

```text
Welcome → chọn ngôn ngữ
Setup → Validate environment
Samples → Scan folder
Generate → Generate YARA rule
Monitor → xem progress
Validate/Test → kiểm tra rule
Reports → Analyze rule scores
```
#   A u t o m a t e d - Y A R A - R u l e - G e n e r a t i o n - T o o l 
 
 #   A u t o m a t e d - Y A R A - R u l e - G e n e r a t i o n - T o o l 
 
 
---

## Update 3.2.0 - Tích hợp yarGen + VirusTotal/YARA engine

Bản này làm rõ đúng hướng đề tài:

> **Xây dựng công cụ tự động tạo chữ ký YARA từ các đặc trưng chung của một họ mã độc**

Ứng dụng hiện dùng cả hai lớp:

1. **yarGen**: sinh rule YARA có score từ thư mục malware sample.
2. **YARA engine chính thức**: validate cú pháp và scan malware/goodware bằng `yara-python` hoặc YARA CLI build từ source `VirusTotal/yara`.

### Workflow đề xuất

```text
Samples cùng family
→ Family: phân tích folder
→ Family: Generate common rule
→ Generate: chạy yarGen
→ Family: Merge with yarGen rule
→ Validate/Test: Detect YARA engine
→ Validate/Test: Validate syntax
→ Validate/Test: Test malware + goodware
→ Analysis Suite: Quality Gate / Rule Doctor / Analyst Report
```

### Family common-feature rule

Tab **Family** được bổ sung:

- `Common-feature rule output`: file rule phụ sinh từ đặc trưng chung.
- `Coverage ratio`: tỉ lệ mẫu phải cùng chứa một feature, mặc định `0.60`.
- `Min string length`: độ dài string tối thiểu.
- `Max common features`: số đặc trưng tối đa đưa vào rule.
- `Generate common rule`: trích strings chung từ nhiều mẫu trong cùng family và sinh rule YARA.
- `Merge with yarGen rule`: ghép rule của yarGen với rule đặc trưng chung thành một file cuối.
- `Validate common rule`: kiểm tra rule bằng YARA engine.

### YARA engine

App tự động ưu tiên backend theo thứ tự:

1. `yara-python`, nếu cài được bằng `pip install yara-python`.
2. `yara` CLI từ PATH.
3. Binary `yara` nằm trong thư mục local như `yara-master/cli/yara` nếu bạn đã build source `VirusTotal/yara`.

Thư mục `yara-master` trong project là source chính thức của YARA. Nếu chưa build binary, app vẫn nhận diện source này trong tab **Setup**, nhưng để scan/validate cần cài `yara-python` hoặc build CLI.

### File mới / file đã cập nhật

- `core/family_signature.py`: trích đặc trưng chung và sinh YARA rule.
- `core/yara_engine.py`: wrapper dùng `yara-python` hoặc YARA CLI.
- `screens/family_screen.py`: thêm workflow common-feature rule và merge.
- `screens/validate_screen.py`: validate/scan qua YARA engine wrapper.
- `core/validators.py`: kiểm tra cả yarGen, source VirusTotal/YARA và YARA engine.
- `core/state.py`: thêm biến cấu hình cho common rule và merged rule.

## Final test checklist

Bản `3.2.1-final-tested` đã được kiểm thử các luồng chính:

1. `python -m compileall .` để kiểm tra lỗi cú pháp toàn bộ source.
2. Import các module chính: `app`, `main`, `core.family_signature`, `core.yara_engine`, `screens.family_screen`, `screens.validate_screen`.
3. Tạo sample giả lập cùng họ mã độc, trích đặc trưng chung, sinh rule `*_CommonFamilyFeatures`, xuất CSV/Markdown report.
4. Compile rule và scan sample bằng `yara-python` khi dependency khả dụng.
5. Smoke test GUI bằng Tkinter/Xvfb: app khởi động, build đủ 12 màn hình, rồi đóng sạch.

Khuyến nghị cài dependency trước khi chạy validate/scan thật:

```bash
pip install -r requirements.txt
# hoặc tối thiểu cho YARA engine:
pip install yara-python
```

Nếu chưa cài `pygame`, app vẫn chạy bình thường; phần nhạc nền sẽ tự tắt thay vì làm app crash.



## YARA-X support

This build supports both classic YARA and YARA-X. The engine wrapper checks backends in this order:

1. `yara-x` Python module (`pip install yara-x`)
2. `yr` CLI from VirusTotal/yara-x
3. `yara-python`
4. classic `yara` CLI

For the newest YARA-X workflow, install:

```bash
pip install yara-x
```

Or install the official `yr` binary / build it with Rust:

```bash
git clone https://github.com/VirusTotal/yara-x
cd yara-x
cargo install --path cli
```

The Validate/Test screen uses YARA-X compilation/scanning when available, while yarGen is still used to generate initial rules from malware-family samples.

## Validate & Test note

`Detect YARA engine` chi kiem tra backend va duong dan. Nut nay khong scan file. Quy trinh dung:

1. Bam `Detect YARA engine` de xem app dang dung `yara-x`, `yara-python`, `yr`, hay `yara` CLI.
2. Bam `Validate syntax` de kiem tra file `.yar`.
3. Bam `Test malware` de scan thu muc malware.
4. Neu co goodware folder, bam `Test goodware` de do false positive.

Neu detect thanh cong nhung scan khong co match, rule hop le nhung khong khop sample trong folder da chon. Kiem tra lai rule, folder, hoac sample malware.


## Official VirusTotal/YARA CLI backend

Bản 3.2.4 ưu tiên dùng trực tiếp công cụ YARA chính thức nếu bạn đặt các file sau trong thư mục gốc của app:

```text
yara64.exe   hoặc yara.exe
yarac64.exe  hoặc yarac.exe
```

Khi bấm **Detect official YARA CLI**, app sẽ ưu tiên backend `yara-cli`. Nếu backend hiện là `yara-cli`, app đang gọi trực tiếp executable từ dự án VirusTotal/yara:

```text
yarac64.exe rule.yar out.compiled     # validate/compile rule
yara64.exe rule.yar sample.exe        # scan/nhận diện file
```

Nếu không tìm thấy hoặc không chạy được `yara64.exe`, app mới fallback sang `yara-python`.

Flow test đúng:

```text
1. Chọn Rule file (.yar)
2. Chọn Malware folder
3. Bấm Detect official YARA CLI
4. Bấm Validate syntax
5. Bấm Test malware
6. Xem dòng [MATCH] rule_name -> file_name trong log
```

## Version 3.3.0 - Correct workflow update

Main logic has been reorganized:

1. **Analyze Malware** is the main workflow for uploading one malware sample and automatically assessing it.
   - Static-only analysis: hash, file type, entropy, printable strings, PE sections/imports.
   - Optional YARA scan against an existing `.yar/.yara` rule file or rule folder.
   - Uses official VirusTotal/YARA CLI (`yara64.exe` / `yara.exe`) when present, then falls back to Python backends.
   - Generates a quick triage YARA rule and Markdown assessment report.

2. **Family** remains the thesis-focused workflow for generating a YARA signature from common features across multiple samples from the same malware family.

3. **Validate & Test** is now clearly treated as a post-generation QA step:
   - Validate generated rule syntax.
   - Scan malware folder.
   - Scan a separate clean goodware folder to check false positives.
   - Do not choose the project root as goodware because it may contain malware samples.

Recommended demo flow:

```text
Analyze Malware -> Save suggested rule -> Family/Common features for multiple samples -> Validate & Test generated rule
```
