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

## License

Dự án có thể sử dụng license tùy chọn như MIT License.  
Nếu bạn dùng lại `yarGen.py`, hãy kiểm tra và tuân thủ license của dự án gốc.
