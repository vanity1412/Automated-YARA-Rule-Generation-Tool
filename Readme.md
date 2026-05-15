# yarGen GUI - Malware Family YARA Builder

> Công cụ desktop hỗ trợ **tự động tạo chữ ký YARA từ các đặc trưng chung của một họ mã độc**.  
> GUI này **không thay đổi engine `yarGen.py`**, mà đóng vai trò là lớp giao diện, workflow, validation, monitoring, testing và reporting để giúp sinh viên/analyst dễ sử dụng yarGen hơn trong môn **Phân tích mã độc**.

---

## 1. Mục tiêu của công cụ

Trong quá trình học và thực hành phân tích mã độc, sinh viên thường phải:

1. Thu thập nhiều mẫu mã độc cùng một họ.
2. Phân tích tĩnh để trích xuất strings, hash, PE info, import/export.
3. Tìm các đặc trưng chung giữa các mẫu.
4. Viết YARA rule thủ công.
5. Kiểm tra cú pháp rule.
6. Test rule trên malware và goodware.
7. Đánh giá false positive.
8. Viết báo cáo.

Công cụ này giúp tự động hóa và trực quan hóa các bước trên:

```text
Malware samples cùng family
→ phân tích sample
→ chạy yarGen.py
→ tạo rule YARA
→ giám sát quá trình generate
→ validate rule
→ test malware/goodware
→ chấm điểm rule
→ xuất báo cáo
```

Công cụ phù hợp với đề tài:

```text
Xây dựng công cụ tự động tạo chữ ký YARA từ các đặc trưng chung của một họ mã độc
```

---

## 2. Công cụ này dùng để làm gì?

Công cụ được dùng để hỗ trợ quá trình **phân tích mã độc ứng dụng** và **xây dựng chữ ký phát hiện mã độc**.

Cụ thể:

- Nhận vào nhiều mẫu malware cùng một họ.
- Trích xuất đặc trưng tĩnh như strings, hash, file type.
- Gọi engine `yarGen.py` để sinh YARA rule.
- Dùng goodware database để giảm false positive.
- Sinh SIMPLE rules và SUPER rules.
- Validate cú pháp YARA.
- Test rule trên malware folder.
- Test rule trên goodware/benign folder.
- Chấm điểm rule dựa trên `score` của yarGen.
- Xuất báo cáo phục vụ demo, bài lab hoặc đồ án.

---

## 3. Điểm khác biệt so với chạy yarGen CLI

Nếu chạy yarGen CLI thủ công, bạn thường chỉ nhận được file `.yar`.

Ví dụ:

```powershell
python yarGen.py -m samples\TrickBot -o rules\trickbot.yar --score --strings
```

GUI này bổ sung thêm:

- Giao diện dễ dùng.
- Sidebar workflow rõ ràng.
- Basic Mode / Advanced Mode.
- Chọn preset phù hợp từng loại malware.
- Kiểm tra môi trường.
- Kiểm tra DB.
- Phân tích sample trước khi generate.
- Theo dõi log realtime.
- Progress dashboard.
- Preview file `.yar`.
- Validate syntax.
- Test malware/goodware.
- Chấm điểm rule.
- Xuất Markdown/CSV/HTML report.
- Hỗ trợ Tiếng Việt / English.
- Light / Dark theme.

---

## 4. Kiến trúc mã nguồn

Dự án được tổ chức theo kiến trúc modular để dễ bảo trì và sửa lỗi.

```text
yargen_gui_redesign_v3/
├── main.py
├── app.py
├── README.md
├── settings.json                 # Tạo tự động sau khi chạy app
│
├── core/
│   ├── __init__.py
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
│   ├── __init__.py
│   ├── sidebar.py
│   ├── statusbar.py
│   └── cards.py
│
└── screens/
    ├── __init__.py
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

## 5. Vai trò từng file/folder

### `main.py`

Entry point của ứng dụng.

Chạy app bằng:

```powershell
python main.py
```

Nội dung chính:

```python
from app import YarGenApp

if __name__ == "__main__":
    YarGenApp().mainloop()
```

---

### `app.py`

Tạo cửa sổ chính của GUI.

Chức năng:

- Tạo main window.
- Tạo top bar.
- Tạo sidebar.
- Tạo status bar.
- Load các màn hình trong `screens/`.
- Quản lý chuyển màn hình.
- Quản lý language/theme/mode.
- Khởi tạo `AppState`, `SettingsManager`, `I18n`, `ProcessRunner`.

---

### `core/config.py`

Chứa cấu hình cố định:

- Tên app.
- Version.
- Danh sách extension malware/script/PE.
- Danh sách prefix DB.
- Danh sách sidebar navigation.
- Mô tả preset.

Sửa file này nếu muốn:

- Đổi version.
- Thêm extension mới.
- Thêm preset description.
- Đổi danh sách sidebar.

---

### `core/settings.py`

Quản lý file `settings.json`.

Lưu các cấu hình:

- Ngôn ngữ.
- Theme.
- Basic/Advanced Mode.
- DB mode mặc định.
- Số dòng log giữ lại.

---

### `core/i18n.py`

Quản lý song ngữ Tiếng Việt / English.

Ví dụ:

```python
TRANSLATIONS = {
    "vi": {
        "generate.title": "Tạo YARA rule"
    },
    "en": {
        "generate.title": "Generate YARA Rules"
    }
}
```

Muốn thêm text mới thì thêm key vào file này.

---

### `core/state.py`

Chứa toàn bộ biến dùng chung cho GUI.

Ví dụ:

- Đường dẫn Python.
- Đường dẫn `yarGen.py`.
- Working directory.
- Malware folder.
- Output rule path.
- Rule parameters.
- DB mode.
- Test folder.
- Report folder.
- Progress state.
- Last command.
- Last test result.

Đây là file quan trọng để các màn hình dùng chung dữ liệu.

---

### `core/utils.py`

Chứa các hàm tiện ích:

- Mở file/folder.
- Browse file/folder.
- Chuẩn hóa path.
- Tạo dòng input path.
- Quote command.
- Tạo safe identifier.

---

### `core/yargen_command.py`

Build command CLI để chạy `yarGen.py`.

Ví dụ GUI sẽ build command dạng:

```powershell
python -W ignore yarGen.py -m samples\TrickBot -o rules\trickbot.yar -a "yarGen GUI" -p "TrickBot family rule" --score --strings
```

Nếu muốn sửa cách tạo command, sửa file này.

---

### `core/validators.py`

Kiểm tra môi trường:

- Python executable.
- Working directory.
- `yarGen.py`.
- `requirements.txt`.
- `dbs/`.
- `3rdparty/strings.xml`.
- Python module `pefile`, `lxml`, `yara`.

---

### `core/runner.py`

Chạy subprocess.

Chức năng:

- Chạy command yarGen.
- Đọc log realtime.
- Đẩy log lên Monitor.
- Cập nhật trạng thái Running/Idle.
- Gọi callback sau khi generate xong.

---

### `core/yara_score.py`

Phân tích file `.yar/.yara`.

Chức năng:

- Tách từng rule.
- Đếm số strings.
- Trích xuất score trong comment:

```yara
/* score: '41.00' */
```

- Tính:
  - Max Score.
  - Avg Score.
  - Min Score.
  - Confidence.
  - Số Goodware String.
  - Số score âm.
  - Rule có phải Super Rule hay không.
- Tạo báo cáo Markdown.

---

### `core/report_builder.py`

Xuất báo cáo test:

- CSV.
- HTML.

Dùng cho kết quả scan malware/goodware.

---

### `widgets/sidebar.py`

Sidebar bên trái.

Chứa các mục:

- Home
- Setup
- Samples
- Family
- Generate
- Monitor
- Validate/Test
- Database
- Reports
- Settings

---

### `widgets/statusbar.py`

Status bar dưới cùng.

Hiển thị:

- Environment status.
- Project path.
- Preset đang dùng.
- Output rule.
- Running status.

---

### `widgets/cards.py`

Widget card dùng ở Home Dashboard.

---

### `screens/`

Mỗi file trong `screens/` là một màn hình chức năng riêng.

Điều này giúp dễ sửa hơn so với gom toàn bộ GUI vào một file lớn.

---

## 6. Các màn hình chức năng

### 6.1 Welcome Screen

File:

```text
screens/welcome_screen.py
```

Chức năng:

- Hiện khi chạy app lần đầu.
- Cho chọn:
  - Tiếng Việt.
  - English.
- Có tùy chọn remember language.

---

### 6.2 Home Dashboard

File:

```text
screens/home_screen.py
```

Đây là màn hình tổng quan workflow.

Hiển thị các bước chính:

```text
Setup → Samples → Generate → Monitor → Validate/Test → Reports
```

Dùng để hướng dẫn người mới biết nên bắt đầu từ đâu.

---

### 6.3 Setup

File:

```text
screens/setup_screen.py
```

Chức năng:

- Chọn Python executable.
- Chọn Working directory.
- Chọn `yarGen.py`.
- Validate environment.
- Install requirements.
- Download/update DBs.

Các nút chính:

- `Validate environment`
- `Install requirements`
- `Download / update DBs`
- `Open project folder`

Mục tiêu:

```text
Đảm bảo môi trường sẵn sàng trước khi generate rule.
```

---

### 6.4 Samples

File:

```text
screens/samples_screen.py
```

Chức năng:

- Chọn folder malware samples.
- Scan folder.
- Tính:
  - MD5.
  - SHA256.
  - File type.
  - File size.
  - Archive warning.
- Trích strings nhẹ để hỗ trợ clustering.
- Cluster các sample giống nhau.
- Generate rule per cluster.

Dùng khi:

```text
Bạn có nhiều mẫu malware và muốn kiểm tra chúng có cùng family không.
```

---

### 6.5 Family

File:

```text
screens/family_screen.py
```

Chức năng:

- Nhập tên malware family.
- Nhập mục tiêu rule.
- Nhập số sample tối thiểu.
- Tạo `identifier.txt`.
- Áp preset Family Rule.
- Phân tích folder family.

Mục tiêu:

```text
Đảm bảo người dùng đang tạo rule từ nhiều mẫu cùng một họ mã độc.
```

---

### 6.6 Generate

File:

```text
screens/generate_screen.py
```

Đây là màn hình quan trọng nhất.

Chức năng:

- Chọn preset.
- Chọn DB Mode.
- Chọn malware folder.
- Chọn output `.yar`.
- Chọn string export folder.
- Nhập author/reference/license/prefix.
- Cấu hình tham số yarGen.
- Bật/tắt option CLI.
- Preview command.
- Generate rule.
- Stop process.
- Save command `.bat` hoặc `.sh`.

---

### 6.7 Monitor

File:

```text
screens/monitor_screen.py
```

Chức năng:

- Hiển thị log realtime.
- Hiển thị progress bar.
- Hiển thị stage table:
  - Preflight
  - Load goodware DB
  - Extract strings/opcodes
  - Generate statistics
  - Generate simple/super rules
  - Validate/Test
- Preview output rule.
- Hiển thị summary:
  - số rule.
  - số simple rule.
  - số super rule.
  - số strings.
  - số `$x`.
  - số `$s`.

Mục tiêu:

```text
Giúp người dùng thấy yarGen đang chạy tới đâu, tránh cảm giác app bị treo.
```

---

### 6.8 Validate/Test

File:

```text
screens/validate_screen.py
```

Chức năng:

- Validate YARA syntax.
- Test rule trên malware folder.
- Test rule trên goodware folder.
- Báo false positive.
- Export CSV.
- Export HTML.

Workflow:

```text
Validate syntax
→ Test malware
→ Test goodware
→ Export report
```

---

### 6.9 Database

File:

```text
screens/database_screen.py
```

Chức năng:

- Xem trạng thái DB trong folder `dbs/`.
- Xem nhóm DB:
  - good-strings
  - good-opcodes
  - good-exports
  - good-imphashes
- Xem size.
- Xem số entry.
- Preview DB.
- Tạo/cập nhật Goodware DB từ folder phần mềm sạch.

---

### 6.10 Reports

File:

```text
screens/reports_screen.py
```

Chức năng:

- Chọn file `.yar/.yara`.
- Analyze Rule Scores.
- Vẽ biểu đồ Max Score.
- Tạo báo cáo Markdown.
- Export Markdown.
- Export CSV.

Báo cáo gồm:

- Tên rule.
- Số strings.
- Số score.
- Max Score.
- Avg Score.
- Min Score.
- Confidence.
- Super Rule hay không.
- Nhận xét rule tốt nhất.

---

### 6.11 Settings

File:

```text
screens/settings_screen.py
```

Chức năng:

- Đổi language.
- Đổi theme.
- Đổi Basic/Advanced Mode.
- Save settings.
- Reset settings.

---

## 7. Preset trong Generate

### Beginner

Dành cho lần chạy đầu tiên.

Mục tiêu:

```text
Dễ dùng, cấu hình cân bằng.
```

---

### PE Deep

Dành cho malware PE.

Có thể bật:

- `--strings`
- `--opcodes`
- `--oe`
- `--debug`

Lưu ý:

```text
Chạy chậm hơn và tốn RAM hơn.
```

---

### Script Malware

Dành cho:

- PowerShell.
- JavaScript.
- VBS.
- BAT/CMD.

Tập trung vào strings script.

---

### Webshell

Dành cho:

- PHP.
- ASP.
- ASPX.
- JSP.

---

### Fast Scan

Dành cho demo nhanh hoặc triage.

Dùng DB runtime nhẹ:

```text
Fast no-opcodes DB
```

Không sửa folder `dbs` gốc.

---

### TrickBot Demo

Preset cân bằng cho mẫu TrickBot PE đã giải nén.

Thường bật:

- `--score`
- `--strings`

Và dùng tham số dễ sinh rule hơn.

---

### Loose Debug

Chỉ dùng để debug khi yarGen sinh 0 rule.

Không nên dùng làm rule cuối.

Vì preset này thường rất lỏng:

- Min score thấp.
- High score thấp.
- Có thể bật `--noscorefilter`.

---

## 8. DB Mode

### Full quality DB

Dùng toàn bộ DB goodware.

Ưu điểm:

- Rule tốt hơn.
- Ít false positive hơn.

Nhược điểm:

- Load lâu.
- Tốn RAM.

Dùng khi:

```text
Muốn tạo rule cuối hoặc demo chất lượng.
```

---

### Fast strings DB

Chỉ ưu tiên DB strings nhẹ.

Ưu điểm:

- Nhanh hơn full DB.

Dùng khi:

```text
Muốn demo nhanh nhưng vẫn có lọc strings.
```

---

### Fast no-opcodes DB

Bỏ qua opcodes DB nặng.

Ưu điểm:

- Chạy nhanh hơn.
- Phù hợp demo trên máy yếu.

Dùng khi:

```text
Muốn triage nhanh hoặc tránh lag.
```

---

## 9. Goodware DB là gì?

Goodware DB là database chứa đặc trưng của phần mềm sạch.

Ví dụ string phổ biến trong file sạch:

```text
kernel32.dll
LoadLibraryA
GetProcAddress
This program cannot be run in DOS mode
System.Drawing
```

Nếu dùng các string này trong rule, rule dễ match nhầm goodware.

Goodware DB giúp yarGen:

- Trừ điểm string phổ biến.
- Loại string không đặc trưng.
- Giảm false positive.

Folder DB thường nằm ở:

```text
C:\DACK_MALWARE\dbs
```

Các nhóm DB:

```text
good-strings-part*.db
good-opcodes-part*.db
good-exports-part*.db
good-imphashes-part*.db
```

---

## 10. Score trong YARA rule là gì?

Khi bật `--score`, yarGen thêm comment score vào từng string.

Ví dụ:

```yara
$x1 = "ReflectiveLoader" ascii fullword /* score: '41.00' */
$s2 = "kernel32.dll" ascii fullword /* score: '-5.00' */
```

Ý nghĩa:

```text
Score cao  → string đặc trưng hơn, đáng tin hơn
Score thấp → string bình thường
Score âm   → string phổ biến hoặc có nguy cơ false positive
```

---

## 11. Rule Score Report đánh giá như thế nào?

Công cụ phân tích từng rule và tính:

- Số strings.
- Số strings có score.
- Score cao nhất.
- Score trung bình.
- Score thấp nhất.
- Số Goodware String.
- Số score âm.
- Rule có phải Super Rule không.

Mức đánh giá:

```text
Max Score > 35        → Rất cao
Max Score > 25        → Cao
Max Score > 10        → Trung bình
Max Score <= 10       → Thấp
Không có score        → Không đủ dữ liệu
```

Lưu ý:

```text
Score report là điểm hỗ trợ review/demo, không phải điểm chính thức của YARA.
```

---

## 12. SIMPLE Rule và SUPER Rule

### SIMPLE Rule

Rule được tạo cho từng file hoặc từng sample.

Ưu điểm:

- Dễ sinh.
- Có thể bắt được mẫu cụ thể.

Nhược điểm:

- Có thể quá file-specific.

---

### SUPER Rule

Rule được tạo từ các đặc trưng chung của nhiều sample.

Ưu điểm:

- Phù hợp đề tài.
- Có khả năng đại diện cho một family/cluster.
- Hữu ích để phát hiện biến thể cùng họ.

Khi thuyết trình nên nhấn mạnh:

```text
SUPER Rule thể hiện việc công cụ tìm đặc trưng chung giữa nhiều mẫu malware cùng family.
```

---

## 13. Cài đặt

### 13.1 Yêu cầu

- Windows 10/11 hoặc Linux/macOS.
- Python 3.10+ khuyến nghị.
- `yarGen.py`.
- Folder `dbs/`.
- Folder `3rdparty/strings.xml`.
- Python packages:
  - `pefile`
  - `lxml`
  - `yara-python` nếu muốn validate/test bằng Python.

---

### 13.2 Cài requirements

Nếu project có `requirements.txt`:

```powershell
pip install -r requirements.txt
```

Nếu thiếu `yara-python`:

```powershell
pip install yara-python
```

Nếu thiếu `scandir` khi chạy yarGen cũ:

```powershell
pip install scandir
```

---

## 14. Cách chạy khuyến nghị

Giả sử project chính ở:

```text
C:\DACK_MALWARE
```

Nên copy source GUI vào thẳng `C:\DACK_MALWARE` để cấu trúc là:

```text
C:\DACK_MALWARE
├── main.py
├── app.py
├── core\
├── screens\
├── widgets\
├── yarGen.py
├── dbs\
├── 3rdparty\
├── samples\
├── rules\
├── strings_out\
└── reports\
```

Chạy:

```powershell
cd C:\DACK_MALWARE
.\venv\Scripts\python.exe main.py
```

---

## 15. Nếu để GUI trong folder riêng

Ví dụ:

```text
C:\DACK_MALWARE\yargen_gui_redesign_v3
```

Chạy:

```powershell
cd C:\DACK_MALWARE\yargen_gui_redesign_v3
C:\DACK_MALWARE\venv\Scripts\python.exe main.py
```

Sau khi mở app, vào Setup chỉnh:

```text
Working directory = C:\DACK_MALWARE
yarGen.py = C:\DACK_MALWARE\yarGen.py
```

Nếu không chỉnh, GUI sẽ tìm `dbs/`, `samples/`, `yarGen.py` trong folder GUI riêng, có thể bị báo thiếu.

---

## 16. Workflow demo đề xuất

### Bước 1: Setup

Vào:

```text
Setup
```

Bấm:

```text
Validate environment
```

Mục tiêu:

```text
Chứng minh môi trường, yarGen.py và DB đã sẵn sàng.
```

---

### Bước 2: Samples

Vào:

```text
Samples
```

Chọn folder mẫu:

```text
samples\TrickBot
```

Bấm:

```text
Scan folder
```

Quan sát:

- File type.
- Size.
- MD5.
- SHA256.
- Archive warning.
- Suggested preset.

---

### Bước 3: Family

Vào:

```text
Family
```

Nhập:

```text
Family name = TrickBot
```

Bấm:

```text
Apply Family Rule preset
```

---

### Bước 4: Generate

Vào:

```text
Generate
```

Chọn:

```text
Preset = TrickBot Demo
DB Mode = Full quality DB
```

Bấm:

```text
Generate YARA rule
```

---

### Bước 5: Monitor

Vào:

```text
Monitor
```

Quan sát:

- Load goodware DB.
- Process malware files.
- Generate statistics.
- Generate SIMPLE/SUPER rules.
- Preview rule.
- YARA summary.

---

### Bước 6: Validate/Test

Vào:

```text
Validate/Test
```

Bấm:

```text
Validate syntax
Test malware
Test goodware
```

Nếu có false positive, tăng `-z`, tăng `-x` hoặc chỉnh rule.

---

### Bước 7: Reports

Vào:

```text
Reports
```

Bấm:

```text
Analyze rule scores
Export Markdown
Export CSV
```

Dùng báo cáo để trình bày rule nào tốt nhất.

---

## 17. Lệnh CLI tương đương để debug

Nếu muốn chạy ngoài GUI:

```powershell
.\venv\Scripts\python.exe -W ignore .\yarGen.py `
  -m .\samples\TrickBot `
  -o .\rules\trickbot.yar `
  -e .\strings_out\trickbot `
  -a "yarGen GUI" `
  -p "TrickBot family rule" `
  -y 6 `
  -z 0 `
  -x 10 `
  -w 2 `
  -s 512 `
  -rc 30 `
  -fs 100 `
  -fm 5 `
  --score `
  --strings
```

---

## 18. Các lỗi thường gặp

### 18.1 Không thấy Goodware DB

Nguyên nhân:

- Working directory sai.
- Folder `dbs/` không nằm cùng project.
- GUI đặt trong folder riêng nhưng chưa chỉnh Setup.

Cách sửa:

```text
Setup → Working directory = C:\DACK_MALWARE
Setup → yarGen.py = C:\DACK_MALWARE\yarGen.py
```

---

### 18.2 yarGen báo `ModuleNotFoundError: scandir`

Cài:

```powershell
pip install scandir
```

Hoặc dùng bản yarGen đã chỉnh import phù hợp Python mới.

---

### 18.3 Generate lâu

Nguyên nhân:

- Full quality DB load hàng triệu strings.
- `good-opcodes` rất nặng.
- Sample nhiều hoặc dung lượng lớn.

Cách xử lý:

- Dùng `Fast no-opcodes DB` để demo nhanh.
- Dùng `Full quality DB` khi tạo rule cuối.
- Không bật `--opcodes` nếu không cần.
- Giải nén sample trước, không đưa `.7z/.zip` vào generate.
- Dùng cluster để chia sample theo nhóm.

---

### 18.4 yarGen sinh 0 rule

Nguyên nhân có thể:

- Sample không phải malware thật.
- Sample bị pack/encrypt, ít strings.
- Folder trộn nhiều family.
- Tham số score quá chặt.
- DB loại quá nhiều string.
- File sample là archive chưa giải nén.

Cách debug:

- Dùng `Loose Debug`.
- Bật `--score`.
- Bật `--strings`.
- Giảm `-z`.
- Giảm `-x`.
- Tăng `-s`.
- Dùng Sample Analyzer để kiểm tra file thật.
- Giải nén malware archive trước.
- Dùng nhiều sample cùng family.

---

### 18.5 Reports không có score

Nguyên nhân:

- Khi generate không bật `--score`.

Cách sửa:

```text
Generate → bật --score → Generate lại
```

---

### 18.6 Rule match goodware

Đây là false positive.

Cách xử lý:

- Tăng `-z`.
- Tăng `-x`.
- Loại string phổ biến.
- Kiểm tra Goodware String.
- Test lại trên goodware folder.
- Ưu tiên string có score cao và ít phổ biến.

---

## 19. Lưu ý an toàn khi dùng malware thật

- Chỉ phân tích malware trong máy ảo/sandbox.
- Không double-click hoặc chạy sample thật.
- Tắt chia sẻ clipboard/folder nếu không cần.
- Snapshot VM trước khi phân tích.
- Dùng folder cách ly.
- Không upload malware lên dịch vụ công khai nếu không được phép.
- Chỉ dùng công cụ cho mục đích học tập, nghiên cứu và phòng thủ.

---

## 20. Ý nghĩa trong môn Phân tích mã độc

Công cụ này giúp sinh viên hiểu quy trình:

```text
Phân tích tĩnh malware
→ trích xuất đặc trưng
→ tìm đặc trưng chung của family
→ tạo chữ ký YARA
→ kiểm thử rule
→ đánh giá false positive
→ viết báo cáo
```

Nó không chỉ tạo rule, mà giúp hoàn thiện vòng đời:

```text
Malware analysis → Detection engineering → Validation → Reporting
```

---

## 21. Câu mô tả ngắn cho báo cáo

Có thể dùng đoạn sau trong báo cáo đồ án:

> Công cụ được xây dựng nhằm hỗ trợ tự động tạo chữ ký YARA từ nhiều mẫu thuộc cùng một họ mã độc. Hệ thống sử dụng `yarGen.py` làm engine để trích xuất strings, opcode, imphash và exports từ mẫu malware, sau đó so sánh với goodware database nhằm loại bỏ các đặc trưng phổ biến trong phần mềm sạch. Giao diện GUI cung cấp workflow từ kiểm tra môi trường, phân tích mẫu, sinh rule, giám sát tiến trình, validate cú pháp, test malware/goodware, phát hiện false positive, chấm điểm rule và xuất báo cáo. Nhờ đó công cụ hỗ trợ sinh viên và analyst chuyển kết quả phân tích mã độc thành chữ ký phát hiện có thể kiểm thử được.

---

## 22. Câu thuyết trình ngắn

> Công cụ của em nhận vào nhiều mẫu mã độc cùng family, tự động trích xuất đặc trưng chung, dùng goodware database để lọc đặc trưng phổ biến, sinh YARA rule bằng yarGen, sau đó validate, test false positive và chấm điểm rule để analyst chọn rule tốt nhất.

---

## 23. Gợi ý hướng phát triển tiếp theo

Có thể bổ sung:

- Quality Gate PASS/WARNING/FAIL.
- MITRE ATT&CK auto mapping từ strings.
- AI Explain Rule.
- Rule Diff & Evolution.
- Threat Intel Assistant.
- Sample Similarity Graph.
- Export full analyst report HTML/PDF.
- CustomTkinter hoặc PySide6 để giao diện hiện đại hơn.

---

## 24. License / Disclaimer

Công cụ được xây dựng cho mục đích học tập, nghiên cứu và phòng thủ an toàn thông tin.

Không sử dụng công cụ để phát triển, phát tán hoặc vận hành mã độc.

`yarGen.py` là engine bên ngoài và thuộc quyền của tác giả/dự án gốc. GUI này chỉ là lớp hỗ trợ workflow và không thay đổi thuật toán lõi của yarGen.

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
