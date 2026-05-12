# DEMO WORKFLOW - yarGen GUI Malware Family YARA Builder

> File này dùng để bạn thực hiện demo đầy đủ các chức năng của công cụ trong đồ án/môn Phân tích mã độc.  
> Chủ đề demo: **Xây dựng công cụ tự động tạo chữ ký YARA từ các đặc trưng chung của một họ mã độc**.

---

## 1. Mục tiêu demo

Sau khi demo xong, người xem phải hiểu được công cụ làm được các việc sau:

```text
1. Kiểm tra môi trường chạy yarGen.
2. Phân tích folder malware sample.
3. Nhận diện sample, hash, type, archive warning.
4. Định nghĩa malware family.
5. Chọn preset phù hợp.
6. Generate YARA rule bằng yarGen.py.
7. Theo dõi tiến trình generate bằng dashboard/log realtime.
8. Validate cú pháp YARA.
9. Test rule trên malware.
10. Test rule trên goodware để kiểm false positive.
11. Kiểm tra Goodware DB.
12. Phân tích điểm rule.
13. Xuất báo cáo Markdown/CSV/HTML.
```

---

## 2. Chuẩn bị trước khi demo

### 2.1 Cấu trúc thư mục khuyến nghị

Nên đặt toàn bộ source GUI ở cùng project chính:

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
│   └── TrickBot\
├── goodware\
├── rules\
├── strings_out\
└── reports\
```

Nếu bạn để GUI trong folder riêng, vẫn được, nhưng trong tab `Setup` phải chỉnh:

```text
Working directory = C:\DACK_MALWARE
yarGen.py = C:\DACK_MALWARE\yarGen.py
```

---

### 2.2 Folder malware sample

Ví dụ:

```text
C:\DACK_MALWARE\samples\TrickBot
```

Folder này nên chứa các sample đã giải nén:

```text
sample_01.exe
sample_02.dll
sample_03.exe
sample_04.bin
...
```

Không nên để trực tiếp file:

```text
.7z
.zip
.rar
```

Nếu có archive, hãy giải nén trước.

---

### 2.3 Folder goodware

Tạo folder goodware để test false positive:

```text
C:\DACK_MALWARE\goodware
```

Có thể bỏ vào vài file sạch như:

```text
notepad.exe
calc.exe
7z.exe
putty.exe
chrome installer
file exe/dll sạch khác
```

Mục tiêu là test xem rule có match nhầm file sạch không.

---

### 2.4 Kiểm tra DB

Folder DB phải tồn tại:

```text
C:\DACK_MALWARE\dbs
```

Có các nhóm DB:

```text
good-strings-part*.db
good-opcodes-part*.db
good-exports-part*.db
good-imphashes-part*.db
```

Nếu DB quá nặng và demo bị lâu, dùng DB mode:

```text
Fast no-opcodes DB
```

Nếu muốn rule cuối chất lượng hơn, dùng:

```text
Full quality DB
```

---

## 3. Lệnh chạy app

Mở PowerShell:

```powershell
cd C:\DACK_MALWARE
.\venv\Scripts\python.exe main.py
```

Nếu không dùng venv:

```powershell
cd C:\DACK_MALWARE
python main.py
```

---

## 4. Kịch bản demo tổng quan

Bạn demo theo thứ tự này:

```text
1. Welcome / Language
2. Home Dashboard
3. Setup
4. Samples
5. Family
6. Generate
7. Monitor
8. Validate/Test
9. Database
10. Reports
11. Settings
12. Kết luận
```

---

# PHẦN A - DEMO GIAO DIỆN VÀ WORKFLOW

---

## 5. Mở app lần đầu - Welcome Screen

### Thao tác

1. Chạy app.
2. Nếu hiện màn hình chọn ngôn ngữ, chọn:

```text
Tiếng Việt
```

hoặc:

```text
English
```

3. Tick:

```text
Remember my choice
```

4. Bấm:

```text
Continue / Tiếp tục
```

### Nói khi demo

> Khi chạy lần đầu, công cụ cho phép chọn ngôn ngữ giao diện. App hỗ trợ song ngữ Tiếng Việt và English để phù hợp sinh viên cũng như người dùng kỹ thuật.

---

## 6. Home Dashboard

### Thao tác

Vào màn hình:

```text
Home
```

Quan sát các card:

```text
1. Setup
2. Samples
3. Generate
4. Monitor
5. Validate/Test
6. Reports
```

### Nói khi demo

> Home Dashboard hướng dẫn workflow tổng thể. Người dùng không cần nhớ CLI yarGen, chỉ cần đi theo từng bước từ Setup, phân tích sample, generate rule, monitor, validate/test và xuất báo cáo.

---

# PHẦN B - SETUP MÔI TRƯỜNG

---

## 7. Demo Setup

### Mục tiêu

Kiểm tra xem app có đủ điều kiện chạy không.

### Thao tác

Vào:

```text
Setup
```

Kiểm tra các trường:

```text
Python executable
Working directory
yarGen.py
```

Nếu bạn đặt source tại `C:\DACK_MALWARE`, nên là:

```text
Python executable = C:\DACK_MALWARE\venv\Scripts\python.exe
Working directory = C:\DACK_MALWARE
yarGen.py = C:\DACK_MALWARE\yarGen.py
```

Bấm:

```text
Validate environment
```

### Kết quả mong đợi

Bảng hiện:

```text
Python executable       OK
Working directory       OK
yarGen.py               OK
requirements.txt        OK hoặc Warning
dbs folder              OK
3rdparty/strings.xml    OK
Python module pefile    OK
Python module lxml      OK
Python module yara      OK hoặc Warning
DB files                OK
```

### Nói khi demo

> Trước khi generate rule, công cụ kiểm tra môi trường gồm Python, yarGen.py, folder DB, strings.xml và các thư viện cần thiết. Điều này giúp người dùng tránh lỗi khi chạy CLI thủ công.

### Nếu lỗi

Nếu thiếu `yara-python`:

```powershell
pip install yara-python
```

Nếu thiếu `scandir`:

```powershell
pip install scandir
```

Nếu thiếu DB:

```text
Setup → Download / update DBs
```

---

# PHẦN C - PHÂN TÍCH SAMPLE

---

## 8. Demo Samples - Scan folder

### Mục tiêu

Phân tích folder malware trước khi generate rule.

### Thao tác

Vào:

```text
Samples
```

Chọn:

```text
Malware sample folder = C:\DACK_MALWARE\samples\TrickBot
```

Bấm:

```text
Scan folder
```

### Kết quả mong đợi

Bảng hiện:

```text
file name
type
size
md5
sha256
status
```

Ví dụ:

```text
sample_01.exe    PE    356352    md5...    sha256...    OK
sample_02.dll    PE    421888    md5...    sha256...    OK
```

Summary hiện:

```text
Total=...
PE=...
Scripts=...
Archives=...
Size=...
Suggested=Beginner/PE Deep
```

### Nói khi demo

> Tab Samples hỗ trợ bước phân tích tĩnh ban đầu. Công cụ tính hash MD5, SHA256, nhận diện loại file và cảnh báo nếu có file nén chưa giải nén. Đây là bước thường gặp trong môn Phân tích mã độc.

---

## 9. Demo Samples - Cluster similar samples

### Mục tiêu

Gom các mẫu giống nhau thành cluster trước khi generate.

### Thao tác

Trong tab `Samples`, bấm:

```text
Cluster similar samples
```

Nếu có cluster, bấm:

```text
Generate rule per cluster
```

### Kết quả mong đợi

App tạo folder:

```text
C:\DACK_MALWARE\clusters\cluster_01
C:\DACK_MALWARE\clusters\cluster_02
...
```

Và tự set Generate input sang:

```text
Malware/sample folder = C:\DACK_MALWARE\clusters\cluster_01
```

### Nói khi demo

> Nếu người dùng vô tình trộn nhiều family trong một folder, rule sinh ra dễ bị loạn. Chức năng clustering giúp gom mẫu có strings tương đồng rồi tạo rule riêng cho từng nhóm. Đây là bước phù hợp với mục tiêu tìm đặc trưng chung của từng family.

---

# PHẦN D - MALWARE FAMILY WORKFLOW

---

## 10. Demo Family

### Mục tiêu

Định nghĩa family và metadata cho rule.

### Thao tác

Vào:

```text
Family
```

Nhập:

```text
Malware family name = TrickBot
Goal / description = Tạo rule YARA từ đặc trưng chung của họ TrickBot
Minimum sample count = 3
Author = yarGen GUI
Reference = https://github.com/Neo23x0/yarGen
```

Bấm:

```text
Create identifier.txt
```

Sau đó bấm:

```text
Apply Family Rule preset
```

### Kết quả mong đợi

App tự set:

```text
Malware folder = C:\DACK_MALWARE\samples\TrickBot
Output rule = C:\DACK_MALWARE\rules\TrickBot.yar
String export folder = C:\DACK_MALWARE\strings_out\TrickBot
```

### Nói khi demo

> Vì đề tài tập trung vào đặc trưng chung của một họ mã độc, tab Family giúp người dùng định nghĩa family, tạo identifier và áp preset phù hợp để sinh family rule thay vì rule cho một file đơn lẻ.

---

# PHẦN E - GENERATE YARA RULE

---

## 11. Demo Generate - Basic Mode

### Mục tiêu

Sinh YARA rule bằng GUI.

### Thao tác

Vào:

```text
Generate
```

Chọn:

```text
Preset = TrickBot Demo
DB Mode = Full quality DB
```

Nếu demo cần nhanh hơn:

```text
DB Mode = Fast no-opcodes DB
```

Kiểm tra:

```text
Malware/sample folder
Output YARA file
String export folder
Author
Reference
```

Bấm:

```text
Preview command
```

Sau đó bấm:

```text
Generate YARA rule
```

### Nói khi demo

> GUI sẽ tự build command yarGen tương ứng. Người dùng không cần nhớ các tham số CLI như `-m`, `-o`, `-y`, `-z`, `--score`. Tuy nhiên command vẫn được hiển thị để analyst có thể kiểm tra hoặc chạy lại bằng CLI.

---

## 12. Demo Generate - Advanced Mode

### Mục tiêu

Cho thấy app vẫn hỗ trợ người dùng kỹ thuật.

### Thao tác

Bấm trên top bar:

```text
Advanced Mode
```

Trong Generate sẽ hiện thêm:

```text
License
Prefix
Identifier file
-y
-z
-x
-w
-s
-rc
-fs
-fm
-n
--debug
--trace
--noscorefilter
```

### Nói khi demo

> Basic Mode dành cho người mới. Advanced Mode dành cho người hiểu yarGen hoặc cần tinh chỉnh rule. Ví dụ khi yarGen sinh 0 rule, có thể dùng Loose Debug hoặc giảm `-z`, giảm `-x` để kiểm tra.

---

## 13. Ý nghĩa tham số quan trọng khi demo

### `--score`

Bật score cho từng string.

Cần bật nếu muốn dùng:

```text
Reports → Analyze Rule Scores
```

### `--strings`

Xuất strings hoặc dùng strings mode.

Hữu ích khi review đặc trưng.

### `-z`

Minimum score.

```text
Tăng -z → lọc string yếu → giảm false positive nhưng có thể sinh ít rule hơn.
Giảm -z → dễ sinh rule hơn nhưng rule có thể yếu hơn.
```

### `-x`

High score threshold.

```text
String có score cao hơn -x thường được xem là đặc trưng mạnh.
```

### `-w`

Super rule minimum overlap.

```text
Điều khiển mức độ overlap để tạo Super Rule.
```

### `-s`

Max string length.

```text
Tăng -s nếu malware có chuỗi dài như URL, config, path.
```

### `-rc`

Max strings per rule.

```text
Điều khiển số string tối đa trong rule.
```

### `--opcodes`

Phân tích opcode.

```text
Có thể tốt cho PE nhưng rất chậm và tốn RAM.
```

---

# PHẦN F - MONITOR GENERATION

---

## 14. Demo Monitor

Sau khi bấm Generate, app tự chuyển sang:

```text
Monitor
```

### Quan sát

Các phần cần chỉ cho người xem:

```text
Progress bar
Current stage
Stage table
Realtime log
YARA preview
YARA summary
```

Stage table gồm:

```text
Preflight
Load goodware DB
Extract strings/opcodes
Generate statistics
Generate simple/super rules
Validate/Test
```

### Log thường thấy

```text
[+] Reading goodware strings from database
[+] Loading ./dbs/good-strings-part1.db
[+] Processing malware files
[+] Processing sample_01.exe
[+] Generating statistical data
[+] Generating Super Rules
[+] Generating Simple Rules
[=] Generated X SIMPLE rules.
[=] Generated Y SUPER rules.
```

### Nói khi demo

> Monitor giúp người dùng biết app không bị treo. Quá trình load DB có thể lâu vì goodware DB chứa hàng triệu strings. Dashboard cho thấy app đang ở bước nào: load DB, xử lý sample, tạo statistics hay sinh rule.

---

## 15. Nếu generate lâu thì giải thích sao?

Nói:

> yarGen phải load goodware DB để loại các chuỗi phổ biến trong phần mềm sạch. DB càng lớn thì rule càng ít false positive nhưng thời gian chạy càng lâu. Khi demo nhanh có thể dùng Fast no-opcodes DB, còn khi tạo rule cuối nên dùng Full quality DB.

---

## 16. Sau khi generate xong

### Kết quả mong đợi

File rule được tạo ở:

```text
C:\DACK_MALWARE\rules\TrickBot.yar
```

Monitor preview sẽ hiển thị nội dung `.yar`.

Summary có thể là:

```text
rules=7
simple=5
super=2
strings=128
$x=6
$s=122
```

### Nói khi demo

> Rule đã được sinh tự động. SIMPLE rule thường gắn với từng sample, còn SUPER rule thể hiện đặc trưng chung giữa nhiều sample, phù hợp nhất với mục tiêu đề tài.

---

# PHẦN G - VALIDATE VÀ TEST RULE

---

## 17. Demo Validate syntax

Vào:

```text
Validate/Test
```

Kiểm tra:

```text
Rule file = C:\DACK_MALWARE\rules\TrickBot.yar
```

Bấm:

```text
Validate syntax
```

### Kết quả mong đợi

```text
[VALIDATE OK]
Rule is valid.
```

### Nói khi demo

> Rule sinh ra chưa chắc đã dùng được. Bước validate giúp kiểm tra cú pháp YARA bằng yara-python hoặc yarac.

---

## 18. Demo Test malware

Trong tab:

```text
Validate/Test
```

Set:

```text
Malware folder = C:\DACK_MALWARE\samples\TrickBot
```

Bấm:

```text
Test malware
```

### Kết quả mong đợi

```text
Malware matches: 5
```

Danh sách:

```text
[malware] rule_name -> sample_01.exe
[malware] rule_name -> sample_02.dll
...
```

### Nói khi demo

> Bước này kiểm tra rule có phát hiện lại các sample malware trong family hay không. Nếu không match malware, rule chưa đạt yêu cầu.

---

## 19. Demo Test goodware

Set:

```text
Goodware folder = C:\DACK_MALWARE\goodware
```

Bấm:

```text
Test goodware
```

### Kết quả tốt

```text
Goodware false positives: 0
```

### Nếu có false positive

```text
Goodware false positives: 2
```

### Nói khi demo

> Rule tốt không chỉ match malware mà còn không match nhầm goodware. Nếu có false positive, analyst cần tăng `-z`, tăng `-x`, loại string phổ biến hoặc test lại với Goodware DB đầy đủ hơn.

---

## 20. Export test report

Bấm:

```text
Export CSV
Export HTML
```

File xuất ra:

```text
C:\DACK_MALWARE\reports\yara_test_report.csv
C:\DACK_MALWARE\reports\yara_test_report.html
```

### Nói khi demo

> Công cụ hỗ trợ xuất báo cáo kết quả test để đưa vào bài lab hoặc đồ án.

---

# PHẦN H - DATABASE / GOODWARE DB

---

## 21. Demo Database Inspector

Vào:

```text
Database
```

Bấm:

```text
Refresh DB
```

### Quan sát

Bảng hiện:

```text
good-strings-part1.db
good-opcodes-part1.db
good-exports-part1.db
good-imphashes-part1.db
...
```

Các cột:

```text
file
group
size
entries
status
```

Chọn một DB rồi bấm:

```text
Evaluate selected DB
```

### Nói khi demo

> Goodware DB chứa đặc trưng phần mềm sạch. yarGen dùng DB này để trừ điểm hoặc loại các strings phổ biến, từ đó giảm false positive.

---

## 22. Demo Goodware DB operations

Trong tab Database có phần:

```text
Goodware DB operations
```

Chọn:

```text
Goodware folder = C:\DACK_MALWARE\goodware
```

Có thể demo nút:

```text
Create new DB
Update DB
Create with opcodes
```

### Lưu ý khi demo

Không nhất thiết phải chạy thật nếu sợ lâu.

Có thể nói:

> Phần này dùng khi người dùng muốn tự tạo goodware DB từ tập phần mềm sạch của riêng mình. Trong demo này em dùng DB có sẵn để tiết kiệm thời gian.

---

# PHẦN I - REPORTS / RULE SCORE

---

## 23. Demo Analyze Rule Scores

Vào:

```text
Reports
```

Chọn:

```text
YARA file = C:\DACK_MALWARE\rules\TrickBot.yar
```

Bấm:

```text
Analyze Rule Scores
```

### Kết quả mong đợi

Reports hiển thị:

```text
Bảng tổng hợp rule
Biểu đồ Max Score
Nhận xét rule tốt nhất
```

Bảng gồm:

```text
STT
Tên Rule
Số lượng chuỗi
Số chuỗi có score
Score cao nhất
Score trung bình
Score thấp nhất
Đánh giá độ tin cậy
```

---

## 24. Giải thích score

Nói:

> Khi bật `--score`, yarGen gắn điểm cho từng string. String có score cao thường đặc trưng hơn cho malware. String có score thấp hoặc âm thường phổ biến hoặc dễ gây false positive.

Ví dụ:

```text
ReflectiveLoader      score cao
Chrome passwords      score cao
kernel32.dll          score thấp
This program cannot   score thấp hoặc âm
```

---

## 25. Mức đánh giá độ tin cậy

App đánh giá:

```text
Max Score > 35        → Rất cao
Max Score > 25        → Cao
Max Score > 10        → Trung bình
Max Score <= 10       → Thấp
Không có score        → Không đủ dữ liệu
```

### Nói khi demo

> Rule có Max Score cao nhất thường chứa ít nhất một string rất đặc trưng. Tuy nhiên để chắc hơn cần xem thêm Average Score, Goodware String và kết quả test goodware.

---

## 26. Export Score Report

Bấm:

```text
Export Markdown
Export CSV
```

File xuất ra:

```text
C:\DACK_MALWARE\reports\yara_rule_score_report.md
C:\DACK_MALWARE\reports\yara_rule_score_report.csv
```

### Nói khi demo

> Báo cáo này giúp analyst chọn rule đáng tin nhất, rule nào cần review và rule nào có nguy cơ false positive.

---

# PHẦN J - SETTINGS / UI UX

---

## 27. Demo Settings

Vào:

```text
Settings
```

Có thể đổi:

```text
Language = vi / en
Theme = light / dark
Mode = basic / advanced
```

Bấm:

```text
Save settings
```

### Nói khi demo

> Công cụ hỗ trợ song ngữ, light/dark theme và Basic/Advanced Mode để phù hợp cả người mới và người dùng kỹ thuật.

---

# PHẦN K - DEMO ĐẦY ĐỦ TRONG 10 PHÚT

---

## 28. Kịch bản demo nhanh 10 phút

### Phút 1: Giới thiệu

Nói:

> Công cụ của em hỗ trợ tự động tạo chữ ký YARA từ nhiều mẫu mã độc cùng family. GUI không thay thế yarGen.py mà bổ sung workflow, validation, testing, dashboard và report.

---

### Phút 2: Setup

Thao tác:

```text
Setup → Validate environment
```

Nói:

> Công cụ kiểm tra Python, yarGen.py, DB, strings.xml và thư viện.

---

### Phút 3: Samples

Thao tác:

```text
Samples → chọn samples\TrickBot → Scan folder
```

Nói:

> Công cụ tính MD5, SHA256, file type và cảnh báo archive.

---

### Phút 4: Family

Thao tác:

```text
Family → nhập TrickBot → Apply Family Rule preset
```

Nói:

> Đây là bước gắn với đề tài: nhiều mẫu cùng họ mã độc.

---

### Phút 5: Generate

Thao tác:

```text
Generate → Preset TrickBot Demo → DB Mode Fast no-opcodes DB hoặc Full quality DB → Generate
```

Nói:

> GUI build command yarGen và chạy engine.

---

### Phút 6: Monitor

Thao tác:

```text
Monitor → xem progress/log
```

Nói:

> Có thể thấy app load DB, process sample và generate simple/super rules.

---

### Phút 7: Validate

Thao tác:

```text
Validate/Test → Validate syntax
```

Nói:

> Rule sinh ra cần được compile để đảm bảo cú pháp hợp lệ.

---

### Phút 8: Test

Thao tác:

```text
Test malware
Test goodware
```

Nói:

> Rule phải match malware và không match nhầm goodware.

---

### Phút 9: Reports

Thao tác:

```text
Reports → Analyze Rule Scores
```

Nói:

> App đọc score của yarGen, tính Max/Avg/Min Score và nhận xét rule tốt nhất.

---

### Phút 10: Kết luận

Nói:

> Công cụ hoàn thiện quy trình từ phân tích sample đến tạo rule, kiểm thử và báo cáo. Điểm quan trọng là SUPER rule và score report giúp tìm đặc trưng chung của family, đúng với mục tiêu đề tài.

---

# PHẦN L - SCRIPT THUYẾT TRÌNH MẪU

---

## 29. Mở đầu

> Trong môn Phân tích mã độc, sau khi phân tích một hoặc nhiều mẫu malware, analyst cần tạo chữ ký phát hiện để nhận diện các biến thể tương tự. YARA là công cụ phổ biến để viết chữ ký dựa trên strings, PE info và pattern. Tuy nhiên việc viết YARA thủ công mất thời gian và dễ chọn nhầm string phổ biến. Vì vậy em xây dựng GUI hỗ trợ tự động tạo rule YARA từ nhiều mẫu cùng family bằng yarGen.

---

## 30. Giải thích kiến trúc

> Công cụ gồm 3 lớp. Lớp engine là `yarGen.py`, không bị thay đổi. Lớp core xử lý state, command, subprocess, validation và scoring. Lớp GUI gồm các màn hình Setup, Samples, Family, Generate, Monitor, Validate/Test, Database và Reports. Thiết kế modular giúp dễ bảo trì và mở rộng.

---

## 31. Giải thích quy trình

> Người dùng chọn nhiều mẫu malware cùng họ. Công cụ phân tích sample, tính hash và type. Sau đó GUI build command để chạy yarGen. yarGen trích xuất strings và so sánh với goodware database để giảm false positive. Kết quả là file YARA rule. Sau khi sinh rule, công cụ validate syntax, test trên malware/goodware và chấm điểm rule.

---

## 32. Giải thích Goodware DB

> Goodware DB chứa strings/opcodes/imphash/export thường gặp trong phần mềm sạch. Nếu một string xuất hiện nhiều trong goodware thì không nên dùng làm IOC mạnh. Nhờ DB này, rule sinh ra ít false positive hơn.

---

## 33. Giải thích SIMPLE/SUPER Rule

> SIMPLE rule thường sinh cho từng mẫu cụ thể. SUPER rule được tạo từ đặc trưng chung giữa nhiều mẫu. Vì đề tài là tạo chữ ký từ đặc trưng chung của một họ mã độc, SUPER rule là phần quan trọng nhất.

---

## 34. Giải thích Score Report

> Khi bật `--score`, yarGen gắn điểm cho từng string. GUI đọc lại các điểm này và tổng hợp theo từng rule. Rule có Max Score và Avg Score cao thường đáng tin hơn. Nếu rule có nhiều score âm hoặc Goodware String, cần review vì có nguy cơ false positive.

---

## 35. Kết luận demo

> Công cụ giúp biến kết quả phân tích mã độc thành chữ ký phát hiện có thể kiểm thử. Nó hỗ trợ sinh viên hiểu đầy đủ quy trình từ malware analysis đến detection engineering: phân tích sample, tạo rule, validate, test false positive và xuất báo cáo.

---

# PHẦN M - CHECKLIST TRƯỚC KHI DEMO

---

## 36. Checklist kỹ thuật

Trước khi lên demo, kiểm tra:

```text
[ ] App mở được bằng main.py
[ ] Setup validate OK
[ ] yarGen.py đúng path
[ ] dbs folder có DB
[ ] samples\TrickBot có sample đã giải nén
[ ] goodware folder có file sạch
[ ] rules folder tồn tại
[ ] reports folder tồn tại
[ ] Generate chạy được
[ ] Output .yar không rỗng
[ ] Validate syntax OK
[ ] Test malware có match
[ ] Test goodware không FP hoặc biết cách giải thích nếu có FP
[ ] Reports phân tích được score
```

---

## 37. Checklist nội dung thuyết trình

```text
[ ] Nói rõ app không thay đổi yarGen.py
[ ] Nói rõ input là nhiều mẫu cùng family
[ ] Nói rõ Goodware DB giúp giảm false positive
[ ] Nói rõ SIMPLE vs SUPER rule
[ ] Nói rõ score là điểm của từng string
[ ] Nói rõ rule cần validate và test
[ ] Nói rõ ứng dụng trong môn Phân tích mã độc
```

---

# PHẦN N - TÌNH HUỐNG LỖI VÀ CÁCH XỬ LÝ KHI DEMO

---

## 38. App báo thiếu DB

Cách nói:

> Do Working directory chưa trỏ đúng project chính hoặc folder dbs chưa tồn tại.

Cách sửa:

```text
Setup → Working directory = C:\DACK_MALWARE
```

---

## 39. Generate mất nhiều thời gian

Cách nói:

> Full quality DB load nhiều triệu strings nên thời gian lâu. Đây là trade-off giữa chất lượng rule và tốc độ. Để demo nhanh có thể dùng Fast no-opcodes DB.

---

## 40. yarGen sinh 0 rule

Cách nói:

> Có thể do sample bị pack, ít string, chưa giải nén hoặc tham số quá chặt. Có thể dùng Loose Debug để kiểm tra và giảm ngưỡng score.

Cách xử lý:

```text
Preset = Loose Debug
Bật --score
Bật --strings
Giảm -z
Giảm -x
Tăng -s
```

---

## 41. Reports không có score

Cách nói:

> Do khi generate chưa bật `--score`.

Cách xử lý:

```text
Generate → bật --score → Generate lại
```

---

## 42. Rule match goodware

Cách nói:

> Đây là false positive. Analyst cần chỉnh rule hoặc tăng ngưỡng score.

Cách xử lý:

```text
Tăng -z
Tăng -x
Bỏ string phổ biến
Dùng Full quality DB
Test lại goodware
```

---

# PHẦN O - KẾT QUẢ MONG ĐỢI SAU DEMO

Sau demo, bạn nên có các file:

```text
rules\TrickBot.yar
strings_out\TrickBot\
reports\yara_test_report.csv
reports\yara_test_report.html
reports\yara_rule_score_report.md
reports\yara_rule_score_report.csv
```

Và có thể trình bày:

```text
Số sample đã phân tích
Số rule sinh ra
Số SIMPLE rule
Số SUPER rule
Số strings
Rule có score cao nhất
Kết quả test malware
Kết quả test goodware
Nhận xét false positive
```

---

# PHẦN P - KẾT LUẬN NGẮN GỌN

Câu kết luận nên dùng:

> Công cụ này hỗ trợ sinh viên và analyst tự động hóa quy trình tạo chữ ký YARA từ nhiều mẫu malware cùng family. Điểm mạnh của công cụ là không chỉ generate rule, mà còn phân tích sample, quản lý DB, giám sát tiến trình, validate, test false positive, chấm điểm rule và xuất báo cáo. Điều này giúp hoàn thiện quy trình từ Phân tích mã độc đến Detection Engineering.
