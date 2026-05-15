# Báo cáo đánh giá điểm YARA rule

File: `C:\DACK_MALWARE\rules\trick.yar`

## 1. Bảng tổng hợp

| STT | Tên Rule | Số lượng chuỗi | Số chuỗi có score | Score cao nhất | Score trung bình | Score thấp nhất | Đánh giá độ tin cậy |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | `sig_4becc0d518a97cc31427cd08348958cda4e0048...` | 20 | 20 | 41.00 | 28.20 | 23.00 | Rất cao |
| 2 | `ef6603a7ef46177ecba194148f72d396d0ddae47e3d...` | 20 | 20 | 37.00 | 22.55 | 18.00 | Rất cao |
| 3 | `sig_6a75c212b49093517e6c29dcb2644df57a93119...` | 20 | 20 | 30.00 | 11.65 | 6.00 | Cao |
| 4 | `e2e034dfa6cc9e5dae4121a0b3fa6d56` | 20 | 20 | 23.00 | 8.61 | 4.26 | Trung bình |
| 5 | `ec2a22d92dd78e37a6705c8116251fabdae2afecb35...` | 20 | 20 | 33.00 | 14.90 | 10.00 | Cao |
| 6 | `_4becc0d518a97cc31427cd08348958cda4e00487c7...` | 20 | 20 | 37.00 | 22.55 | 18.00 | Rất cao |
| 7 | `_4becc0d518a97cc31427cd08348958cda4e00487c7...` | 8 | 8 | 10.00 | 4.38 | 0.00 | Thấp |

## 2. Biểu đồ thanh - Score cao nhất

```text
sig_4becc0d518a97cc31427cd08348958cda4e004 | ████████████████████████████████████ 41.00
ef6603a7ef46177ecba194148f72d396d0ddae47e3 | ████████████████████████████████ 37.00
_4becc0d518a97cc31427cd08348958cda4e00487c | ████████████████████████████████ 37.00
ec2a22d92dd78e37a6705c8116251fabdae2afecb3 | ████████████████████████████ 33.00
sig_6a75c212b49093517e6c29dcb2644df57a9311 | ██████████████████████████ 30.00
e2e034dfa6cc9e5dae4121a0b3fa6d56           | ████████████████████ 23.00
_4becc0d518a97cc31427cd08348958cda4e00487c | ████████ 10.00
```

## 3. Nhận xét

- Rule có khả năng phát hiện chính xác nhất theo Max Score là `sig_4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc` với **41.00**.
- Rule ổn định hơn theo Avg Score là `sig_4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc` với **28.20**.
- Có 2 Super Rule, phù hợp mục tiêu tìm đặc trưng chung của family.
- Khuyến nghị: giữ rule có Max/Avg Score cao, test lại trên goodware, chỉnh các string score thấp/âm.