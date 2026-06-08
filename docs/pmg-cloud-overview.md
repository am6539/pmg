# PMG Cloud — Hệ thống Kiểm soát Bảo mật Phần mềm Nội bộ

## Tổng quan

**PMG Cloud** là nền tảng bảo mật nội bộ giúp kiểm soát toàn bộ hoạt động cài đặt thư viện/package của lập trình viên trong tổ chức — phát hiện malware, áp policy toàn tổ chức, theo dõi thiết bị, cảnh báo đa kênh và quản lý cập nhật tập trung từ một dashboard duy nhất.

---

## Vấn đề cần giải quyết

Trong quá trình phát triển phần mềm, lập trình viên thường xuyên cài đặt các thư viện mã nguồn mở từ npm (JavaScript), PyPI (Python), v.v. Đây là một **điểm rủi ro lớn**:

| Rủi ro | Mô tả |
|--------|-------|
| **Malware trong package** | Hacker đăng tải package giả mạo để đánh cắp credentials, secrets |
| **Supply chain attack** | Package hợp lệ bị chiếm đoạt và nhúng mã độc |
| **Package quá mới** | Phiên bản vừa publish vài giờ — chưa kịp bị phát hiện là độc hại |
| **Mất kiểm soát thiết bị** | Không biết nhân viên đang dùng công cụ gì, phiên bản nào, có còn cài PMG không |
| **Không có audit trail** | Không theo dõi được ai cài package gì, khi nào, trên máy nào |

> Theo báo cáo 2024, số lượng malware package trên npm tăng **1.300%** so với 3 năm trước.

---

## Giải pháp

PMG (Package Manager Guard) hoạt động như một **lớp bảo vệ trong suốt** — cài đặt trên máy lập trình viên và tự động chặn hoặc cảnh báo khi phát hiện package nguy hiểm, đồng thời gửi toàn bộ dữ liệu về PMG Cloud để quản lý tập trung.

```
Lập trình viên          PMG Agent                     PMG Cloud
      │                     │                            │
      │  npm install X  ──► │  Phân tích (malware +      │
      │                     │  cooldown + org policy)    │
      │                     │  ────── events/heartbeat ─► │ Dashboard
      │  ✅ An toàn     ◄── │                            │ Logs · Alert
      │  hoặc                │  ◄──── policy + update ──── │ Policy · Update
      │  ❌ Bị chặn     ◄── │                            │
```

Mỗi máy chỉ cần cài 1 lần (`install.sh` / `install.ps1`) — tự enroll, tự cập nhật, tự gửi heartbeat.

---

## Tính năng chính

### 1. Phát hiện & Chặn Malware Real-time
- Tích hợp cơ sở dữ liệu malware từ **Aikido Security** (~128.000 package độc hại) + dịch vụ phân tích **SafeDep malysis**
- Phân tích **theo từng version** trước khi cài, **tự động chặn** version độc hại
- **Fail-closed** (chế độ paranoid): khi feed/analyzer không truy cập được, chặn thay vì âm thầm cho qua

### 2. Dependency Cooldown
- Chặn các package **vừa publish dưới N ngày** (mặc định 5) — cửa sổ mà malware mới hay lọt lưới
- Cross-check feed malware: version vừa cooldown vừa là malware luôn được báo đúng **MALWARE**, không nhầm thành "clean"

### 3. Org Policy Push (Chặn/Cho phép toàn tổ chức)
- Admin thêm rule **block / allow** theo tên + version + ecosystem ngay trên dashboard
- Agent áp dụng ở lần heartbeat kế tiếp — **không cần build lại hay cài lại**
- Allow ghi đè block; phản ứng tức thì khi có sự cố supply-chain

### 4. Dashboard Quản lý Tập trung
- Theo dõi tất cả thiết bị, đặt **tên gợi nhớ cho từng máy** (biết máy nào của dev nào)
- Tab **Packages** chi tiết: versions, trạng thái (Malware/Cooldown/Blocked/Clean), số lượt, lần cuối, và **máy nào cài package nào** ngay trong Recent Events
- Lịch sử theo từng máy / nhóm; thống kê tổng quan; xuất CSV

### 5. Giám sát Trạng thái Thiết bị (Heartbeat)
- Agent gửi heartbeat **định kỳ 15 phút** (cron trên Linux/macOS, Task Scheduler chạy ẩn trên Windows) — máy bật là dashboard thấy online, kể cả khi không cài package
- Phát hiện khi nhân viên **gỡ bỏ PMG** khỏi máy
- 3 trạng thái: 🟢 `Active` (<24h) · 🟡 `Idle` (1–3 ngày) · 🔴 `Missing PMG` (>3 ngày)

### 6. Cảnh báo Đa kênh
- **Telegram, Slack, Webhook** — cảnh báo khi phát hiện malware, package bị chặn
- **Quét agent mất tích** hàng giờ → cảnh báo khi một máy ngừng heartbeat >72h (nghi gỡ PMG), tự de-dupe
- Cấu hình + nút **Test** ngay trên dashboard

### 7. Quản lý Nhóm & Phân quyền
- Phân chia thiết bị theo nhóm (dev, staging, production...), mỗi nhóm có API key riêng, dễ thu hồi
- Tài khoản admin / viewer; session bảo vệ; enrollment token một lần

### 8. Cập nhật Agent Từ Xa
- Admin bấm **↓ GitHub** để kéo bản release mới nhất → **Publish** → agent tự update
- Self-update **verify sha256**, thay binary an toàn (kể cả khi đang chạy trên Windows)
- Hỗ trợ: Linux (x64/ARM), macOS (Intel/Apple Silicon), Windows

### 9. Tích hợp CI/CD
- Hỗ trợ GitHub Actions, GitLab CI — theo dõi package theo repository và branch

---

## Kiến trúc

```
┌──────────────────────────────────────────────────┐
│                PMG Cloud Server                   │
│                                                   │
│   Dashboard (Web)  │  gRPC API  │  HTTP API       │
│   Malware feed mirror · Policy · Update store     │
│                                                   │
│   Dữ liệu lưu trữ nội bộ (file JSON, không cloud) │
└──────────────────────────────────────────────────┘
                ▲           ▲           ▲
                │           │           │
         Windows PC    MacBook     CI/CD Pipeline
          PMG Agent    PMG Agent    PMG Agent
   (heartbeat · events · self-update · policy enforce)
```

**Triển khai:** Self-hosted hoàn toàn, chạy trên VPS hoặc server nội bộ, expose qua Cloudflare Tunnel (HTTPS). Dữ liệu không rời khỏi hạ tầng công ty.

---

## Ví dụ thực tế

**Kịch bản: Lập trình viên vô tình cài malware**

1. Dev gõ: `npm install @redhat-cloud-services/types` ← version độc hại
2. PMG Agent phân tích ngay (malware feed + malysis + cooldown + org policy)
3. Phát hiện version nằm trong danh sách malware → **cài đặt bị từ chối**
4. Event gửi về dashboard: **máy nào / dev nào**, package + version, lý do (MALWARE), lúc mấy giờ
5. Admin nhận cảnh báo **Telegram/Slack** trong vài giây, thấy đầy đủ trên dashboard

---

## Thông số kỹ thuật

| Hạng mục | Chi tiết |
|----------|---------|
| Ngôn ngữ | Go |
| Giao thức | gRPC + HTTP/1.1 (fallback qua Cloudflare Tunnel) |
| Lưu trữ | File JSON (không cần database) |
| Kích thước agent | ~40 MB, một binary tĩnh |
| Hệ điều hành | Windows, macOS, Linux |
| Yêu cầu server | 1 vCPU, 512 MB RAM |

---

## Trạng thái triển khai

| Tính năng | Trạng thái |
|-----------|-----------|
| Phát hiện & chặn malware real-time | ✅ |
| Fail-closed khi detection suy giảm | ✅ |
| Dependency cooldown + cross-check malware | ✅ |
| Org policy push (block/allow toàn tổ chức) | ✅ |
| Dashboard: tên thiết bị, packages chi tiết | ✅ |
| Heartbeat định kỳ + giám sát thiết bị | ✅ |
| Cảnh báo Telegram/Slack/Webhook + quét agent mất tích | ✅ |
| Cập nhật agent từ xa (self-update, verify sha256) | ✅ |
| Quản lý nhóm, phân quyền, audit log | ✅ |
| CI/CD integration | ✅ |

---

## Lợi ích Kinh doanh

- **Giảm rủi ro bảo mật** trước supply chain attack — xu hướng tấn công phổ biến nhất hiện nay
- **Kiểm soát tập trung** toàn bộ phần mềm cài trên thiết bị công ty, biết rõ máy nào của ai
- **Phản ứng tức thì** — chặn/cho phép package toàn tổ chức và nhận cảnh báo ngay khi có sự cố
- **Audit trail** đầy đủ, sẵn sàng cho yêu cầu compliance
- **Vận hành nhẹ** — self-hosted, một server nhỏ, agent tự cập nhật, không phụ thuộc bên thứ ba

---

*Tài liệu nội bộ — chuẩn bị cho mục đích trình bày.*
