# LAMPS Demo — Web Interface

Web demo minh hoạ pipeline phát hiện mã độc trong gói PyPI sử dụng CodeBERT fine-tuned.

---

## Khởi động

```powershell
# Chạy từ thư mục gốc của dự án (LAMPS/)
.venv\Scripts\python.exe -m uvicorn demo.backend.app:app --port 8000
```

Chờ xuất hiện dòng log:
```
Model ready. Open http://localhost:8000
```
*(~25–35 giây để load model từ cache)*

Sau đó mở trình duyệt: **http://localhost:8000**

---

## Cài đặt (chỉ cần làm 1 lần)

```powershell
.venv\Scripts\pip.exe install -r demo/requirements.txt
```

---

## Packages trong Demo

| Package | Loại | Mô tả |
|---------|------|-------|
| `aio3` | Malicious | Typosquat của `aiohttp` — thu thập env vars |
| `dfdfdfdfhhh` | Malicious ⚠ | **Evasion case study** — middle-zone attack |
| `click-8.3.2` | Benign | CLI framework phổ biến — hoàn toàn sạch |

---

## Kịch Bản Demo Trước Lớp (~10 phút)

### Mở đầu (1 phút)

> *"Chúng tôi reproduce hệ thống LAMPS — Language Model for Malware Detection in PyPI — sử dụng CodeBERT fine-tuned để phát hiện mã độc ở cấp độ file Python. Demo này minh hoạ pipeline phát hiện và một phát hiện quan trọng trong experiment G4."*

---

### Scene 1: Package sạch — click-8.3.2 (2 phút)

**Click card `click-8.3.2`**, sau đó nhấn **Run Detection Pipeline**.

Chờ pipeline chạy, giải thích từng bước:

- **Package Loader**: *"Hệ thống lấy 3 file Python từ gói click-8.3.2 — một thư viện CLI hợp lệ."*
- **Tokenizer**: *"CodeBERT tokenizer encode source code thành subword token IDs. Tất cả file đều dưới 512 token, không bị cắt."*
- **Classifier**: *"Xác suất malicious rất thấp — 0.03, 0.02, 0.01. Model nhận ra đây là code Python bình thường."*
- **Verdict — CLEAN**: *"Package được xếp loại CLEAN. Đây là kết quả kỳ vọng cho một thư viện hợp lệ."*

---

### Scene 2: Typosquat attack — aio3 (2 phút)

**Click card `aio3`**, nhấn **Run Detection Pipeline**.

- **Package Loader**: *"Package này trông giống `aiohttp` nhưng thêm một ký tự '3' ở cuối — đây là kỹ thuật typosquatting."*
- **Classifier**: *"Xác suất 0.9977 — model rất chắc chắn đây là mã độc."*
- **Verdict — MALICIOUS**: *"Phát hiện chính xác. Nhìn vào code preview, ta thấy code thu thập environment variables và gửi ra ngoài."*

---

### Scene 3: Evasion Attack — dfdfdfdfhhh (4 phút)

**Click card `dfdfdfdfhhh`.**

Xuất hiện banner **G4 Evasion Case Study** — giải thích:

> *"Package này là trường hợp đặc biệt nhất. Attacker đã sử dụng kỹ thuật 'middle-zone evasion' — thêm hàng trăm dòng whitespace để đẩy payload vào vùng token 256–511."*

#### Bước 3a — HEAD strategy (đang chọn mặc định)

Nhấn **Run Detection Pipeline**.

- *"Với HEAD strategy, model lấy token 0–511. Vùng này bao phủ cả token 256–511 → thấy được exec(base64.b64decode(...)) → Xác suất 0.9974 → MALICIOUS. Phát hiện thành công!"*

#### Bước 3b — Chuyển sang HEAD+TAIL strategy

**Click button `HEAD+TAIL (0–255 | 512+)`**, nhấn **Run Detection Pipeline**.

- *"HEAD+TAIL lấy 256 token đầu và 256 token cuối. Nhưng payload nằm ở vùng 256–511 — không phải đầu, không phải cuối. Kết quả..."*
- **Verdict — CLEAN**: *"Model bị đánh lừa hoàn toàn! Xác suất chỉ 0.886 — dưới ngưỡng 0.90. Đây là False Negative."*
- *"Đây chính là blind spot của HEAD+TAIL strategy mà chúng tôi đã phân tích trong Experiment G4. Sliding Window sẽ giải quyết được vấn đề này nhưng tốn 4–8 giờ CPU cho toàn bộ D2."*

---

### Kết luận (1 phút)

> *"Kết quả reproduction: D1 accuracy 96.67% (paper: 97.7%), D2 package accuracy 98.09% (paper: 99.5%). Sai lệch trong ngưỡng chấp nhận được do non-determinism của deep learning.*
>
> *Đóng góp chính: phân tích attack surface của truncation strategy — HEAD có Recall 100% nhưng có blind spot ở token 512+, HEAD+TAIL cải thiện Precision nhưng tạo ra blind spot ở token 256–511 như vừa thấy."*

---

## Cấu trúc

```
demo/
├── backend/
│   ├── app.py        # FastAPI server, asyncio.to_thread cho non-blocking inference
│   └── scanner.py    # CodeBERT wrapper, THRESHOLD=0.90, 3 pre-staged packages
├── frontend/
│   ├── index.html    # Light-mode UI, Syne + Manrope + JetBrains Mono
│   └── app.js        # Pipeline animation, 4 bước với STEP_DELAYS
└── requirements.txt  # fastapi, uvicorn[standard], python-multipart
```

## Model

- **ID**: `KevinPhamH/codebert-finetuned`
- **Threshold**: 0.90 (matches D2 evaluation config)
- **Strategy**: head (default) / head_tail (toggle cho dfdfdfdfhhh)
- **Device**: CPU (auto-detect CUDA nếu có)
