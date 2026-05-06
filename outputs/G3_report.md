# G3 Report -- Real-World Class Imbalance Evaluation

**IE105 · UIT · HK2 2025-2026**
Model: `KevinPhamH/codebert-finetuned` | Dataset: D2 (1328 files, 306 mal files / 1022 ben files, file-level ratio ~1:3.7)

---

## 1. Tom tat

Paper goc bao cao D2 accuracy = **99.5%** tren dataset co ty le file-level gan can bang (~1:3.7). Thuc nghiem G3 cho thay khi ty le imbalance tang dan nhu ngoai doi thuc, **precision suy giam nghiem trong**:

- O ty le **1:50** (van lac quan hon thuc te nhieu): Precision chi con **29.6%** -- tuc 7 trong 10 canh bao la false alarm.
- O ty le **1:200** (uoc tinh thuc te PyPI): Precision theo Bayesian chi con **9.5%** -- tuc **cu 11 canh bao thi chi co 1 la that**.
- Recall = **100%** o tat ca cac ty le -- model khong bo sot package doc hai nao, nhung tao qua nhieu false alarm.

**Ket luan:** Paper khong co diem yeu ve do nhay (recall), nhung co diem yeu nghiem trong ve **tinh thuc te cua danh gia** -- accuracy cao tren balanced dataset khong phan anh duoc hanh vi thuc khi deploy.

> **Luu y ve methodology:** PLAN_G3.md ban dau yeu cau dung 5 split files co san (`package_split_seed*.json`). Tuy nhien, sau khi kiem tra thuc te, cac split files nay tham chieu dataset phien ban cu -- sau khi map vao `metadata.json` hien tai, toan bo malicious files bi mat khoi test sets (0 malicious trong 5 splits), khong the thuc hien danh gia co y nghia. Do do, da chuyen sang phuong phap **controlled ratio experiment** (giu nguyen benign pool, subsample malicious), la phuong phap chuan trong nghien cuu imbalanced classification va dat dung muc tieu G3.

---

## 2. Thiet lap thuc nghiem

| Thong so                 | Gia tri                                            |
|--------------------------|----------------------------------------------------|
| Model                    | `KevinPhamH/codebert-finetuned`                    |
| Dataset                  | D2 (1328 files: 306 malicious + 1022 benign)      |
| File-level ratio (paper) | ~1:3.7                                             |
| Package level            | 233 malicious packages + 396 benign packages       |
| Threshold                | 0.5                                                |
| Bootstrap seeds          | 42, 123, 456, 789, 1024                            |
| Ty le thuc nghiem        | 1:3.7, 1:7, 1:10, 1:20, 1:50                       |
| Priors Bayesian          | 1:10, 1:50, 1:100, 1:200                           |

**Phuong phap:**
1. Chay inference **1 lan** tren toan bo 1328 files -- luu probability scores.
2. Voi moi ty le imbalance: giu nguyen **396 benign packages**, subsample malicious packages de dat ty le mong muon (controlled ratio experiment).
3. Lap 5 seeds -- tinh mean +/- std.
4. Bayesian extrapolation -- uoc tinh precision tai cac prior thuc te hon.

---

## 3. Ket qua thuc nghiem (Package-level, Conservative Verdict)

### 3.1. Baseline -- Toan bo D2 (khong subsample)

| Metric                    | Gia tri                    |
|---------------------------|----------------------------|
| Ty le file (paper D2)     | ~1:3.7                     |
| Ty le package             | 1:1.7 (233 mal / 396 ben)  |
| Precision                 | **92.5%**                  |
| Recall                    | **100.0%**                 |
| F1                        | **96.1%**                  |
| Average Precision (AP)    | **0.9852**                 |
| FPR (False Positive Rate) | **4.80%**                  |

> Paper bao cao accuracy=99.5% tren D2. Thuc nghiem G3 do duoc FPR=4.80% tren toan bo dataset -- day la nguon goc cua van de khi deploy thuc te.

### 3.2. Imbalanced Evaluation -- Precision suy giam theo ty le

| Ty le (file-level)             | #Mal pkgs | Precision | Recall | F1    | AP (mean +/- std) |
|--------------------------------|-----------|-----------|--------|-------|-------------------|
| ~1:3.7 *(paper D2 file ratio)* | 107       | **84.9%** | 100.0% | 91.8% | 0.9679 +/- 0.0020 |
| 1:7                            | 57        | **75.0%** | 100.0% | 85.7% | 0.9445 +/- 0.0059 |
| 1:10                           | 40        | **67.8%** | 100.0% | 80.8% | 0.9271 +/- 0.0078 |
| 1:20                           | 20        | **51.3%** | 100.0% | 67.8% | 0.8901 +/- 0.0358 |
| 1:50                           | 8         | **29.6%** | 100.0% | 45.7% | 0.7610 +/- 0.1298 |

**Nhan xet:**
- Recall giu nguyen **100%** o moi ty le -- model khong bo sot package doc hai nao.
- Precision suy giam don dieu khi ratio tang: tu 84.9% (1:3.7) xuong 29.6% (1:50).
- AP cung giam theo (0.9679 xuong 0.7610) nhung std tang cao o 1:50 (do so malicious qua it, chi ~8 packages).
- Precision_std = 0 vi benign pool co dinh (396 packages, FP count khong doi giua cac seeds).

---

## 4. Phan tich Bayesian -- Precision ky vong khi deploy thuc te

**Cong thuc:**
```
P(malicious | alarm) = TPR x prior / (TPR x prior + FPR x (1 - prior))

Dung: TPR = 100.0%, FPR = 4.80% (tu baseline toan bo D2)
```

| Prior (ty le thuc te)     | Precision ky vong | FDR (False Alarm Rate) | Dien giai                          |
|---------------------------|-------------------|------------------------|------------------------------------|
| 1:10 (10% malicious)      | **69.8%**         | 30.2%                  | Cu 3 canh bao co 1 false alarm     |
| 1:50 (2% malicious)       | **29.8%**         | 70.2%                  | Cu 3 canh bao co 2 false alarm     |
| 1:100 (1% malicious)      | **17.4%**         | 82.6%                  | Cu 6 canh bao co 5 false alarm     |
| **1:200 (0.5% malicious)**| **9.5%**          | **90.5%**              | **Cu 11 canh bao chi co 1 la that**|

> Ty le thuc te tren PyPI uoc tinh ~0.1-0.5% (1:200 den 1:1000). O prior 1:200, **91% canh bao cua LAMPS la false alarm** -- paper hoan toan khong de cap den dieu nay.

---

## 5. So sanh voi Paper

| Metric                         | Paper bao cao      | G3 thuc nghiem                    | Ghi chu                           |
|--------------------------------|--------------------|-----------------------------------|-----------------------------------|
| Accuracy (D2)                 | **99.5%**          | Khong do truc tiep                | Paper dung balanced dataset       |
| Precision (tai ty le paper ~1:3.7) | Khong bao cao | **84.9%**                         | Thap hon claim nhieu              |
| Recall                        | Khong bao cao ro   | **100%** moi ty le                | Diem manh cua model               |
| Average Precision             | **Khong bao cao**  | 0.9852 (balanced) -- 0.7610 (1:50)| Paper thieu metric nay            |
| FDR tai prior 1:200          | **Khong de cap**   | **90.5%**                         | Diem yeu nghiem trong bi bo qua   |
| Dataset ratio duoc dung       | ~1:3.7 (file-level)| Kiem tra nhieu ty le tu 1:3.7 den 1:50 | G3 phu rong hon              |

---

## 6. Diem yeu cua paper duoc chung minh

**G3 da chung minh duoc 3 diem yeu cu the:**

### 6.1. Metric danh gia khong phu hop voi bai toan detection
Paper dung **accuracy** lam metric chinh. Voi bai toan phat hien malware (imbalanced classification), accuracy khong phan anh thuc te. Average Precision (AP = 0.985) va PR curve moi la metrics dung.

### 6.2. Dataset khong phan anh real-world distribution
Paper dung ty le file-level ~1:3.7 -- qua can bang so voi thuc te PyPI (~1:200). Precision o 1:3.7 (84.9%) thap hon dang ke so voi claim 99.5% accuracy cua paper.

### 6.3. False Discovery Rate khong duoc phan tich
Voi FPR=4.8% tren balanced test, **91% canh bao la false alarm** khi deploy o prior 1:200. Paper hoan toan khong de cap den dieu nay, dan den danh gia sai ve tinh kha dung thuc te cua LAMPS.

---

## 7. Huong cai thien de xuat

| Cai thien                           | Mo ta                                                                  |
|-------------------------------------|------------------------------------------------------------------------|
| **Dung Average Precision thay accuracy** | AP = 0.9852 la metric tot hon, khong phu thuoc threshold          |
| **Tang threshold khi deploy**       | Tang threshold tu 0.5 len 0.8-0.9 giam FPR, cai thien precision o prior thap |
| **Bao cao PR curve**                | Thay single-point accuracy bang toan bo PR curve de nguoi dung tu chon operating point |
| **Danh gia tren imbalanced dataset**| Test tren dataset co ty le 1:50, 1:100 thay vi chi balanced          |
| **Calibrate prior**                 | Dung Platt scaling de calibrate probability scores theo prior thuc    |

---

## 8. Files lien quan

| File                              | Mo ta                                                                 |
|-----------------------------------|-----------------------------------------------------------------------|
| `evaluation/metrics.py`           | Them `compute_pr_curve`, `compute_average_precision`, `compute_bayesian_precision`, `compute_expected_fdr` |
| `evaluation/run_d2_imbalanced.py` | Script chinh cua G3 (controlled ratio experiment)                     |
| `outputs/g3_imbalance_results.json` | Ket qua day du (JSON)                                               |
| `outputs/G3_report.md`            | File nay                                                              |
