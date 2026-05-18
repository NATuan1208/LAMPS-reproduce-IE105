# LAMPS Demo - Web Interface

Demo minh hoa LAMPS package-malware detection bang CodeBERT fine-tuned tren 3 mau local deterministic:

- `click-8.3.2`: package benign baseline.
- `aio3`: typosquat co payload base64 trong `setup.py`.
- `dfdfdfdfhhh`: middle-zone evasion case, HEAD detect duoc nhung HEAD+TAIL bi false negative tai threshold `0.90`.

Demo nay la **Quarantined Static Analysis**. Backend chi doc source fixture local trong `D2_dataset/`, tokenize/chay CodeBERT, decode base64 nhu du lieu tinh, va hien IOC bang text. Khong `pip install`, khong import package, khong chay `setup.py`, khong goi shell command payload, khong mo URL.

## 1. Chuan Bi

Chay tu thu muc goc repo `LAMPS/`:

```powershell
.venv\Scripts\pip.exe install -r demo/requirements.txt
```

Neu model da duoc cache local, nen bat offline mode de tranh Hugging Face network probe trong luc demo:

```powershell
$env:HF_HUB_OFFLINE="1"
$env:TRANSFORMERS_OFFLINE="1"
```

## 2. Khoi Dong Server

```powershell
.venv\Scripts\python.exe -m uvicorn demo.backend.app:app --host 127.0.0.1 --port 8000
```

Cho log:

```text
Loading CodeBERT model - please wait (~20s)...
Model ready. Open http://localhost:8000
Application startup complete.
Uvicorn running on http://127.0.0.1:8000
```

Mo trinh duyet tai:

```text
http://127.0.0.1:8000
```

## 3. Kiem Tra Model Va API Da San Sang

Mo PowerShell thu hai, chay:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/ | Select-Object StatusCode
Invoke-RestMethod http://127.0.0.1:8000/packages
```

Expected:

- `/` tra `StatusCode = 200`.
- `/packages` tra 3 package: `aio3`, `dfdfdfdfhhh`, `click`.

Kiem tra scan nhanh:

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:8000/scan `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"package_id":"dfdfdfdfhhh","strategy":"head_tail"}' |
  Select-Object package_id,strategy,verdict,sandbox,strategy_comparison
```

Expected voi model hien tai:

- `package_id = dfdfdfdfhhh`
- `strategy = head_tail`
- `verdict = benign`
- `sandbox.analysis_mode = static`
- `sandbox.executed = false`
- `strategy_comparison.head ~= 0.9974`
- `strategy_comparison.head_tail ~= 0.8863`
- `strategy_comparison.threshold = 0.9`

Neu server fail vi port dang duoc dung:

```powershell
Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,State,OwningProcess
```

Sau do stop process cu neu chac chan dung la demo server:

```powershell
Stop-Process -Id <OwningProcess> -Force
```

## 4. Kich Ban Demo Tren Lop

Tong thoi gian: 8-10 phut.

### Mo Dau

Noi ngan gon:

> "Demo nay reproduce huong tiep can cua LAMPS: dung CodeBERT fine-tuned de phan loai source Python trong package PyPI. Diem quan trong la demo khong chay malware. Moi thu nam trong quarantine/static analysis: load source local, tokenize, classify, decode payload nhu text, roi dua verdict."

Chi nhanh vao thanh progress 5 buoc:

1. **Quarantine / Load**: nap source fixture local, hash file, khong execute.
2. **Safe Extract**: doc source read-only, khong `pip install`, khong import, khong `setup.py`.
3. **CodeBERT Tokenization**: cat/lay token theo strategy va tinh probability.
4. **Payload Evidence**: static inspector decode base64 va hien IOC/API/path.
5. **Final Verdict**: tong hop ket qua voi threshold `0.90`.

### Scene 1 - Benign Baseline: `click-8.3.2`

Thao tac:

1. Chon card `click-8.3.2`.
2. Bam **Run Detection Pipeline**.

Noi khi pipeline hien thi:

- "Day la package CLI hop le cua Pallets Project, dung lam baseline benign."
- "Quarantine cho thay 3 file duoc scan, `executed = NO`, network block bat."
- "Payload Evidence khong co decoded payload/IOC dang nghi."
- "CodeBERT cho probability thap, verdict cuoi la CLEAN/benign."

Thong diep chinh:

> "Baseline sach giup cho thay demo khong phai cu thay `subprocess` hay URL trong code hop le la gan nhan malicious; payload evidence chi hien khi co anchor payload ro rang."

### Scene 2 - Typosquat Payload: `aio3`

Thao tac:

1. Chon card `aio3`.
2. De strategy mac dinh `head`.
3. Bam **Run Detection Pipeline**.

Noi khi hien evidence:

- "`aio3` giong ten `aiohttp`, day la typosquatting."
- "Static inspector tim thay `base64.b64decode`, `exec`, `urlopen`, va URL/domain trong payload da decode."
- "Quan trong: payload chi duoc decode nhu text; demo khong mo URL va khong chay code."
- "CodeBERT probability khoang `0.9977`, vuot threshold `0.90`, nen verdict la MALICIOUS."

Thong diep chinh:

> "Voi mau payload o dau file/setup.py, HEAD strategy va static evidence deu nhin thay dau hieu doc hai."

### Scene 3 - Evasion Boundary: `dfdfdfdfhhh`

Thao tac A - HEAD:

1. Chon card `dfdfdfdfhhh`.
2. Chon **HEAD (0-511 tokens)**.
3. Bam **Run Detection Pipeline**.

Noi:

- "Day la middle-zone evasion: attacker chen whitespace de day payload vao vung token 256-511."
- "HEAD lay token 0-511 nen van bao phu vung payload."
- "Probability khoang `0.9974`, verdict MALICIOUS."

Thao tac B - HEAD+TAIL:

1. Chon **HEAD+TAIL (0-255 | 512+)**.
2. Bam **Run Detection Pipeline** lai.

Noi:

- "HEAD+TAIL lay dau va cuoi, nhung bo qua vung 256-511."
- "Voi mau nay probability giam con khoang `0.8863`, thap hon threshold `0.90`."
- "Verdict thanh CLEAN/benign, day la false negative do truncation strategy."
- "Payload Evidence van hien Windows persistence, `bitsadmin`, Startup/VBS/BAT path, va download indicator vi inspector doc toan bo source tinh."

Thong diep chinh:

> "Classifier co the bi anh huong boi truncation strategy. Static payload inspector khong thay the model, nhung giup giai thich verdict va chi ra IOC de nguoi xem hieu tai sao sample nguy hiem."

### Ket Luan

Noi:

> "Demo cho thay 3 y: package benign duoc giu sach, typosquat payload bi phat hien, va middle-zone evasion tao false negative khi dung HEAD+TAIL tai threshold 0.90. Boundary cua demo la static quarantine, nen an toan cho lop hoc va dung voi tinh chat cua LAMPS/CodeBERT: phan tich source, khong detonate malware."

## 5. Cau Truc Demo

```text
demo/
  backend/
    app.py                 FastAPI server, load model trong lifespan
    scanner.py             CodeBERT wrapper, THRESHOLD=0.90, 3 package fixtures
    payload_inspector.py   Static base64/IOC inspector; no execution
  frontend/
    index.html             Light-mode classroom UI
    app.js                 5-step pipeline animation and API rendering
  requirements.txt         fastapi, uvicorn[standard], python-multipart
```

## 6. Model

- Model ID: `KevinPhamH/codebert-finetuned`
- Threshold: `0.90`
- Default strategy: `head`
- Evasion toggle: `head` vs `head_tail`
- Device: CPU by default, CUDA if available
