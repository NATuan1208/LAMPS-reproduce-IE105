// Pipeline step reveal delays (ms)
const STEP_DELAYS = { A: 80, B: 900, C: 1800, D: 3300 };

// Lucide-compatible inline SVG snippets used in dynamic content
const IC = {
  fileCode: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="m10 13-2 2 2 2"/><path d="m14 17 2-2-2-2"/></svg>`,
  shieldX:   `<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>`,
  shieldOk:  `<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><polyline points="9 12 11 14 15 10"/></svg>`,
  info:      `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`,
  alert:     `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="17" r=".5" fill="currentColor"/></svg>`,
};

// State
let packages = [];
let selectedId = null;
let selectedStrategy = 'head';
let scanning = false;

// Bootstrap
(async () => {
  const res = await fetch('/packages');
  packages = await res.json();
  renderCards();
})();

// ── Cards ─────────────────────────────────────────────────────────────

function cardClass(pkg, selected) {
  const type = pkg.type === 'malicious' ? 'mal' : 'ok';
  return `pkg-card ${type}${selected ? ' selected' : ''}`;
}

function renderCards() {
  document.getElementById('pkg-grid').innerHTML = packages.map(p => {
    const mal = p.type === 'malicious';
    const badgeClass = mal ? 'badge-red' : 'badge-green';
    return `
    <div id="card-${p.id}" onclick="selectPkg('${p.id}')" class="${cardClass(p, false)}">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:.5rem;margin-bottom:.5rem;">
        <span class="mono" style="font-size:.72rem;font-weight:500;color:var(--text);word-break:break-all;">${p.display_name}</span>
        <span class="badge ${badgeClass}" style="flex-shrink:0;">${p.type}</span>
      </div>
      <p style="font-size:.73rem;color:var(--muted);line-height:1.55;">${p.description}</p>
      ${p.strategy_demo ? `
        <div style="display:flex;align-items:center;gap:.375rem;margin-top:.625rem;">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="17" r=".5" fill="currentColor"/></svg>
          <span class="mono" style="font-size:.65rem;color:var(--amber);">evasion case study</span>
        </div>` : ''}
    </div>`;
  }).join('');
}

function selectPkg(id) {
  selectedId = id;
  const pkg = packages.find(p => p.id === id);
  packages.forEach(p => {
    document.getElementById(`card-${p.id}`).className = cardClass(p, p.id === id);
  });

  const ss = document.getElementById('strategy-section');
  if (pkg.strategy_demo) {
    ss.classList.remove('hidden');
    ss.classList.add('slide-up');
    setStrategy('head');
  } else {
    ss.classList.add('hidden');
    selectedStrategy = 'head';
  }

  resetPipeline();
  document.getElementById('scan-btn').disabled = false;
}

// ── Strategy ──────────────────────────────────────────────────────────

function setStrategy(s) {
  selectedStrategy = s;
  document.getElementById('btn-head').className      = `strat-btn ${s === 'head'      ? 'active' : 'inactive'}`;
  document.getElementById('btn-head-tail').className = `strat-btn ${s === 'head_tail' ? 'active' : 'inactive'}`;

  const hint = document.getElementById('strategy-hint');
  hint.style.opacity = '1';
  hint.innerHTML = s === 'head'
    ? '→ HEAD (0–511): bao phủ token 256–511 → <span style="color:var(--red);font-weight:500;">PHÁT HIỆN</span> payload'
    : '→ HEAD+TAIL (0–255 ∪ 512+): bỏ qua 256–511 → <span style="color:var(--amber);font-weight:500;">BỎ LỠ</span> payload (evasion!)';

  resetPipeline();
}

// ── Scan ──────────────────────────────────────────────────────────────

async function startScan() {
  if (!selectedId || scanning) return;
  scanning = true;

  const btn   = document.getElementById('scan-btn');
  const icon  = document.getElementById('scan-icon');
  const label = document.getElementById('scan-label');
  btn.disabled = true;
  icon.innerHTML = `<span class="spinner" style="display:inline-block;width:13px;height:13px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;"></span>`;
  label.textContent = 'Scanning…';

  resetPipeline();
  const pipeline = document.getElementById('pipeline');
  pipeline.classList.remove('hidden');
  pipeline.style.display = 'flex';

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package_id: selectedId, strategy: selectedStrategy }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    animatePipeline(await res.json());
  } catch (e) {
    pipeline.classList.add('hidden');
    alert('Scan failed: ' + e.message);
  } finally {
    scanning = false;
    btn.disabled = false;
    icon.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 3 20 12 6 21 6 3"/></svg>`;
    label.textContent = 'Run Detection Pipeline';
  }
}

// ── Pipeline ──────────────────────────────────────────────────────────

function animatePipeline(data) {
  setTimeout(() => renderStepA(data), STEP_DELAYS.A);
  setTimeout(() => renderStepB(data), STEP_DELAYS.B);
  setTimeout(() => renderStepC(data), STEP_DELAYS.C);
  setTimeout(() => renderStepD(data), STEP_DELAYS.D);
}

function reveal(id) {
  const el = document.getElementById(id);
  el.classList.remove('hidden');
  el.classList.add('slide-up');
}

function resetPipeline() {
  ['step-a', 'step-b', 'step-c', 'step-d'].forEach(id => {
    const el = document.getElementById(id);
    el.classList.add('hidden');
    el.classList.remove('slide-up');
  });
  const pipeline = document.getElementById('pipeline');
  pipeline.classList.add('hidden');
  pipeline.style.display = '';
}

// Step A — Package Loader
function renderStepA(data) {
  const totalTok = data.files.reduce((s, f) => s + f.token_count, 0);
  const tokenColor = data.verdict === 'malicious' ? 'var(--red)' : 'var(--green)';
  document.getElementById('step-a-body').innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.625rem;margin-bottom:.875rem;">
      ${statCard(data.file_count, 'Python files', 'var(--blue)')}
      ${statCard('PyPI', 'Source', 'var(--muted)')}
      ${statCard(totalTok.toLocaleString(), 'Total tokens', tokenColor)}
    </div>
    <div style="display:flex;flex-direction:column;gap:.375rem;">
      ${data.files.map(f => `
        <div class="file-row">
          ${IC.fileCode}
          <span class="mono" style="font-size:.7rem;color:var(--text);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${f.filename}</span>
          <span class="mono" style="font-size:.68rem;color:var(--muted);flex-shrink:0;">${f.token_count.toLocaleString()} tok</span>
        </div>`).join('')}
    </div>`;
  reveal('step-a');
}

// Step B — Tokenizer
function renderStepB(data) {
  document.getElementById('step-b-body').innerHTML = data.files.map(f => `
    <div class="file-row" style="justify-content:space-between;">
      <span class="mono" style="font-size:.7rem;color:var(--text);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${f.filename}</span>
      <div style="display:flex;align-items:center;gap:.5rem;flex-shrink:0;">
        <span class="mono" style="font-size:.68rem;color:var(--muted);">${f.token_count} tokens</span>
        ${f.is_truncated
          ? `<span class="badge badge-amber">TRUNCATED &gt;512</span>`
          : `<span class="badge badge-neutral">fits 512</span>`}
      </div>
    </div>`).join('') + (data.truncated_count > 0 ? `
    <div style="display:flex;align-items:center;gap:.375rem;padding:.5rem .625rem;background:var(--amber-bg);border-radius:6px;border:1px solid var(--amber-border);">
      <span style="color:var(--amber);">${IC.alert}</span>
      <span class="mono" style="font-size:.68rem;color:var(--amber);">${data.truncated_count}/${data.file_count} file(s) exceed 512-token limit · strategy: ${data.strategy}</span>
    </div>` : `
    <div style="display:flex;align-items:center;gap:.375rem;padding:.5rem .625rem;background:var(--green-bg);border-radius:6px;border:1px solid var(--green-border);">
      <span style="color:var(--green);">${IC.info}</span>
      <span class="mono" style="font-size:.68rem;color:var(--green);">All files within 512-token window — no truncation applied</span>
    </div>`);
  reveal('step-b');
}

// Step C — Classifier
function renderStepC(data) {
  document.getElementById('step-c-body').innerHTML = data.files.map((f, i) => {
    const mal  = f.label === 'malicious';
    const pct  = Math.round(f.probability * 100);
    const clr  = mal ? 'var(--red)' : 'var(--green)';
    const pill = mal ? 'badge-red' : 'badge-green';
    return `
    <div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.375rem;">
        <span class="mono" style="font-size:.7rem;color:var(--text);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-right:.625rem;">${f.filename}</span>
        <div style="display:flex;align-items:center;gap:.5rem;flex-shrink:0;">
          <span class="mono" style="font-size:.75rem;font-weight:500;color:${clr};">${f.probability.toFixed(4)}</span>
          <span class="badge ${pill}">${f.label}</span>
        </div>
      </div>
      <div style="height:5px;background:var(--surface-2);border-radius:3px;border:1px solid var(--border);overflow:hidden;">
        <div id="bar-${i}" class="prob-bar" style="width:0%;height:100%;background:${clr};border-radius:3px;"></div>
      </div>
      <p class="mono" style="margin-top:.25rem;font-size:.65rem;color:var(--muted);">P(malicious) = ${pct}%</p>
    </div>`;
  }).join('');
  reveal('step-c');
  requestAnimationFrame(() => requestAnimationFrame(() => {
    data.files.forEach((f, i) => {
      document.getElementById(`bar-${i}`).style.width = Math.round(f.probability * 100) + '%';
    });
  }));
}

// Step D — Verdict
function renderStepD(data) {
  const mal     = data.verdict === 'malicious';
  const flagged = data.files.filter(f => f.label === 'malicious');
  const worst   = flagged.sort((a, b) => b.probability - a.probability)[0];

  const clr  = mal ? 'var(--red)'   : 'var(--green)';
  const icon = mal ? IC.shieldX     : IC.shieldOk;
  const cls  = mal ? 'mal'          : 'ok';
  const word = mal ? 'MALICIOUS'    : 'CLEAN';

  let evNote = '';
  if (data.strategy_demo) {
    if (!mal && data.strategy === 'head_tail') {
      evNote = `
        <div style="display:flex;gap:.625rem;align-items:flex-start;padding:.875rem 1rem;background:var(--amber-bg);border:1.5px solid var(--amber-border);border-radius:8px;margin-top:.75rem;">
          <span style="color:var(--amber);flex-shrink:0;margin-top:1px;">${IC.alert}</span>
          <div>
            <p class="syne" style="font-size:.78rem;font-weight:700;color:var(--amber);margin-bottom:.25rem;">Evasion Thành Công — Middle-Zone Attack</p>
            <p style="font-size:.73rem;color:#92400E;line-height:1.6;">HEAD+TAIL bỏ qua vùng token 256–511 — đúng chỗ payload được giấu. Chuyển sang <strong>HEAD strategy</strong> để phát hiện.</p>
          </div>
        </div>`;
    } else if (mal && data.strategy === 'head') {
      evNote = `
        <div style="display:flex;gap:.625rem;align-items:flex-start;padding:.875rem 1rem;background:#EFF6FF;border:1.5px solid #BFDBFE;border-radius:8px;margin-top:.75rem;">
          <span style="color:var(--blue);flex-shrink:0;margin-top:1px;">${IC.info}</span>
          <div>
            <p class="syne" style="font-size:.78rem;font-weight:700;color:var(--blue);margin-bottom:.25rem;">HEAD Strategy — Covers Token 256–511</p>
            <p style="font-size:.73rem;color:#1e40af;line-height:1.6;">HEAD (0–511) bao phủ toàn bộ vùng payload. Thử <strong>HEAD+TAIL</strong> để xem evasion attack thực tế.</p>
          </div>
        </div>`;
    }
  }

  const previewBlock = (mal && worst) ? `
    <div class="code-block" style="margin-top:.75rem;">
      <div class="code-header">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <span class="mono" style="font-size:.65rem;color:var(--muted);">Flagged: ${worst.filename} · P = ${worst.probability.toFixed(4)}</span>
      </div>
      <pre style="padding:.875rem;overflow-x:auto;max-height:200px;overflow-y:auto;"><code class="language-python hljs">${hljs.highlight(worst.preview, { language: 'python', ignoreIllegals: true }).value}</code></pre>
    </div>` : '';

  const el = document.getElementById('step-d');
  el.innerHTML = `
    <div class="verdict-card ${cls}">
      <div style="color:${clr};">${icon}</div>
      <div style="flex:1;">
        <div class="syne" style="font-size:1.625rem;font-weight:800;letter-spacing:-.02em;color:${clr};line-height:1;">${word}</div>
        <div class="mono" style="font-size:.68rem;color:var(--muted);margin-top:.375rem;">${data.display_name}</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:.25rem;align-items:flex-end;flex-shrink:0;">
        <span class="mono" style="font-size:.68rem;color:var(--muted);">${data.file_count} file(s) scanned</span>
        <span class="mono" style="font-size:.68rem;color:var(--muted);">${flagged.length} flagged · strategy: ${data.strategy}</span>
        ${worst ? `<span class="mono" style="font-size:.68rem;color:${clr};font-weight:500;">max P = ${worst.probability.toFixed(4)}</span>` : ''}
      </div>
    </div>
    ${evNote}${previewBlock}`;
  reveal('step-d');
}

// ── Helpers ───────────────────────────────────────────────────────────

function statCard(value, label, color) {
  return `
    <div class="stat-card">
      <div class="syne" style="font-size:1.2rem;font-weight:800;color:${color};letter-spacing:-.01em;">${value}</div>
      <div style="font-size:.65rem;color:var(--muted);margin-top:.25rem;">${label}</div>
    </div>`;
}
