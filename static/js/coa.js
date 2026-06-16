/**
 * coa.js  –  COA Panel: Memory / Branch / Pipeline / Cache / Processing
 * All rendering is pure DOM; no framework dependency.
 */
"use strict";

/* ── shared with ui.js ────────────────────────────────────────── */
const _api = path => fetch(path).then(r => r.json()).catch(() => null);
const _post = (path, body) =>
  fetch(path, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) })
    .then(r => r.json()).catch(() => null);

function _h64(n) {
  if (n === undefined || n === null) return '0x0';
  return '0x' + (n).toString(16);
}
function _fmt(n) {
  if (n === undefined) return '?';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}
function _esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function _pct(v, max) {
  return Math.min(100, Math.max(0, (v / (max || 1)) * 100)).toFixed(1);
}

/* ── COA Panel state ──────────────────────────────────────────── */
const COA = {
  active: false,
  tab: 'memory',
  poll: null,
  last: null,
};

/* ════════════════════════════════════════════════════════════════
   ENTRY POINT – call after binary is loaded
════════════════════════════════════════════════════════════════ */
function coaInit() {
  COA.active = true;
  document.getElementById('coa-panel').classList.remove('hidden');
  coaSwitchTab(COA.tab);
  if (!COA.poll) {
    COA.poll = setInterval(coaRefresh, 1200);
  }
}

function coaDestroy() {
  COA.active = false;
  if (COA.poll) { clearInterval(COA.poll); COA.poll = null; }
  document.getElementById('coa-panel').classList.add('hidden');
}

async function coaRefresh() {
  if (!COA.active) return;
  const data = await _api('/api/coa/all');
  if (!data) return;
  COA.last = data;
  renderActiveTab(data);
  updateCoaSummaryBar(data);
}

function coaSwitchTab(name) {
  COA.tab = name;
  document.querySelectorAll('.coa-tab-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.ctab === name));
  document.querySelectorAll('.coa-panel-body').forEach(p =>
    p.classList.toggle('hidden', p.dataset.cpanel !== name));
  if (COA.last) renderActiveTab(COA.last);
  else coaRefresh();
}

function renderActiveTab(data) {
  if (!data) return;
  const t = COA.tab;
  if (t === 'memory')     renderMemory(data.memory);
  if (t === 'branch')     renderBranch(data.branch);
  if (t === 'pipeline')   renderPipeline(data.pipeline);
  if (t === 'cache')      renderCache(data.cache);
  if (t === 'processing') renderProcessing(data.processing, data.pipeline);
}

document.querySelectorAll('.coa-tab-btn').forEach(btn =>
  btn.addEventListener('click', () => coaSwitchTab(btn.dataset.ctab)));

/* ════════════════════════════════════════════════════════════════
   SUMMARY BAR  (always visible across top of COA panel)
════════════════════════════════════════════════════════════════ */
function updateCoaSummaryBar(data) {
  const p = data.pipeline, c = data.cache, b = data.branch, pr = data.processing;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('coa-ipc',     p?.ipc?.toFixed(3)   ?? '—');
  set('coa-cpi',     p?.cpi?.toFixed(3)   ?? '—');
  set('coa-l1hit',   (c?.levels?.[1]?.hit_rate?.toFixed(1) ?? '—') + '%');
  set('coa-l2hit',   (c?.levels?.[2]?.hit_rate?.toFixed(1) ?? '—') + '%');
  set('coa-bpred',   (b?.hit_rate?.toFixed(1) ?? '—') + '%');
  set('coa-stalls',  p?.stalls ?? '—');
  set('coa-insns',   (p?.retired ?? 0).toLocaleString());
  set('coa-faults',  data.memory?.unmapped?.length ?? 0);
  const pie = data.memory?.is_pie;
  const pieBadge = document.getElementById('coa-pie-badge');
  if (pieBadge) {
    pieBadge.textContent = pie ? 'PIE' : 'STATIC';
    pieBadge.className   = 'coa-badge ' + (pie ? 'badge-pie' : 'badge-static');
  }
}

/* ════════════════════════════════════════════════════════════════
   1. MEMORY LAYOUT
════════════════════════════════════════════════════════════════ */
function renderMemory(mem) {
  if (!mem) return;
  renderRootCause();
  renderAddressMap(mem);
  renderRelocTable(mem);
  renderUnmappedLog(mem);
}

async function renderRootCause() {
  const rc = await _api('/api/coa/root_cause');
  if (!rc) return;
  const el = document.getElementById('coa-root-cause');
  if (!el) return;
  const issues = rc.root_cause?.issues ?? [];
  if (!issues.length) { el.innerHTML = '<div class="coa-ok">✓ No memory layout issues</div>'; return; }
  el.innerHTML = issues.map(i => `
    <div class="rca-card sev-${i.severity.toLowerCase()}">
      <div class="rca-header">
        <span class="rca-badge">${i.severity}</span>
        <span class="rca-id">${_esc(i.id)}</span>
        <span class="rca-title">${_esc(i.title)}</span>
      </div>
      <div class="rca-detail">${_esc(i.detail)}</div>
      <div class="rca-fix"><strong>Fix:</strong> ${_esc(i.fix)}</div>
    </div>`).join('');
}

function renderAddressMap(mem) {
  const el = document.getElementById('coa-addr-map');
  if (!el) return;
  const regions = mem.regions || [];
  // Build a visual address-space strip
  // Bucket addresses into visual lanes
  const VIRT_TOP = 0x800000000000;
  const buckets = regions.map(r => ({
    ...r,
    pct_start: Math.log2(Math.max(r.base, 1)) / Math.log2(VIRT_TOP) * 100,
    color: regionColor(r.label),
  }));

  el.innerHTML = `
    <div class="addr-map-strip">
      ${buckets.map(b => `
        <div class="addr-region" style="background:${b.color};left:${b.pct_start.toFixed(2)}%;width:max(1%,0.5%)"
          title="${b.label} @ ${_h64(b.base)} size=${_fmt(b.size)} flags=${b.flags}">
        </div>`).join('')}
    </div>
    <div class="addr-region-list">
      ${regions.slice(0, 30).map(r => `
        <div class="addr-row">
          <span class="addr-dot" style="background:${regionColor(r.label)}"></span>
          <span class="addr-label">${_esc(r.label)}</span>
          <span class="addr-range">${_h64(r.base)} – ${_h64(r.base + r.size)}</span>
          <span class="addr-size">${_fmt(r.size)}</span>
          <span class="addr-perms">${permsStr(r.flags)}</span>
          ${r.rw && r.rx ? '<span class="addr-warn" title="RWX region – security risk">⚠ RWX</span>' : ''}
        </div>`).join('')}
    </div>
    ${(mem.conflicts || []).length ? `
    <div class="coa-section-title" style="margin-top:10px;color:var(--red)">⚠ Layout Conflicts</div>
    ${mem.conflicts.map(c => `
      <div class="conflict-row">
        <span class="conflict-kind">${_esc(c.kind)}</span>
        <span class="conflict-addr">${_h64(c.address)}</span>
        <span class="conflict-detail">${_esc(c.detail)}</span>
      </div>`).join('')}` : ''}`;
}

function renderRelocTable(mem) {
  const el = document.getElementById('coa-reloc-table');
  if (!el) return;
  const relocs = (mem.relocations || []).slice(0, 60);
  if (!relocs.length) { el.innerHTML = '<div class="coa-empty">No relocations</div>'; return; }
  el.innerHTML = `
    <table class="coa-table">
      <thead><tr><th>Offset</th><th>Type</th><th>Symbol</th><th>Action</th></tr></thead>
      <tbody>${relocs.map(r => `
        <tr class="${r.type === 7 || r.type === 6 ? 'reloc-got' : ''}">
          <td class="mono">${_h64(r.offset)}</td>
          <td><span class="reloc-type-badge type-${r.type}">${relocTypeName(r.type)}</span></td>
          <td class="mono sym-col">${_esc(r.symbol || '—')}</td>
          <td class="reloc-action">${_esc(r.fixup)}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
}

function renderUnmappedLog(mem) {
  const el = document.getElementById('coa-unmapped-log');
  if (!el) return;
  const evs = mem.unmapped || [];
  if (!evs.length) { el.innerHTML = '<div class="coa-ok">✓ No unmapped accesses</div>'; return; }
  el.innerHTML = evs.map(e => `
    <div class="unmapped-row">
      <span class="unmapped-kind kind-${e.kind}">${e.kind}</span>
      <span class="unmapped-addr">${_h64(e.address)}</span>
    </div>`).join('');
}

function regionColor(label) {
  const map = {
    'seg_': '#00e5ff', text:'#00e5ff', stack:'#69ff47', heap:'#ffb347',
    data:'#ffd166', rodata:'#c084fc', bss:'#ff6b6b', stubs:'#ff9f43',
    null_page:'#ff6b6b', vdso:'#a29bfe', vsyscall:'#6c5ce7',
  };
  for (const [k, v] of Object.entries(map)) {
    if (label && label.toLowerCase().includes(k)) return v;
  }
  return '#8b949e';
}
function permsStr(f) {
  return [(f&4)?'R':'-',(f&2)?'W':'-',(f&1)?'X':'-'].join('');
}
function relocTypeName(t) {
  return {1:'ABS64',2:'PC32',6:'GLOB_DAT',7:'JUMP_SLOT',8:'RELATIVE',10:'COPY'}[t] || `T${t}`;
}

/* ════════════════════════════════════════════════════════════════
   2. BRANCH LAYOUT
════════════════════════════════════════════════════════════════ */
function renderBranch(br) {
  if (!br) return;
  const el = document.getElementById('coa-branch-body');
  if (!el) return;

  const s = br.stats || {};
  const total = s.total || 1;

  // Predictor state distribution
  const hist = br.history || [];
  const taken_pct = _pct(s.taken, total);
  const mispredict_pct = _pct(s.mispredicts, total);

  // Mini timeline: last 60 branch events as colored dots
  const recent = hist.slice(-60);
  const dotHTML = recent.map(e =>
    `<div class="branch-dot ${e.taken ? 'taken' : 'nottaken'} ${e.correct ? '' : 'mispredict'}"
      title="${_esc(e.mnemonic)} @ ${_h64(e.address)}\nTaken:${e.taken} Predicted:${e.predicted} Correct:${e.correct}"></div>`
  ).join('');

  // Hot spot table
  const spots = (br.hot_spots || []).slice(0, 15);

  el.innerHTML = `
    <div class="coa-2col">
      <div>
        <div class="coa-section-title">Predictor Statistics</div>
        <div class="bp-stat-grid">
          <div class="bp-stat-card"><div class="bp-stat-val" style="color:var(--green)">${s.taken?.toLocaleString() ?? 0}</div><div class="bp-stat-label">Taken</div></div>
          <div class="bp-stat-card"><div class="bp-stat-val" style="color:var(--muted)">${s.not_taken?.toLocaleString() ?? 0}</div><div class="bp-stat-label">Not Taken</div></div>
          <div class="bp-stat-card"><div class="bp-stat-val" style="color:var(--red)">${s.mispredicts?.toLocaleString() ?? 0}</div><div class="bp-stat-label">Mispredicts</div></div>
          <div class="bp-stat-card"><div class="bp-stat-val" style="color:var(--accent)">${br.hit_rate ?? 0}%</div><div class="bp-stat-label">Accuracy</div></div>
        </div>
        <div style="margin-top:10px">
          <div class="coa-mini-label">Taken rate</div>
          <div class="coa-bar-track"><div class="coa-bar-fill" style="width:${taken_pct}%;background:var(--green)"></div></div>
          <div class="coa-mini-label" style="margin-top:6px">Mispredict rate</div>
          <div class="coa-bar-track"><div class="coa-bar-fill" style="width:${mispredict_pct}%;background:var(--red)"></div></div>
        </div>
        <div class="coa-section-title" style="margin-top:14px">Branch Timeline (last ${recent.length})</div>
        <div class="branch-timeline">${dotHTML || '<div class="coa-empty">No branches yet</div>'}</div>
        <div class="branch-legend">
          <span class="branch-dot taken"></span> Taken &nbsp;
          <span class="branch-dot nottaken"></span> Not-taken &nbsp;
          <span class="branch-dot taken mispredict"></span> Mispredict
        </div>
      </div>
      <div>
        <div class="coa-section-title">Hot Branch Addresses (2-bit Saturating Counter)</div>
        <table class="coa-table">
          <thead><tr><th>Address</th><th>Mnemonic</th><th>State</th><th>Bias</th></tr></thead>
          <tbody>${spots.map(s => `
            <tr>
              <td class="mono">${_h64(s.address)}</td>
              <td class="mono">${_esc(s.mnemonic || '')}</td>
              <td><div class="state-pip">
                ${[0,1,2,3].map(i =>
                  `<div class="pip ${i <= s.state ? 'pip-on' : ''}"></div>`).join('')}
              </div></td>
              <td><span class="bias-badge ${s.bias === 'taken' ? 'bias-taken' : 'bias-nt'}">${s.bias}</span></td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`;
}

/* ════════════════════════════════════════════════════════════════
   3. PIPELINE LAYOUT
════════════════════════════════════════════════════════════════ */
const STAGE_COLORS = {
  Fetch:'#00e5ff', Decode:'#c084fc', Execute:'#ffb347',
  Memory:'#ff6b6b', WriteBack:'#69ff47'
};
const STAGE_ICONS = {
  Fetch:'⬇', Decode:'🔍', Execute:'⚙', Memory:'💾', WriteBack:'✏'
};

function renderPipeline(pl) {
  if (!pl) return;
  const el = document.getElementById('coa-pipeline-body');
  if (!el) return;

  const util = pl.utilisation || {};
  const snaps = (pl.snapshots || []).slice(-32);

  // Stage utilisation gauges
  const gaugeHTML = Object.entries(util).map(([stage, pct]) => `
    <div class="pipe-gauge">
      <div class="pipe-gauge-bar">
        <div class="pipe-gauge-fill" style="height:${pct}%;background:${STAGE_COLORS[stage]}">
          <span class="pipe-gauge-val">${pct}%</span>
        </div>
      </div>
      <div class="pipe-gauge-label">${STAGE_ICONS[stage] || ''} ${stage}</div>
    </div>`).join('');

  // Pipeline diagram: last 8 snapshots as a waterfall
  const waterfall = snaps.slice(-8).map((s, col) => {
    const stages = ['Fetch','Decode','Execute','Memory','WriteBack'];
    return stages.map((st, row) => {
      const active = s.stages[st]?.active;
      const isHaz  = s.hazard && st === 'Execute';
      return `<div class="pf-cell ${active ? 'pf-active' : 'pf-idle'} ${isHaz ? 'pf-hazard' : ''}"
        style="grid-column:${col+2};grid-row:${row+2};background:${active ? STAGE_COLORS[st]+'33' : 'transparent'};
               border-color:${active ? STAGE_COLORS[st] : 'var(--border)'};"
        title="${st} cycle=${s.cycle} ${s.mnemonic}">
        ${active ? (isHaz ? '⚡' : '●') : ''}
      </div>`;
    }).join('');
  }).join('');

  const colHeaders = snaps.slice(-8).map((s, i) =>
    `<div class="pf-col-header" style="grid-column:${i+2};grid-row:1">
      <span class="pf-cycle">${s.cycle}</span><br>
      <span class="pf-mnem">${_esc(s.mnemonic)}</span>
    </div>`).join('');

  const rowHeaders = ['Fetch','Decode','Execute','Memory','WriteBack'].map((s, i) =>
    `<div class="pf-row-header" style="grid-column:1;grid-row:${i+2};color:${STAGE_COLORS[s]}">${STAGE_ICONS[s]} ${s}</div>`
  ).join('');

  el.innerHTML = `
    <div class="coa-2col">
      <div>
        <div class="coa-section-title">Stage Utilisation</div>
        <div class="pipe-gauges">${gaugeHTML}</div>
        <div class="pipe-kpi-row" style="margin-top:12px">
          <div class="pipe-kpi"><div class="kpi-val" style="color:var(--accent)">${pl.ipc}</div><div class="kpi-lbl">IPC</div></div>
          <div class="pipe-kpi"><div class="kpi-val" style="color:var(--yellow)">${pl.cpi}</div><div class="kpi-lbl">CPI</div></div>
          <div class="pipe-kpi"><div class="kpi-val" style="color:var(--red)">${pl.stalls}</div><div class="kpi-lbl">Stalls</div></div>
          <div class="pipe-kpi"><div class="kpi-val" style="color:var(--orange)">${pl.flushes}</div><div class="kpi-lbl">Flushes</div></div>
          <div class="pipe-kpi"><div class="kpi-val" style="color:var(--green)">${pl.retired?.toLocaleString()}</div><div class="kpi-lbl">Retired</div></div>
        </div>
      </div>
      <div>
        <div class="coa-section-title">Pipeline Waterfall (last 8 instructions)</div>
        <div class="pipeline-waterfall" style="grid-template-columns: 90px repeat(${snaps.slice(-8).length}, 1fr);">
          ${rowHeaders}${colHeaders}${waterfall}
        </div>
        <div class="pipe-legend">
          <span class="pipe-leg-dot" style="background:var(--orange)">⚡</span> Hazard/Stall &nbsp;
          <span class="pipe-leg-dot" style="background:var(--accent)">●</span> Active
        </div>
      </div>
    </div>`;
}

/* ════════════════════════════════════════════════════════════════
   4. CACHE LAYOUT
════════════════════════════════════════════════════════════════ */
const CACHE_COLORS = ['#00e5ff','#69ff47','#ffb347','#c084fc'];
const CACHE_LABELS = ['L1-Instruction','L1-Data','L2-Unified','L3-Unified'];

function renderCache(cache) {
  if (!cache) return;
  const el = document.getElementById('coa-cache-body');
  if (!el) return;

  const levels = cache.levels || [];
  const dist   = cache.level_dist || [0,0,0,0];

  // Hierarchy diagram
  const hierHTML = levels.map((l, i) => {
    const color = CACHE_COLORS[i];
    const width = [90, 75, 55, 35][i];
    return `
      <div class="cache-level" style="width:${width}%;border-color:${color}">
        <div class="cache-level-name" style="color:${color}">${l.name}</div>
        <div class="cache-level-specs">${_fmt(l.size)} · ${l.ways}-way · ${l.line_size}B lines · ${l.sets} sets</div>
        <div class="cache-hit-bar">
          <div class="cache-hit-fill" style="width:${l.hit_rate}%;background:${color}"></div>
        </div>
        <div class="cache-hit-stats">
          <span style="color:${color}">${l.hit_rate}% hit</span>
          <span>${(l.hits||0).toLocaleString()} hits / ${(l.misses||0).toLocaleString()} misses</span>
        </div>
      </div>`;
  }).join('<div class="cache-arrow">▼</div>');

  // Access distribution pie-like bar
  const distHTML = dist.map((pct, i) => {
    const labels = ['L1 Hit','L2 Hit','L3 Hit','DRAM'];
    return `
      <div class="mini-bar-row">
        <span class="mini-bar-label" style="color:${CACHE_COLORS[i]}">${labels[i]}</span>
        <div class="coa-bar-track"><div class="coa-bar-fill" style="width:${pct}%;background:${CACHE_COLORS[i]}"></div></div>
        <span class="mini-bar-count">${pct}%</span>
      </div>`;
  }).join('');

  // Access log (last 40)
  const log = (cache.access_log || []).slice(-40);
  const logHTML = log.map(a =>
    `<div class="cache-access-row level-${a.level}">
      <span class="ca-addr">${_h64(a.address)}</span>
      <span class="ca-kind ${a.kind === 'instruction' ? 'ca-insn' : 'ca-data'}">${a.kind.slice(0,1).toUpperCase()}</span>
      <span class="ca-level" style="color:${CACHE_COLORS[a.level-1] || '#888'}">L${a.level}${a.level > 3 ? ' DRAM' : ''}</span>
    </div>`
  ).join('');

  el.innerHTML = `
    <div class="coa-2col">
      <div>
        <div class="coa-section-title">Cache Hierarchy</div>
        <div class="cache-hierarchy">${hierHTML}
          <div class="cache-level dram-level" style="width:20%;border-color:#636e72">
            <div class="cache-level-name" style="color:#636e72">DRAM</div>
            <div class="cache-level-specs">~60ns · ∞ capacity</div>
          </div>
        </div>
        <div class="coa-section-title" style="margin-top:14px">Hit Level Distribution</div>
        <div style="padding:4px 0">${distHTML}</div>
      </div>
      <div>
        <div class="coa-section-title">Access Log <span style="color:var(--muted);font-weight:400">(last ${log.length})</span></div>
        <div class="cache-access-log">${logHTML || '<div class="coa-empty">No accesses yet</div>'}</div>
      </div>
    </div>`;
}

/* ════════════════════════════════════════════════════════════════
   5. PROCESSING CONTROLS
════════════════════════════════════════════════════════════════ */
function renderProcessing(pr, pl) {
  if (!pr) return;
  const el = document.getElementById('coa-processing-body');
  if (!el) return;

  const faults = pr.fault_events || [];
  const segs   = pr.run_segments || [];

  // Throughput sparkline (mini bars from run segments)
  const maxTP = Math.max(...segs.map(s => s.throughput), 0.01);
  const sparkHTML = segs.slice(-30).map(s => {
    const h = Math.max(4, (s.throughput / maxTP) * 60);
    const color = s.reason === 'ok' ? 'var(--green)' :
                  s.reason === 'breakpoint' ? 'var(--red)' : 'var(--orange)';
    return `<div class="spark-bar" style="height:${h}px;background:${color}"
      title="${s.insns} insns · IPC≈${s.throughput.toFixed(2)} · ${s.reason}"></div>`;
  }).join('');

  el.innerHTML = `
    <div class="coa-2col">
      <div>
        <div class="coa-section-title">Emulation Metrics</div>
        <div class="proc-kpi-grid">
          <div class="proc-kpi-card"><div class="proc-kpi-val" style="color:var(--accent)">${(pr.total_insns||0).toLocaleString()}</div><div class="proc-kpi-lbl">Instructions Retired</div></div>
          <div class="proc-kpi-card"><div class="proc-kpi-val" style="color:var(--yellow)">${(pr.total_cycles||0).toLocaleString()}</div><div class="proc-kpi-lbl">Cycles</div></div>
          <div class="proc-kpi-card"><div class="proc-kpi-val" style="color:var(--green)">${pl?.ipc ?? '—'}</div><div class="proc-kpi-lbl">IPC</div></div>
          <div class="proc-kpi-card"><div class="proc-kpi-val" style="color:var(--orange)">${pr.stall_rate ?? 0}%</div><div class="proc-kpi-lbl">Stall Rate</div></div>
          <div class="proc-kpi-card"><div class="proc-kpi-val" style="color:var(--red)">${pr.flush_rate ?? 0}%</div><div class="proc-kpi-lbl">Flush Rate</div></div>
          <div class="proc-kpi-card"><div class="proc-kpi-val" style="color:var(--purple)">${pr.breakpoint_hits ?? 0}</div><div class="proc-kpi-lbl">BP Hits</div></div>
        </div>

        <div class="coa-section-title" style="margin-top:14px">Throughput History (IPC per run segment)</div>
        <div class="spark-container">${sparkHTML || '<div class="coa-empty">Run emulator to see throughput</div>'}</div>
        <div class="spark-legend">
          <span class="spark-bar" style="height:10px;background:var(--green);display:inline-block;width:12px"></span> Normal &nbsp;
          <span class="spark-bar" style="height:10px;background:var(--red);display:inline-block;width:12px"></span> Breakpoint &nbsp;
          <span class="spark-bar" style="height:10px;background:var(--orange);display:inline-block;width:12px"></span> Timeout
        </div>
      </div>
      <div>
        <div class="coa-section-title">Fault / Exception Events</div>
        ${faults.length ? faults.map(f => `
          <div class="fault-row">
            <span class="fault-kind kind-${f.kind}">${_esc(f.kind)}</span>
            <span class="fault-addr">${_h64(f.address)}</span>
            <span class="fault-detail">${_esc(f.detail)}</span>
          </div>`).join('') :
          '<div class="coa-ok">✓ No faults recorded</div>'}

        <div class="coa-section-title" style="margin-top:14px">Execution Controls</div>
        <div class="proc-controls">
          <button class="btn primary" onclick="coaStep(1)">↓ Step 1</button>
          <button class="btn warn"    onclick="coaStep(10)">↓ Step 10</button>
          <button class="btn warn"    onclick="coaStep(100)">↓ Step 100</button>
          <button class="btn success" onclick="coaRun()">▶ Run</button>
          <button class="btn danger"  onclick="coaStop()">■ Stop</button>
        </div>
        <div id="coa-proc-status" class="proc-status"></div>

        <div class="coa-section-title" style="margin-top:14px">Dynamic Binary Loader</div>
        <div class="proc-controls">
          <label class="btn" style="cursor:pointer">
            📂 Load (Dynamic)
            <input type="file" id="coa-dyn-upload" style="display:none" onchange="coaDynLoad(this)">
          </label>
        </div>
        <div id="coa-load-status" class="proc-status"></div>
      </div>
    </div>`;
}

/* ── COA control actions ────────────────────────────────────── */
async function coaStep(n) {
  const r = await _post('/api/emulate/step', { count: n });
  const el = document.getElementById('coa-proc-status');
  if (el && r) el.textContent = `Stepped ${n} → RIP: ${_h64(r.ip)}`;
  await coaRefresh();
}

async function coaRun() {
  const el = document.getElementById('coa-proc-status');
  if (el) el.textContent = 'Running…';
  const r = await _post('/api/emulate/start', { timeout: 2000000, count: 200000 });
  if (el && r) el.textContent = `Run complete. RIP: ${_h64(r.ip)} trace: ${r.trace_len}`;
  await coaRefresh();
}

async function coaStop() {
  await _post('/api/emulate/stop', {});
  const el = document.getElementById('coa-proc-status');
  if (el) el.textContent = 'Stopped.';
  await coaRefresh();
}

async function coaDynLoad(input) {
  const file = input.files[0];
  if (!file) return;
  const el = document.getElementById('coa-load-status');
  if (el) el.textContent = `Loading ${file.name}…`;
  const fd = new FormData();
  fd.append('file', file);
  const r = await fetch('/api/upload/dynamic', { method: 'POST', body: fd })
    .then(r => r.json()).catch(e => ({ error: e.message }));
  if (r.error) {
    if (el) el.textContent = '✗ ' + r.error;
    return;
  }
  if (el) el.textContent = `✓ ${file.name} loaded as ${r.arch} (PIE: ${r.is_pie}) · ${r.relocs_applied} relocs · ${Object.keys(r.stubs||{}).length} stubs`;
  coaInit();
  // Notify main ui.js
  if (window.S) { window.S.loaded = true; window.S.ip = r.entry_point; }
  if (window._ld) window._ld(r.entry_point);
}
