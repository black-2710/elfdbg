/* ui.js – ELFDebugger frontend */
"use strict";

// ─────────────────────────────────────────────────────
// API helper
// ─────────────────────────────────────────────────────
const API = {
  async req(method, path, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(path, opts);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  },
  get:  (p)    => API.req('GET',    p),
  post: (p, b) => API.req('POST',   p, b),
  put:  (p, b) => API.req('PUT',    p, b),
  del:  (p)    => API.req('DELETE', p),
};

// ─────────────────────────────────────────────────────
// Utilities (defined first so everything below can use them)
// ─────────────────────────────────────────────────────
function hex(n) {
  if (n === undefined || n === null) return '0x0';
  const s = (n >>> 0).toString(16);
  return '0x' + (s.length < 4 ? s.padStart(4,'0') : s);
}
function hex64(n) {
  // For 64-bit values that may exceed 32-bit safe range
  if (n === undefined || n === null) return '0x0';
  return '0x' + (n).toString(16);
}
function fmtBytes(n) {
  if (n === undefined) return '?';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  return (n/1048576).toFixed(2) + ' MB';
}
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function toast(msg, type = 'info', duration = 2800) {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), duration);
}

// ─────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────
const S = {
  loaded:   false,
  faulted:  false,
  arch:     'x86_64',
  ip:       0,
  regs:     {},
  prevRegs: {},
  breakpoints:       {},
  disasmInsns:       [],
  currentTab:        'disasm',
  currentAnalysisTab:'stats',
  polling:  null,
  autoScroll: true,
};

// ─────────────────────────────────────────────────────
// Status helpers
// ─────────────────────────────────────────────────────
function setStatus(state) {
  const dot   = document.getElementById('status-dot');
  const label = document.getElementById('status-label');
  dot.className = 'status-dot ' + state;
  label.textContent = {
    running:'Running', stopped:'Stopped', faulted:'FAULTED',
    ready:'Ready', loading:'Loading…', '':'No binary',
  }[state] ?? state;
  if (state === 'faulted') {
    dot.style.background = 'var(--red)';
    dot.style.boxShadow  = '0 0 8px var(--red)';
    ['btn-run','btn-step','btn-stepo'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = true;
    });
  } else {
    dot.style.background = '';
    dot.style.boxShadow  = '';
  }
}
function enableControls(on) {
  ['btn-run','btn-step','btn-stepo','btn-reset','btn-stop'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = !on;
  });
}
function updateIpDisplay(ip) {
  S.ip = ip;
  document.getElementById('ip-display').textContent = 'RIP: ' + hex64(ip);
}

// ─────────────────────────────────────────────────────
// Upload
// ─────────────────────────────────────────────────────
document.getElementById('file-input').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append('file', file);
  setStatus('loading');
  try {
    const r = await fetch('/api/upload', { method: 'POST', body: fd });
    const data = await r.json();
    if (data.error) throw new Error(data.error);
    S.loaded  = true;
    S.faulted = false;
    S.arch    = data.arch;
    S.ip      = data.entry_point;
    document.getElementById('binary-name').textContent = file.name;
    document.getElementById('binary-name').style.color = 'var(--accent)';
    setStatus('ready');
    const dynTag = data.is_dynamic ? ` · ${data.is_pie ? 'PIE' : 'DYN'} — GOT stubs installed` : ' · static';
    toast(`Loaded ${file.name} (${data.arch}${dynTag}, ${fmtBytes(data.file_size)})`, 'ok', 4000);
    enableControls(true);
    await Promise.all([
      loadDisasm(data.entry_point),
      refreshRegs(),
      loadSections(),
      loadSymbols(),
      loadStrings(),
    ]);
    renderBinaryInfo(data);
    startPolling();
    // Notify COA panel
    if (typeof window.onBinaryLoaded === 'function') window.onBinaryLoaded();
  } catch (err) {
    toast(err.message, 'err');
    setStatus('');
  }
});

// ─────────────────────────────────────────────────────
// Execution controls
// ─────────────────────────────────────────────────────
document.getElementById('btn-run').addEventListener('click', async () => {
  if (S.faulted) { toast('Emulator faulted — press ↺ Reset to restart', 'err'); return; }
  setStatus('running');
  try {
    const st = await API.post('/api/emulate/start',
      { begin: S.ip, timeout: 3000000, count: 500000 });
    await handleStateUpdate(st);
    if (st.plt_calls && st.plt_calls.length) {
      const syms = [...new Set(st.plt_calls.map(c => c.symbol))].join(', ');
      toast(`PLT intercepted: ${syms} → returned 0`, 'warn', 3500);
    }
  } catch (err) { toast(err.message, 'err'); }
  if (!S.faulted) setStatus('stopped');
});

document.getElementById('btn-stop').addEventListener('click', async () => {
  await API.post('/api/emulate/stop');
  setStatus('stopped');
  await refreshState();
});

document.getElementById('btn-step').addEventListener('click',  () => step(1));
document.getElementById('btn-stepo').addEventListener('click', () => step(1));

document.getElementById('btn-reset').addEventListener('click', async () => {
  try {
    await API.post('/api/emulate/reset');
    S.ip      = 0;
    S.faulted = false;
    clearTrace();
    enableControls(true);
    setStatus('ready');
    toast('Emulator reset', 'info');
    await refreshState();
  } catch (err) { toast(err.message, 'err'); }
});

async function step(count = 1) {
  if (S.faulted) {
    toast('Emulator faulted — press ↺ Reset to restart', 'err');
    return;
  }
  try {
    const st = await API.post('/api/emulate/step', { count });
    await handleStateUpdate(st);
    if (st.plt_calls && st.plt_calls.length) {
      const syms = [...new Set(st.plt_calls.map(c => c.symbol))].join(', ');
      toast(`PLT intercepted: ${syms} → returned 0`, 'warn', 3500);
    }
  } catch (err) { toast(err.message, 'err'); }
}

async function handleStateUpdate(st) {
  S.prevRegs = { ...S.regs };
  S.regs     = st.registers || S.regs;
  const ip   = st.ip || 0;
  S.faulted  = !!st.faulted;
  updateIpDisplay(ip);
  renderRegs(S.regs, S.prevRegs);

  if (S.faulted) {
    setStatus('faulted');
    // Don't try to disassemble null/garbage address
    if (ip < 0x10000) {
      const tbody = document.getElementById('disasm-tbody');
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="6">
          <div class="empty-state" style="height:100px;gap:8px">
            <div style="font-size:28px">💥</div>
            <div style="color:var(--red);font-weight:700;font-size:13px">Emulator faulted at ${hex64(ip)}</div>
            <div style="color:var(--muted);font-size:11px">${escHtml(st.error || 'Unmapped memory fetch — RIP landed at 0x0 (likely a missing PLT/GOT stub)')}</div>
            <div style="color:var(--muted);font-size:11px">Press <strong style="color:var(--accent)">↺ Reset</strong> to restart from entry point</div>
          </div>
        </td></tr>`;
      }
    } else {
      highlightCurrentIp(ip);
    }
    toast(st.error || `Faulted at ${hex64(ip)} — press ↺ Reset`, 'err', 6000);
  } else {
    highlightCurrentIp(ip);
  }
  await refreshTrace();
  await refreshStack();
}

async function refreshState() {
  try {
    const st = await API.get('/api/state');
    await handleStateUpdate(st);
  } catch (_) {}
}

// Keyboard shortcuts
window.addEventListener('keydown', e => {
  if (!S.loaded) return;
  if (['INPUT','TEXTAREA','SELECT'].includes(e.target.tagName)) return;
  if (e.key === 'F7' || e.key === 's') { e.preventDefault(); step(1); }
  if (e.key === 'F8' || e.key === 'n') { e.preventDefault(); step(1); }
  if (e.key === 'F9' || e.key === 'r') { e.preventDefault(); document.getElementById('btn-run').click(); }
  if (e.key === 'F2')     { e.preventDefault(); toggleBpAtIp(); }
  if (e.key === 'Escape') document.getElementById('ctx-menu').classList.remove('visible');
});

// ─────────────────────────────────────────────────────
// Polling
// ─────────────────────────────────────────────────────
function startPolling() {
  if (S.polling) return;
  S.polling = setInterval(async () => {
    if (!S.loaded) return;
    try {
      const st = await API.get('/api/state');
      if (st.ip !== S.ip) await handleStateUpdate(st);
    } catch (_) {}
  }, 1500);
}

// ─────────────────────────────────────────────────────
// Registers
// ─────────────────────────────────────────────────────
async function refreshRegs() {
  try {
    const regs = await API.get('/api/registers');
    S.prevRegs = { ...S.regs };
    S.regs = regs;
    renderRegs(regs, S.prevRegs);
  } catch (_) {}
}

function renderRegs(regs, prev) {
  const grid = document.getElementById('reg-grid');
  grid.innerHTML = '';
  const order = S.arch === 'x86_64'
    ? ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
       'r8','r9','r10','r11','r12','r13','r14','r15',
       'rip','rflags','cs','ss','ds','es']
    : Object.keys(regs).slice(0, 22);

  for (const name of order) {
    if (!(name in regs)) continue;
    const val     = regs[name];
    const changed = prev[name] !== undefined && prev[name] !== val;
    const row     = document.createElement('div');
    row.className = 'reg-row' + (changed ? ' changed' : '');
    row.dataset.reg = name;
    row.title = `Click to edit ${name}`;

    const rn = document.createElement('span');
    rn.className   = 'reg-name';
    rn.textContent = name;

    const rv = document.createElement('span');
    rv.className   = 'reg-val'
      + (val === 0 ? ' zero' : '')
      + (name === 'rip' || name === 'pc' ? ' rip' : '');
    rv.textContent = hex64(val);

    row.appendChild(rn);
    row.appendChild(rv);
    row.addEventListener('click', () => startRegEdit(row, name, val));
    grid.appendChild(row);
  }
}

function startRegEdit(row, name, curVal) {
  const rv    = row.querySelector('.reg-val');
  const input = document.createElement('input');
  input.className = 'reg-edit';
  input.value     = hex64(curVal);
  rv.replaceWith(input);
  input.focus(); input.select();

  const finish = async () => {
    const raw = input.value.trim();
    let v;
    try { v = parseInt(raw.startsWith('0x') ? raw : '0x' + raw, 16); }
    catch { v = curVal; }
    try {
      await API.post('/api/registers', { name, value: hex64(v) });
      toast(`${name} = ${hex64(v)}`, 'ok', 1500);
    } catch (err) { toast(err.message, 'err'); }
    await refreshRegs();
  };
  input.addEventListener('blur',   finish);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter')  input.blur();
    if (e.key === 'Escape') { input.replaceWith(rv); }
  });
}

// ─────────────────────────────────────────────────────
// Disassembly
// ─────────────────────────────────────────────────────
async function loadDisasm(addr, size = 512) {
  if (!addr && addr !== 0) return;
  try {
    const insns = await API.get(`/api/disasm?addr=${hex64(addr)}&size=${size}&max=300`);
    S.disasmInsns = insns;
    renderDisasm(insns, S.ip);
  } catch (err) {
    toast('Disasm error: ' + err.message, 'err');
  }
}

function renderDisasm(insns, currentIp) {
  const tbody = document.getElementById('disasm-tbody');
  tbody.innerHTML = '';
  const bpAddrs = new Set(Object.keys(S.breakpoints).map(Number));

  for (const ins of insns) {
    const isBp      = bpAddrs.has(ins.address);
    const isCurrent = ins.address === currentIp;

    const tr = document.createElement('tr');
    tr.className = 'disasm-row'
      + (isCurrent ? ' current-ip' : '')
      + (isBp      ? ' breakpoint' : '');
    tr.dataset.addr = ins.address;

    // BP gutter cell
    const tdBp = document.createElement('td');
    tdBp.className   = 'd-bp';
    tdBp.textContent = isBp ? '●' : '';
    tdBp.addEventListener('click', ev => {
      ev.stopPropagation();
      toggleBreakpointAt(ins.address);
    });

    const tdAddr  = mkTd('d-addr',  hex64(ins.address));
    const tdBytes = mkTd('d-bytes', ins.bytes);
    const tdMnem  = mkTd('d-mnem',  ins.mnemonic);
    const tdOps   = mkTd('d-ops',   ins.op_str || '');
    const tdSym   = mkTd('d-sym',   ins.symbol  || '');

    tr.append(tdBp, tdAddr, tdBytes, tdMnem, tdOps, tdSym);
    tr.addEventListener('dblclick',     () => toggleBreakpointAt(ins.address));
    tr.addEventListener('contextmenu',  ev => showCtxMenu(ev, ins.address));
    tbody.appendChild(tr);
  }
}

function mkTd(cls, text) {
  const td = document.createElement('td');
  td.className   = cls;
  td.textContent = text;
  return td;
}

function highlightCurrentIp(ip) {
  document.querySelectorAll('.disasm-row.current-ip')
    .forEach(r => r.classList.remove('current-ip'));

  const row = document.querySelector(`.disasm-row[data-addr="${ip}"]`);
  if (row) {
    row.classList.add('current-ip');
    if (S.autoScroll) row.scrollIntoView({ block: 'center', behavior: 'smooth' });
  } else {
    // IP scrolled off-screen — reload disasm centred on new IP
    loadDisasm(ip);
  }
  updateIpDisplay(ip);
}

// Goto bar
document.getElementById('goto-btn').addEventListener('click', async () => {
  const raw = document.getElementById('goto-input').value.trim();
  if (!raw) return;
  const addr = parseInt(raw, 16);
  if (isNaN(addr)) { toast('Invalid address', 'warn'); return; }
  await loadDisasm(addr);
});
document.getElementById('goto-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('goto-btn').click();
});

// ─────────────────────────────────────────────────────
// Breakpoints
// ─────────────────────────────────────────────────────
async function loadBreakpoints() {
  try {
    const bps = await API.get('/api/breakpoints');
    S.breakpoints = {};
    bps.forEach(bp => { S.breakpoints[bp.address] = bp; });
    renderBreakpoints(bps);
    return bps;
  } catch (_) { return []; }
}

function renderBreakpoints(bps) {
  const el = document.getElementById('bp-list');
  if (!bps.length) {
    el.innerHTML = '<div class="empty-state"><div class="icon">⬡</div>No breakpoints set</div>';
    return;
  }
  el.innerHTML = '';
  for (const bp of bps) {
    const div = document.createElement('div');
    div.className = 'bp-item' + (bp.enabled ? '' : ' disabled');
    div.innerHTML = `
      <span class="bp-dot bp-${bp.type}"></span>
      <span class="bp-addr">${hex64(bp.address)}</span>
      <span class="bp-sym">${escHtml(bp.symbol || '')}</span>
      ${bp.condition ? `<span class="bp-cond">[${escHtml(bp.condition)}]</span>` : ''}
      <span class="bp-hits">${bp.hit_count > 0 ? '×'+bp.hit_count : ''}</span>
      <button class="bp-toggle" data-addr="${bp.address}" title="Toggle">⊘</button>
      <button class="bp-del"    data-addr="${bp.address}" title="Remove">×</button>`;
    el.appendChild(div);
  }
  el.querySelectorAll('.bp-del').forEach(btn =>
    btn.addEventListener('click', () => removeBreakpoint(parseInt(btn.dataset.addr))));
  el.querySelectorAll('.bp-toggle').forEach(btn =>
    btn.addEventListener('click', () => toggleBreakpoint(parseInt(btn.dataset.addr))));
}

async function toggleBreakpointAt(addr) {
  if (S.breakpoints[addr]) {
    await removeBreakpoint(addr);
  } else {
    await addBreakpoint(addr, null, 'exec');
  }
}

async function addBreakpoint(addr, condition, type = 'exec') {
  try {
    await API.post('/api/breakpoints', { addr: hex64(addr), condition, type });
    toast(`BP @ ${hex64(addr)}`, 'ok', 1500);
    await loadBreakpoints();
    renderDisasm(S.disasmInsns, S.ip);  // re-render to update BP dots
  } catch (err) { toast(err.message, 'err'); }
}

async function removeBreakpoint(addr) {
  try {
    await API.del(`/api/breakpoints/${hex64(addr)}`);
    await loadBreakpoints();
    renderDisasm(S.disasmInsns, S.ip);
  } catch (err) { toast(err.message, 'err'); }
}

async function toggleBreakpoint(addr) {
  try {
    await API.put(`/api/breakpoints/${hex64(addr)}`);
    await loadBreakpoints();
    renderDisasm(S.disasmInsns, S.ip);
  } catch (err) { toast(err.message, 'err'); }
}

function toggleBpAtIp() { toggleBreakpointAt(S.ip); }

// BP add form
document.getElementById('bp-add-btn').addEventListener('click', async () => {
  const addrEl = document.getElementById('bp-addr-input');
  const condEl = document.getElementById('bp-cond-input');
  const typeEl = document.getElementById('bp-type-select');
  const raw    = addrEl.value.trim();
  if (!raw) { toast('Enter an address', 'warn'); return; }
  const addr   = parseInt(raw, 16);
  if (isNaN(addr)) { toast('Invalid address', 'warn'); return; }
  const cond   = condEl.value.trim() || null;
  await addBreakpoint(addr, cond, typeEl.value);
  addrEl.value = ''; condEl.value = '';
});

// ─────────────────────────────────────────────────────
// Memory / Hex viewer
// ─────────────────────────────────────────────────────
async function loadMemory(addr, size = 256) {
  try {
    const data = await API.get(`/api/memory?addr=${hex64(addr)}&size=${size}`);
    renderHex(data.rows || []);
  } catch (err) { toast('Memory error: ' + err.message, 'err'); }
}

function renderHex(rows) {
  const el = document.getElementById('hex-container');
  el.innerHTML = '';
  for (const row of rows) {
    const div = document.createElement('div');
    div.className = 'hex-row';

    const addrEl = document.createElement('span');
    addrEl.className   = 'hex-addr';
    addrEl.textContent = hex64(row.addr);
    div.appendChild(addrEl);

    const bytesEl = document.createElement('span');
    bytesEl.className = 'hex-bytes';
    for (let i = 0; i < row.hex.length; i += 2) {
      const b  = row.hex.slice(i, i+2);
      const bv = parseInt(b, 16);
      const sp = document.createElement('span');
      sp.className   = 'hex-byte' + (bv === 0 ? ' zero' : (bv < 32 || bv > 126 ? ' nonprint' : ''));
      sp.textContent = b;
      sp.title       = `${hex64(row.addr + i/2)}: ${bv}`;
      bytesEl.appendChild(sp);
    }
    div.appendChild(bytesEl);

    const asciiEl = document.createElement('span');
    asciiEl.className = 'hex-ascii';
    asciiEl.innerHTML = (row.ascii || '').split('').map(c =>
      c === '.' ? '<span>.</span>' : `<span class="p">${escHtml(c)}</span>`
    ).join('');
    div.appendChild(asciiEl);
    el.appendChild(div);
  }
}

document.getElementById('mem-go-btn').addEventListener('click', async () => {
  const a = document.getElementById('mem-addr-input').value.trim();
  const s = parseInt(document.getElementById('mem-size-input').value) || 256;
  if (!a) { toast('Enter an address', 'warn'); return; }
  const addr = parseInt(a, 16);
  if (isNaN(addr)) { toast('Invalid address', 'warn'); return; }
  await loadMemory(addr, s);
});
document.getElementById('mem-addr-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('mem-go-btn').click();
});

// ─────────────────────────────────────────────────────
// Stack
// ─────────────────────────────────────────────────────
async function refreshStack() {
  try {
    const frames = await API.get('/api/stack?depth=24');
    renderStack(frames);
  } catch (_) {}
}

function renderStack(frames) {
  const el = document.getElementById('stack-container');
  el.innerHTML = '';
  frames.forEach((f, i) => {
    const div = document.createElement('div');
    div.className = 'stack-frame' + (i === 0 ? ' sp-ptr' : '');
    div.innerHTML = `
      <span class="sf-offset">${i === 0 ? 'RSP' : '+' + (i*8)}</span>
      <span class="sf-addr">${hex64(f.addr)}</span>
      <span class="sf-val">${hex64(f.value)}</span>
      <span class="sf-sym">${escHtml(f.symbol || '')}</span>`;
    div.addEventListener('click', () => loadDisasm(f.value));
    el.appendChild(div);
  });
}

// ─────────────────────────────────────────────────────
// Trace
// ─────────────────────────────────────────────────────
async function refreshTrace() {
  try {
    const data = await API.get('/api/trace?start=0&limit=200');
    renderTrace(data.entries || [], data.total || 0);
  } catch (_) {}
}

function clearTrace() {
  document.getElementById('trace-container').innerHTML = '';
  document.getElementById('trace-total').textContent   = '0';
}

function renderTrace(entries, total) {
  document.getElementById('trace-total').textContent = total;
  const el = document.getElementById('trace-container');
  el.innerHTML = '';
  for (const e of entries) {
    const div = document.createElement('div');
    div.className = 'trace-entry' + (e.syscall ? ' syscall-row' : '');
    const scBadge  = e.syscall ? `<span class="trace-badge sc">${escHtml(e.syscall.name)}</span>` : '';
    const memBadge = (e.mem_writes && e.mem_writes.length) ? '<span class="trace-badge mem">W</span>' : '';
    div.innerHTML = `
      <span class="t-addr">${hex64(e.address)}</span>
      <span class="t-mnem">${escHtml(e.mnemonic)}</span>
      <span class="t-ops">${escHtml(e.op_str || '')}${scBadge}${memBadge}</span>
      <span class="t-sym">${escHtml(e.symbol || '')}</span>`;
    div.addEventListener('click', () => loadDisasm(e.address));
    el.appendChild(div);
  }
  if (S.autoScroll && el.lastChild) {
    el.lastChild.scrollIntoView({ block: 'end' });
  }
}

// ─────────────────────────────────────────────────────
// Sections visualizer
// ─────────────────────────────────────────────────────
async function loadSections() {
  try {
    const secs = await API.get('/api/sections');
    renderSections(secs);
  } catch (_) {}
}

const SEC_COLORS = {
  '.text':'.sec-text','.data':'.sec-data','.rodata':'.sec-rodata',
  '.bss':'.sec-bss','.plt':'.sec-plt','.got':'.sec-got',
};
function sectionColor(name) {
  for (const [k, v] of Object.entries(SEC_COLORS)) {
    if (name.includes(k)) return v.slice(1);
  }
  return 'sec-other';
}

function renderSections(secs) {
  const el     = document.getElementById('sections-list');
  el.innerHTML = '';
  const maxSz  = Math.max(...secs.map(s => s.size), 1);
  for (const sec of secs) {
    if (!sec.name) continue;
    const pct = Math.max((sec.size / maxSz) * 100, 0.5).toFixed(1);
    const div = document.createElement('div');
    div.className = 'section-bar-row';
    div.innerHTML = `
      <span class="section-bar-label" title="${sec.name}">${sec.name}</span>
      <div class="section-bar-track">
        <div class="section-bar-fill ${sectionColor(sec.name)}" style="width:${pct}%">${pct > 15 ? fmtBytes(sec.size) : ''}</div>
      </div>
      <span class="section-bar-size">${fmtBytes(sec.size)}</span>`;
    if (sec.addr) div.addEventListener('click', () => loadDisasm(sec.addr));
    el.appendChild(div);
  }
}

// ─────────────────────────────────────────────────────
// Symbols
// ─────────────────────────────────────────────────────
async function loadSymbols() {
  try {
    const data = await API.get('/api/symbols');
    const all  = [...(data.exports || []), ...(data.symbols || []).slice(0, 200)];
    renderSymbols(all);
  } catch (_) {}
}

function renderSymbols(syms) {
  const el = document.getElementById('symbols-tbody');
  if (!el) return;
  el.innerHTML = '';
  for (const s of syms) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="sym-addr">${hex64(s.address)}</td>
      <td class="sym-name">${escHtml(s.name)}</td>
      <td class="sym-type">${escHtml(s.type || 'SYM')}</td>
      <td class="sym-size">${s.size ? fmtBytes(s.size) : ''}</td>`;
    tr.addEventListener('click', () => { loadDisasm(s.address); switchTab('disasm'); });
    el.appendChild(tr);
  }
}

// ─────────────────────────────────────────────────────
// Strings
// ─────────────────────────────────────────────────────
async function loadStrings() {
  try {
    const strs = await API.get('/api/strings');
    renderStrings(strs);
  } catch (_) {}
}

function renderStrings(strs) {
  const el     = document.getElementById('strings-list');
  el.innerHTML = '';
  for (const s of strs.slice(0, 500)) {
    const div = document.createElement('div');
    div.className = 'string-row';
    div.innerHTML = `
      <span class="s-addr">${hex64(s.address)}</span>
      <span class="s-sec">${escHtml(s.section || '')}</span>
      <span class="s-val">${escHtml(s.value)}</span>`;
    div.addEventListener('click', () => loadMemory(s.address, 64));
    el.appendChild(div);
  }
}

// ─────────────────────────────────────────────────────
// Analysis panel
// ─────────────────────────────────────────────────────
async function loadAnalysis() {
  const tab = S.currentAnalysisTab;
  if (tab === 'stats')    await loadTraceStats();
  else if (tab === 'freq')     await loadInsnFreq();
  else if (tab === 'syscalls') await loadSyscalls();
  else if (tab === 'heatmap')  await loadHeatmap();
  else if (tab === 'rstrings') await loadRuntimeStrings();
}

async function loadTraceStats() {
  try {
    const d  = await API.get('/api/trace/stats');
    const el = document.getElementById('stats-panel');
    el.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;padding:8px">
        <div class="stat-card"><div class="stat-label">Instructions</div>
          <div class="stat-value">${(d.total_instructions||0).toLocaleString()}</div></div>
        <div class="stat-card"><div class="stat-label">Unique mnemonics</div>
          <div class="stat-value">${d.unique_mnemonics||0}</div></div>
        <div class="stat-card"><div class="stat-label">Mem reads</div>
          <div class="stat-value">${(d.memory_reads||0).toLocaleString()}</div></div>
        <div class="stat-card"><div class="stat-label">Mem writes</div>
          <div class="stat-value">${(d.memory_writes||0).toLocaleString()}</div></div>
        <div class="stat-card" style="grid-column:span 2"><div class="stat-label">Syscalls</div>
          <div class="stat-value">${d.syscall_count||0}</div></div>
      </div>`;
  } catch (_) {}
}

async function loadInsnFreq() {
  try {
    const freq = await API.get('/api/insn_freq');
    const el   = document.getElementById('stats-panel');
    const max  = freq[0]?.count || 1;
    el.innerHTML = '<div style="padding:8px">' + freq.map(f => `
      <div class="mini-bar-row">
        <span class="mini-bar-label">${escHtml(f.mnemonic)}</span>
        <div class="mini-bar-track"><div class="mini-bar-fill" style="width:${(f.count/max*100).toFixed(1)}%"></div></div>
        <span class="mini-bar-count">${f.count}</span>
      </div>`).join('') + '</div>';
  } catch (_) {}
}

async function loadSyscalls() {
  try {
    const scs = await API.get('/api/syscalls');
    const el  = document.getElementById('stats-panel');
    if (!scs.length) { el.innerHTML = '<div class="empty-state"><div class="icon">☎</div>No syscalls recorded</div>'; return; }
    el.innerHTML = scs.map(sc => `
      <div class="syscall-row-item">
        <span class="sc-num">${sc.number}</span>
        <span class="sc-name">${escHtml(sc.name)}</span>
        <span class="sc-addr">${hex64(sc.address)}</span>
        <span class="sc-args">${(sc.args||[]).map(a=>hex64(a)).join(', ')}</span>
      </div>`).join('');
  } catch (_) {}
}

async function loadHeatmap() {
  try {
    const hm  = await API.get('/api/heatmap?top=200');
    const el  = document.getElementById('stats-panel');
    if (!hm.length) { el.innerHTML = '<div class="empty-state"><div class="icon">🔥</div>No memory access data</div>'; return; }
    const maxH = Math.max(...hm.map(h => h.reads + h.writes), 1);
    el.innerHTML = '<div style="padding:8px;display:flex;flex-wrap:wrap;gap:2px">' +
      hm.map(h => {
        const intensity = Math.floor(((h.reads + h.writes) / maxH) * 255);
        return `<div class="heatmap-cell"
          style="background:rgb(${Math.floor(intensity*.8)},${Math.floor(intensity*.25)},60)"
          title="${hex64(h.addr)}: R=${h.reads} W=${h.writes}"></div>`;
      }).join('') + '</div>';
  } catch (_) {}
}

async function loadRuntimeStrings() {
  try {
    const strs = await API.get('/api/runtime_strings');
    const el   = document.getElementById('stats-panel');
    if (!strs.length) { el.innerHTML = '<div class="empty-state"><div class="icon">💬</div>No runtime strings</div>'; return; }
    el.innerHTML = strs.map(s => `
      <div class="string-row">
        <span class="s-addr">${hex64(s.addr)}</span>
        <span class="s-val">${escHtml(s.value)}</span>
      </div>`).join('');
  } catch (_) {}
}

// ─────────────────────────────────────────────────────
// Binary info panel
// ─────────────────────────────────────────────────────
function renderBinaryInfo(info) {
  const el = document.getElementById('info-panel');
  if (!el) return;
  el.innerHTML = `
    <div style="padding:10px">
      <div class="stat-card">
        <div class="stat-label">Architecture</div>
        <div class="stat-value" style="font-size:14px">${info.arch}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Entry Point</div>
        <div class="stat-value" style="font-size:14px;color:var(--yellow)">${hex64(info.entry_point)}</div>
      </div>
      <table style="width:100%;font-size:11px;margin-top:8px;border-collapse:collapse">
        ${[
          ['Type',     info.type],
          ['Class',    (info.class||64)+'-bit'],
          ['Encoding', info.encoding],
          ['File size',fmtBytes(info.file_size)],
          ['Sections', info.num_sections],
          ['Segments', info.num_segments],
          ['Symbols',  info.num_symbols],
          ['Imports',  info.num_imports],
          ['Exports',  info.num_exports],
          ['Strings',  info.num_strings],
        ].map(([k,v]) => `
          <tr>
            <td style="color:var(--muted);padding:3px 0;width:90px">${k}</td>
            <td style="font-family:var(--code-font);color:var(--text)">${v}</td>
          </tr>`).join('')}
      </table>
    </div>`;
}

// ─────────────────────────────────────────────────────
// Context menu
// ─────────────────────────────────────────────────────
const ctxMenu = document.getElementById('ctx-menu');
let ctxAddr = 0;

function showCtxMenu(e, addr) {
  e.preventDefault();
  ctxAddr = addr;
  ctxMenu.style.left = e.clientX + 'px';
  ctxMenu.style.top  = e.clientY + 'px';
  ctxMenu.classList.add('visible');
}
document.addEventListener('click', () => ctxMenu.classList.remove('visible'));

document.getElementById('ctx-bp').addEventListener('click',
  () => toggleBreakpointAt(ctxAddr));

document.getElementById('ctx-goto').addEventListener('click',
  () => loadDisasm(ctxAddr));

document.getElementById('ctx-set-ip').addEventListener('click', async () => {
  try {
    await API.post('/api/registers', { name: 'rip', value: hex64(ctxAddr) });
    S.ip = ctxAddr;
    highlightCurrentIp(ctxAddr);
    toast(`RIP → ${hex64(ctxAddr)}`, 'ok', 1500);
  } catch (err) { toast(err.message, 'err'); }
});

document.getElementById('ctx-hexview').addEventListener('click', () => {
  loadMemory(ctxAddr, 128);
  switchTab('memory');
});

// ─────────────────────────────────────────────────────
// Tab switching
// ─────────────────────────────────────────────────────
function switchTab(id) {
  document.querySelectorAll('.tab-btn[data-tab]')
    .forEach(b => b.classList.toggle('active', b.dataset.tab === id));
  document.querySelectorAll('.tab-panel')
    .forEach(p => p.classList.toggle('active', p.id === 'tab-' + id));
  S.currentTab = id;
  if (id === 'breakpoints') loadBreakpoints();
  if (id === 'memory' && S.ip) loadMemory(S.ip, 256);
  if (id === 'analysis')   loadAnalysis();
  if (id === 'strings')    loadStrings();
  if (id === 'trace')      refreshTrace();
}

document.querySelectorAll('.tab-btn[data-tab]').forEach(btn =>
  btn.addEventListener('click', () => switchTab(btn.dataset.tab)));

// Analysis sub-tabs
document.querySelectorAll('.analysis-tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.analysis-tab-btn')
      .forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    S.currentAnalysisTab = btn.dataset.atab;
    loadAnalysis();
  });
});

// ─────────────────────────────────────────────────────
// Misc button listeners
// ─────────────────────────────────────────────────────
document.getElementById('btn-clear-trace').addEventListener('click', async () => {
  try {
    await API.post('/api/trace/reset');
    clearTrace();
    toast('Trace cleared', 'info', 1500);
  } catch (err) { toast(err.message, 'err'); }
});

document.getElementById('btn-refresh-regs').addEventListener('click',  refreshRegs);
document.getElementById('btn-refresh-stack').addEventListener('click', refreshStack);
document.getElementById('btn-refresh-mem').addEventListener('click', () => {
  const a = document.getElementById('mem-addr-input').value.trim();
  const s = parseInt(document.getElementById('mem-size-input').value) || 256;
  const addr = a ? parseInt(a, 16) : S.ip;
  if (!isNaN(addr)) loadMemory(addr, s);
});

// ─────────────────────────────────────────────────────
// Expose to global scope for index.html inline handlers
// Capture local references BEFORE assigning to window.*
// to prevent window.X = () => X() infinite self-recursion.
// ─────────────────────────────────────────────────────
const _ld = loadDisasm;
const _lm = loadMemory;
const _h  = hex64;
const _fb = fmtBytes;
const _eh = escHtml;
const _st = switchTab;

window._ld = _ld;
window._lm = _lm;
window._h  = _h;
window._fb = _fb;
window._eh = _eh;
window._st = _st;
window.S   = S;
// Keep backward-compat names that DON'T recurse
window.loadDisasm = addr    => _ld(addr);
window.loadMemory = (a, s)  => _lm(a, s);
window.hex        = _h;
window.fmtBytes   = _fb;
window.escHtml    = _eh;
window.switchTab  = _st;
