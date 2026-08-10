
function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>'"]/g, tag => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[tag]));
}

'use strict';
/* QuantumShield — Security Dashboard Logic */

const ATTACK_TYPES = ['MITM Attack','SQL Injection','Brute Force','Replay Attack','SIM Swap','Phishing','DDoS','XSS Injection','Social Engineering','Zero-Day Probe'];
const LAYERS = ['QRNG Layer','PQC Encryption','HSM Vault','RASP Engine','Behavioral AI','Zero-Trust','Rate Limiter'];
const SOURCES = ['185.220.101.x (TOR)','45.33.32.x (US)','192.168.x.x (Internal)','103.21.x.x (IN)','91.108.x.x (RU)','195.54.x.x (EU)'];
const ACTORS = ['Alice (Dev)','Bob (Finance)','Carol (Support)','Dave (Admin)','System','API Gateway','Scheduler'];
const ACTIONS = ['READ transaction','LOGIN success','DATA export attempt','KEY access denied','CONFIG change','REPORT generated','LOGOUT','API call'];

let blocked = 2847, tokens = 48291;

window.addEventListener('DOMContentLoaded', () => {
  initCanvas();
  updateClock();
  setInterval(updateClock, 1000);
  buildThreatTable();
  buildEmployeeTable();
  buildAuditTable();
  buildAccessLog();
  buildAnomalies();
  buildQRNGStream();
  drawAttackChart();
  drawVectorPie();
  drawBehaviorChart();
  drawQChart();
  startLiveUpdates();
});

// ── NAVIGATION ─────────────────────────────────────────
const TITLES = {
  overview:'Security Overview', threats:'Threat Monitor',
  behavior:'Behavioral AI Engine', zerotrust:'Zero-Trust Access Control',
  audit:'Quantum Audit Log', quantum:'Quantum Security Layer'
};

function showTab(id, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i => i.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  if (el) el.classList.add('active');
  document.getElementById('tab-title').textContent = TITLES[id] || id;
}

// ── CLOCK ──────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('tb-clock');
  if (el) el.textContent = new Date().toLocaleTimeString('en-IN', { hour12: false });
}

// ── THREAT TABLE ───────────────────────────────────────
function buildThreatTable(n = 15) {
  const tbody = document.getElementById('threat-table');
  if (!tbody) return;
  tbody.innerHTML = Array.from({ length: n }, (_, i) => {
    const minsAgo = i * 3 + Math.floor(Math.random() * 3);
    const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
    const src = SOURCES[Math.floor(Math.random() * SOURCES.length)];
    const layer = LAYERS[Math.floor(Math.random() * LAYERS.length)];
    const ms = (Math.random() * 80 + 10).toFixed(0);
    return `<tr>
      <td style="color:var(--dim);font-size:0.72rem">${minsAgo}m ago</td>
      <td><strong>${type}</strong></td>
      <td class="mono">${src}</td>
      <td style="color:var(--cyan);font-size:0.75rem">${layer}</td>
      <td><span class="status-pill blocked">BLOCKED</span></td>
      <td style="color:var(--green);font-family:'Space Mono',monospace;font-size:0.72rem">${ms}ms</td>
    </tr>`;
  }).join('');
}

// ── EMPLOYEE TABLE ─────────────────────────────────────
function buildEmployeeTable() {
  const tbody = document.getElementById('employee-table');
  if (!tbody) return;
  const employees = [
    { name:'Arjun Mehta', role:'Senior Developer', access:'High', last:'2 min ago', score:12, status:'safe' },
    { name:'Priya Singh', role:'Finance Manager', access:'Medium', last:'15 min ago', score:8, status:'safe' },
    { name:'Ravi Kumar', role:'Support Agent', access:'Low', last:'1 hour ago', score:3, status:'safe' },
    { name:'Deepa Nair', role:'DevOps Engineer', access:'High', last:'5 min ago', score:24, status:'warn' },
    { name:'Suresh Patel', role:'Security Officer', access:'Admin', last:'just now', score:2, status:'safe' },
    { name:'Anita Joshi', role:'Data Analyst', access:'Medium', last:'3 hours ago', score:6, status:'safe' },
  ];
  tbody.innerHTML = employees.map(e => {
    const scoreColor = e.score > 20 ? 'var(--pink)' : e.score > 10 ? 'var(--yellow)' : 'var(--green)';
    return `<tr>
      <td><strong>${escapeHTML(e.name)}</strong></td>
      <td style="color:var(--dim);font-size:0.75rem">${escapeHTML(e.role)}</td>
      <td><span class="status-pill ${e.access === 'Admin' ? 'risk' : 'safe'}">${e.access}</span></td>
      <td style="color:var(--dim);font-size:0.75rem">${e.last}</td>
      <td><span style="font-family:'Space Mono',monospace;color:${scoreColor};font-weight:700">${e.score}</span>/100</td>
      <td><span class="status-pill ${e.status}">${e.status === 'safe' ? 'NORMAL' : 'WATCH'}</span></td>
    </tr>`;
  }).join('');
}

// ── AUDIT TABLE ────────────────────────────────────────
function buildAuditTable(n = 12) {
  const tbody = document.getElementById('audit-table');
  if (!tbody) return;
  tbody.innerHTML = Array.from({ length: n }, (_, i) => {
    const block = 12847 - i;
    const actor = ACTORS[Math.floor(Math.random() * ACTORS.length)];
    const action = ACTIONS[Math.floor(Math.random() * ACTIONS.length)];
    const hash = Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    const min = i * 4;
    return `<tr>
      <td class="mono" style="color:var(--cyan)">#${block}</td>
      <td style="color:var(--dim);font-size:0.72rem">${min}m ago</td>
      <td><strong>${actor}</strong></td>
      <td style="font-size:0.75rem">${action}</td>
      <td class="mono" style="color:var(--dim);font-size:0.65rem">${hash}...</td>
      <td><span class="q-badge">✅ Verified</span></td>
    </tr>`;
  }).join('');
}

// ── ACCESS LOG ─────────────────────────────────────────
function buildAccessLog(n = 10) {
  const log = document.getElementById('access-log');
  if (!log) return;
  const entries = Array.from({ length: n }, (_, i) => {
    const actor = ACTORS[Math.floor(Math.random() * ACTORS.length)];
    const action = ACTIONS[Math.floor(Math.random() * ACTIONS.length)];
    const allowed = Math.random() > 0.25;
    const color = allowed ? 'var(--green)' : 'var(--pink)';
    return `<div class="access-item">
      <div class="ai-dot" style="background:${color};box-shadow:0 0 4px ${color}"></div>
      <div style="flex:1;font-size:0.75rem">
        <strong>${actor}</strong> → ${action}
      </div>
      <div style="font-size:0.65rem;color:${color};font-weight:700">${allowed ? 'ALLOWED' : 'DENIED'}</div>
      <div style="font-size:0.65rem;color:var(--dim)">${i * 3 + 1}m ago</div>
    </div>`;
  }).join('');
  log.innerHTML = entries;
}

// ── ANOMALIES ─────────────────────────────────────────
function buildAnomalies() {
  const list = document.getElementById('anomaly-list');
  if (!list) return;
  const items = [
    { title:'Unusual login time', sub:'Deepa Nair logged in at 02:34 AM from new location', score:'Score: 78/100' },
    { title:'Bulk data access', sub:'Finance system accessed 2,400 records in 3 minutes (normal: 50)', score:'Score: 65/100' },
    { title:'New device detected', sub:'Ravi Kumar used unregistered device — MFA triggered', score:'Score: 45/100' },
    { title:'Off-hours API call', sub:'Automated script ran outside scheduled window', score:'Score: 32/100' },
  ];
  list.innerHTML = items.map(a => `
    <div class="anomaly-item">
      <div class="ai-title">⚠ ${a.title}</div>
      <div class="ai-sub">${a.sub}</div>
      <div class="ai-score">${a.score}</div>
    </div>
  `).join('');
}

// ── QRNG STREAM ───────────────────────────────────────
function buildQRNGStream() {
  const el = document.getElementById('qrng-stream');
  if (!el) return;
  const bits = Array.from({ length: 80 }, () => Math.random() > 0.5 ? '1' : '0');
  el.innerHTML = bits.map(b => `<div class="qb ${b === '1' ? 'one' : 'zero'}">${b}</div>`).join('');

  setInterval(() => {
    const bits = Array.from({ length: 80 }, () => Math.random() > 0.5 ? '1' : '0');
    el.innerHTML = bits.map(b => `<div class="qb ${b === '1' ? 'one' : 'zero'}">${b}</div>`).join('');
  }, 2000);
}

// ── CHARTS ────────────────────────────────────────────
function drawAttackChart() {
  const canvas = document.getElementById('attack-chart');
  if (!canvas) return;
  canvas.width = canvas.clientWidth || 600;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = 180;
  const pad = { t: 10, r: 10, b: 30, l: 45 };
  const cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;

  const hrs = 24;
  const data = Array.from({ length: hrs }, () => Math.floor(Math.random() * 180 + 40));
  const max = Math.max(...data);

  ctx.clearRect(0, 0, W, H);
  const sx = i => pad.l + (i / (hrs - 1)) * cw;
  const sy = v => pad.t + (1 - v / max) * ch;

  // Grid
  ctx.strokeStyle = 'rgba(255,255,255,0.05)'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (ch / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
    ctx.fillStyle = 'rgba(128,144,176,0.7)'; ctx.font = '9px Space Mono'; ctx.textAlign = 'right';
    ctx.fillText(Math.round(max - (max / 4) * i), pad.l - 5, y + 3);
  }

  // Area
  const g = ctx.createLinearGradient(0, pad.t, 0, pad.t + ch);
  g.addColorStop(0, 'rgba(0,255,170,0.25)'); g.addColorStop(1, 'rgba(0,255,170,0)');
  ctx.beginPath();
  data.forEach((v, i) => i === 0 ? ctx.moveTo(sx(i), sy(v)) : ctx.lineTo(sx(i), sy(v)));
  ctx.lineTo(sx(hrs - 1), pad.t + ch); ctx.lineTo(sx(0), pad.t + ch); ctx.closePath();
  ctx.fillStyle = g; ctx.fill();

  // Line
  ctx.beginPath();
  data.forEach((v, i) => i === 0 ? ctx.moveTo(sx(i), sy(v)) : ctx.lineTo(sx(i), sy(v)));
  ctx.strokeStyle = '#00ffaa'; ctx.lineWidth = 2; ctx.stroke();

  // X labels
  ctx.fillStyle = 'rgba(128,144,176,0.6)'; ctx.font = '9px Outfit'; ctx.textAlign = 'center';
  [0, 6, 12, 18, 23].forEach(i => ctx.fillText(`${i}:00`, sx(i), pad.t + ch + 14));
}

function drawVectorPie() {
  const canvas = document.getElementById('vector-pie');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const cx = 100, cy = 100, r = 80;
  const slices = [
    { label: 'Network MITM', pct: 31, color: '#ff6b6b' },
    { label: 'Injection Attacks', pct: 24, color: '#7b2fff' },
    { label: 'Brute Force', pct: 18, color: '#ffcc00' },
    { label: 'Social Engineering', pct: 14, color: '#ff9f40' },
    { label: 'Replay Attacks', pct: 8, color: '#00f5ff' },
    { label: 'Zero-Day', pct: 5, color: '#00ffaa' },
  ];

  let start = -Math.PI / 2;
  slices.forEach(s => {
    const angle = (s.pct / 100) * Math.PI * 2;
    ctx.beginPath(); ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, start + angle);
    ctx.closePath(); ctx.fillStyle = s.color; ctx.fill();
    start += angle;
  });

  ctx.beginPath(); ctx.arc(cx, cy, 48, 0, Math.PI * 2);
  ctx.fillStyle = '#0a0f28'; ctx.fill();
  ctx.fillStyle = '#e0eaff'; ctx.font = 'bold 11px Outfit'; ctx.textAlign = 'center';
  ctx.fillText('Attacks', cx, cy - 4); ctx.fillText('by Type', cx, cy + 10);

  const legend = document.getElementById('vector-legend');
  if (legend) {
    legend.innerHTML = slices.map(s => `
      <div class="vl-item">
        <div class="vl-dot" style="background:${s.color}"></div>
        <span style="color:var(--dim)">${s.label}</span>
        <span class="vl-pct" style="color:${s.color}">${s.pct}%</span>
      </div>
    `).join('');
  }
}

function drawBehaviorChart() {
  const canvas = document.getElementById('behavior-chart');
  if (!canvas) return;
  canvas.width = canvas.clientWidth || 500;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = 220;
  canvas.height = H;
  const pad = { t: 20, r: 20, b: 40, l: 50 };
  const cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
  const hrs = 24;

  const normal = Array.from({ length: hrs }, () => 40 + Math.random() * 20);
  const current = Array.from({ length: hrs }, (_, i) => {
    const base = normal[i];
    return i === 2 ? base * 3.2 : i === 14 ? base * 2.1 : base + (Math.random() - 0.4) * 10;
  });

  ctx.clearRect(0, 0, W, H);
  const sx = i => pad.l + (i / (hrs - 1)) * cw;
  const max = Math.max(...current, ...normal) * 1.1;
  const sy = v => pad.t + (1 - v / max) * ch;

  // Grid
  ctx.strokeStyle = 'rgba(255,255,255,0.05)'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (ch / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
  }

  // Normal baseline band
  ctx.globalAlpha = 0.15; ctx.fillStyle = '#00f5ff';
  ctx.beginPath();
  normal.forEach((v, i) => i === 0 ? ctx.moveTo(sx(i), sy(v + 15)) : ctx.lineTo(sx(i), sy(v + 15)));
  for (let i = hrs - 1; i >= 0; i--) ctx.lineTo(sx(i), sy(normal[i] - 15));
  ctx.fill(); ctx.globalAlpha = 1;

  // Normal line
  ctx.beginPath();
  normal.forEach((v, i) => i === 0 ? ctx.moveTo(sx(i), sy(v)) : ctx.lineTo(sx(i), sy(v)));
  ctx.strokeStyle = 'rgba(0,245,255,0.5)'; ctx.lineWidth = 1.5; ctx.setLineDash([4, 4]); ctx.stroke(); ctx.setLineDash([]);

  // Current line
  ctx.beginPath();
  current.forEach((v, i) => i === 0 ? ctx.moveTo(sx(i), sy(v)) : ctx.lineTo(sx(i), sy(v)));
  ctx.strokeStyle = '#00ffaa'; ctx.lineWidth = 2; ctx.stroke();

  // Anomaly markers
  [2, 14].forEach(i => {
    ctx.beginPath(); ctx.arc(sx(i), sy(current[i]), 5, 0, Math.PI * 2);
    ctx.fillStyle = '#ff6b6b'; ctx.shadowBlur = 8; ctx.shadowColor = '#ff6b6b'; ctx.fill(); ctx.shadowBlur = 0;
  });

  // Labels
  ctx.fillStyle = 'rgba(128,144,176,0.7)'; ctx.font = '9px Outfit'; ctx.textAlign = 'center';
  [0, 6, 12, 18, 23].forEach(i => ctx.fillText(`${i}:00`, sx(i), pad.t + ch + 16));
  ctx.fillStyle = '#00ffaa'; ctx.textAlign = 'left';
  ctx.fillText('— Current', pad.l + 8, pad.t + 14);
  ctx.fillStyle = 'rgba(0,245,255,0.6)'; ctx.font = '9px Outfit';
  ctx.fillText('- - Normal Baseline', pad.l + 8, pad.t + 26);
}

function drawQChart() {
  const canvas = document.getElementById('q-chart');
  if (!canvas) return;
  canvas.width = canvas.clientWidth || 400;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = 120;
  canvas.height = H;

  const data = Array.from({ length: 30 }, () => 4.5 + Math.random() * 3.5);
  const max = 8;
  const sx = i => (i / (data.length - 1)) * W;
  const sy = v => H - 10 - (v / max) * (H - 16);

  const g = ctx.createLinearGradient(0, 0, 0, H);
  g.addColorStop(0, 'rgba(0,245,255,0.3)'); g.addColorStop(1, 'rgba(0,245,255,0)');
  ctx.beginPath();
  data.forEach((v, i) => i === 0 ? ctx.moveTo(sx(i), sy(v)) : ctx.lineTo(sx(i), sy(v)));
  ctx.lineTo(sx(data.length - 1), H); ctx.lineTo(0, H); ctx.closePath();
  ctx.fillStyle = g; ctx.fill();
  ctx.beginPath();
  data.forEach((v, i) => i === 0 ? ctx.moveTo(sx(i), sy(v)) : ctx.lineTo(sx(i), sy(v)));
  ctx.strokeStyle = '#00f5ff'; ctx.lineWidth = 2; ctx.stroke();

  ctx.fillStyle = 'rgba(128,144,176,0.6)'; ctx.font = '9px Outfit'; ctx.textAlign = 'center';
  ctx.fillText('Encryption operations / second (last 30s)', W / 2, H - 1);
}

// ── LIVE UPDATES ─────────────────────────────────────
function startLiveUpdates() {
  setInterval(() => {
    blocked += Math.floor(Math.random() * 5);
    tokens += Math.floor(Math.random() * 20);
    const bEl = document.getElementById('m-blocked');
    const tEl = document.getElementById('m-tokens');
    const tsEl = document.getElementById('ts-total');
    if (bEl) bEl.textContent = blocked.toLocaleString();
    if (tEl) tEl.textContent = tokens.toLocaleString();
    if (tsEl) tsEl.textContent = blocked.toLocaleString();

    // Add random threat row
    const tbody = document.getElementById('threat-table');
    if (tbody && tbody.children.length > 0) {
      const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
      const src = SOURCES[Math.floor(Math.random() * SOURCES.length)];
      const layer = LAYERS[Math.floor(Math.random() * LAYERS.length)];
      const ms = (Math.random() * 80 + 10).toFixed(0);
      const row = document.createElement('tr');
      row.innerHTML = `
        <td style="color:var(--dim);font-size:0.72rem">just now</td>
        <td><strong>${type}</strong></td>
        <td class="mono">${src}</td>
        <td style="color:var(--cyan);font-size:0.75rem">${layer}</td>
        <td><span class="status-pill blocked">BLOCKED</span></td>
        <td style="color:var(--green);font-family:'Space Mono',monospace;font-size:0.72rem">${ms}ms</td>
      `;
      row.style.animation = 'fade-in 0.4s ease';
      tbody.insertBefore(row, tbody.firstChild);
      if (tbody.children.length > 20) tbody.removeChild(tbody.lastChild);
    }
  }, 8000);
}

// ── CANVAS ───────────────────────────────────────────
function initCanvas() {
  const canvas = document.getElementById('sc');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let ps = [];
  const R = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
  R(); window.addEventListener('resize', R);
  class P {
    constructor() { this.reset(); }
    reset() {
      this.x = Math.random() * canvas.width; this.y = Math.random() * canvas.height;
      this.vx = (Math.random() - .5) * .3; this.vy = (Math.random() - .5) * .3;
      this.r = Math.random() * 1.5 + .5;
      this.h = Math.random() > .5 ? 190 : 270;
      this.a = Math.random() * .3 + .1;
    }
    update() {
      this.x += this.vx; this.y += this.vy;
      if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
      if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
    }
    draw() {
      ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${this.h},100%,70%,${this.a})`; ctx.fill();
    }
  }
  for (let i = 0; i < 50; i++) ps.push(new P());
  (function f() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ps.forEach(p => { p.update(); p.draw(); });
    requestAnimationFrame(f);
  })();
}
