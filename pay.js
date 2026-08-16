'use strict';
/* =====================================================
   QuantumPay — Payment App Logic
   Phase 2: Connected to real FastAPI backend
   Real ANU QRNG (proxied) + PQC + JWT Auth
   ===================================================== */

const API = ''; // ← Backend URL
const AUTH_TOKEN = () => localStorage.getItem('qp_token') || '';
const AUTH_HDR   = () => ({ 'Authorization': `Bearer ${AUTH_TOKEN()}`, 'Content-Type': 'application/json' });


// ── STATE ─────────────────────────────────────────────
let tokenCount = 0, txCount = 0, fraudCount = 0;
let currentPayUPI = '', currentPayAmount = 0;
let lastQRNGToken = '';

const TRANSACTIONS = [
  { name:'Priya Sharma', note:'Lunch 🍱', amount:'-₹340', time:'2m ago', q:true, init:'PS', color:'#7b2fff' },
  { name:'Razorpay', note:'Monthly subscription', amount:'-₹999', time:'1h ago', q:true, init:'R', color:'#00f5ff' },
  { name:'Raj Patel', note:'Movie tickets 🎬', amount:'+₹850', time:'3h ago', q:true, init:'RP', color:'#00ffaa' },
  { name:'Swiggy', note:'Dinner delivery', amount:'-₹487', time:'Yesterday', q:true, init:'SW', color:'#ff6b6b' },
  { name:'Mom', note:'Grocery reimbursement', amount:'+₹2,100', time:'2d ago', q:true, init:'M', color:'#ffcc00' },
];

const THREATS = [
  { type:'blocked', icon:'🛡', msg:'MITM attack blocked — PQC encryption held', time:'1m ago' },
  { type:'blocked', icon:'✅', msg:'QRNG token verified — replay attempt rejected', time:'5m ago' },
  { type:'warn',    icon:'⚠', msg:'Unusual login attempt from new IP — MFA triggered', time:'12m ago' },
  { type:'blocked', icon:'🛡', msg:'SQL injection probe blocked by RASP engine', time:'23m ago' },
  { type:'blocked', icon:'✅', msg:'Zero-trust: unauthorised data access denied', time:'31m ago' },
];

// ── INIT ──────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  initBgCanvas();
  buildQRMini();
  buildQRLarge();
  buildTransactions();
  buildThreatLog();
  updateStats();
  fetchLiveQRNG();
  startLiveThreatFeed();
  checkBackendStatus();
  await loadUserProfile();
  await loadRealTransactions();
});

// ── BACKEND STATUS ───────────────────────────────────
async function checkBackendStatus() {
  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      showToast('✅', 'Backend Connected', 'Real quantum backend online — PQC active', true);
      document.querySelectorAll('.ssb-item').forEach(el => el.classList.add('active'));
    }
  } catch {
    showToast('⚠', 'Backend Offline', 'Running in demo mode. Start backend/start.bat', false);
  }
}

// ── LOAD USER PROFILE ────────────────────────────────
async function loadUserProfile() {
  const name    = localStorage.getItem('qp_name')   || 'Manoj Kumar';
  const upi     = localStorage.getItem('qp_upi')    || 'manoj@quantumpay';
  const balance = localStorage.getItem('qp_balance') || '1,24,830';

  const nameEl = document.querySelector('.user-name');
  const upiEl  = document.querySelector('.user-id');
  const balEl  = document.querySelector('.wc-balance');
  const idEl   = document.querySelector('.wc-id');

  if (nameEl) nameEl.textContent = name;
  if (upiEl)  upiEl.textContent  = upi;
  if (idEl)   idEl.textContent   = upi;

  try {
    const r = await fetch(`${API}/api/user/profile`, {credentials: 'include'});
    if (r.ok) {
      const data = await r.json();
      localStorage.setItem('qp_balance', data.balance);
      if (nameEl) nameEl.textContent = data.name;
      if (upiEl)  upiEl.textContent  = data.upi_id;
      if (idEl)   idEl.textContent   = data.upi_id;
      if (balEl)  balEl.innerHTML    = `₹${Number(data.balance).toLocaleString('en-IN')}<span>.00</span>`;
    }
  } catch { /* use cached values */ }
}

// ── LOAD REAL TRANSACTIONS ───────────────────────────
async function loadRealTransactions() {
  try {
    const r = await fetch(`${API}/api/transactions`, { headers: AUTH_HDR(), signal: AbortSignal.timeout(3000) });
    if (!r.ok) return;
    const txs = await r.json();
    if (txs.length === 0) return;
    const list = document.getElementById('tx-list');
    if (!list) return;
    const upi = localStorage.getItem('qp_upi') || '';
    list.innerHTML = txs.slice(0, 8).map(t => {
      const isOut   = t.direction === 'OUT';
      const other   = isOut ? t.receiver : t.sender;
      const init    = other.substring(0, 2).toUpperCase();
      const amt     = isOut ? `-₹${t.amount}` : `+₹${t.amount}`;
      const color   = isOut ? '#ff6b6b' : '#00ffaa';
      const dt      = new Date(t.created_at + 'Z').toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
      return `<div class="tx-item">
        <div class="tx-avatar" style="background:linear-gradient(135deg,${color}44,${color}88)"><span style="color:${color}">${init}</span></div>
        <div style="flex:1"><div class="tx-name">${other}</div><div class="tx-note">${t.note || 'Payment'}</div><div class="tx-q">⚛ Quantum secured · ${t.quantum_token ? t.quantum_token.substring(0,14)+'...' : 'Token used'}</div></div>
        <div class="tx-amount"><div class="tx-val ${isOut ? 'neg' : 'pos'}">${amt}</div><div class="tx-time">${dt}</div></div>
      </div>`;
    }).join('');
  } catch { /* keep demo transactions */ }
}


// ── SCREEN NAVIGATION ─────────────────────────────────
function goScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const screen = document.getElementById(id);
  if (screen) screen.classList.add('active');
}

function setActive(btn) {
  document.querySelectorAll('.bn-item').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

// ── PAYMENT FLOW ──────────────────────────────────────
function setAmt(v) {
  document.getElementById('pay-amount').value = v;
}

// ── MPIN KEYPAD & SOUNDBOX ──────────────────────────────
let currentMpin = '';

function initiatePayment() {
  const upi = document.getElementById('pay-upi').value.trim();
  const amt = parseFloat(document.getElementById('pay-amount').value);
  if (!upi) { showToast('⚠', 'Missing UPI ID', 'Please enter a recipient UPI ID', false); return; }
  if (!amt || amt <= 0) { showToast('⚠', 'Invalid Amount', 'Please enter a valid amount', false); return; }
  currentPayUPI = upi;
  currentPayAmount = amt;

  // Open MPIN Modal (PhonePe Style)
  openMpinModal(upi, amt);
}

function openMpinModal(upi, amt) {
  currentMpin = '';
  updateMpinDots();
  const infoEl = document.getElementById('mpin-recipient-info');
  if (infoEl) infoEl.textContent = `Sending ₹${Number(amt).toLocaleString('en-IN')} to ${upi}`;
  const modal = document.getElementById('mpin-modal');
  if (modal) modal.classList.add('active');
}

function closeMpinModal() {
  const modal = document.getElementById('mpin-modal');
  if (modal) modal.classList.remove('active');
  currentMpin = '';
}

function pressPin(digit) {
  if (currentMpin.length < 4) {
    currentMpin += digit;
    updateMpinDots();
    if (currentMpin.length === 4) {
      setTimeout(submitPin, 250);
    }
  }
}

function clearPin() {
  if (currentMpin.length > 0) {
    currentMpin = currentMpin.slice(0, -1);
    updateMpinDots();
  }
}

function updateMpinDots() {
  for (let i = 1; i <= 4; i++) {
    const dot = document.getElementById(`dot-${i}`);
    if (dot) {
      if (i <= currentMpin.length) dot.classList.add('filled');
      else dot.classList.remove('filled');
    }
  }
}

function submitPin() {
  if (currentMpin.length < 4) {
    showToast('⚠', 'Enter PIN', 'Please enter your 4-digit UPI PIN', false);
    return;
  }
  closeMpinModal();
  goScreen('screen-processing');
  runQuantumPaymentFlow(currentPayUPI, currentPayAmount);
}

function playQuantumPaymentSound(amt) {
  try {
    // 1. Play PhonePe-style Success Audio Chime via Web Audio API
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (AudioCtx) {
      const ctx = new AudioCtx();
      const now = ctx.currentTime;
      
      const osc1 = ctx.createOscillator();
      const osc2 = ctx.createOscillator();
      const gain = ctx.createGain();

      osc1.type = 'sine';
      osc2.type = 'sine';

      // Harmony chime (C5 to G5 chord)
      osc1.frequency.setValueAtTime(523.25, now); // C5
      osc1.frequency.exponentialRampToValueAtTime(1046.50, now + 0.15); // C6

      osc2.frequency.setValueAtTime(659.25, now); // E5
      osc2.frequency.exponentialRampToValueAtTime(1318.51, now + 0.15); // E6

      gain.gain.setValueAtTime(0.3, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.8);

      osc1.connect(gain);
      osc2.connect(gain);
      gain.connect(ctx.destination);

      osc1.start(now);
      osc2.start(now);
      osc1.stop(now + 0.8);
      osc2.stop(now + 0.8);
    }

    // 2. SoundBox Text-to-Speech Voice Announcement
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      const msg = new SpeechSynthesisUtterance(`Payment of ${amt} rupees received on QuantumPay`);
      msg.rate = 1.0;
      msg.pitch = 1.1;
      msg.lang = 'en-IN';
      window.speechSynthesis.speak(msg);
    }
  } catch (e) {
    console.log('Audio alert error:', e);
  }
}

function demoScan() {
  document.getElementById('pay-upi').value = 'merchant@quantumpay';
  document.getElementById('pay-amount').value = '500';
  showToast('📷', 'QR Scanned', 'Merchant QR scanned successfully', true);
  goScreen('screen-pay');
  setTimeout(() => initiatePayment(), 400);
}

function showSuccess(amt, upi, result) {
  const token   = typeof result === 'string' ? result : result.quantum_token;
  const txId    = typeof result === 'object' ? result.tx_id : 'QP-' + Date.now().toString(36).toUpperCase();
  const sigAlgo = typeof result === 'object' ? result.pqc_signature?.algorithm || 'CRYSTALS-Dilithium-3' : 'CRYSTALS-Dilithium-3';
  const ms      = typeof result === 'object' ? result.processing_ms || 31 : 31;
  const auditHash = typeof result === 'object' ? result.audit_block_hash || '—' : '—';

  document.getElementById('success-amount').textContent = `₹${Number(amt).toLocaleString('en-IN')}`;
  document.getElementById('success-to').textContent = `To: ${upi}`;
  document.getElementById('sp-txid').textContent = txId;
  document.getElementById('sp-token').textContent = token ? token.substring(0, 24) + '...' : '—';

  const sigEl = document.getElementById('sp-sig');
  const msEl  = document.getElementById('sp-ms');
  const blkEl = document.getElementById('sp-block');
  if (sigEl) sigEl.textContent = sigAlgo + ' ✓';
  if (msEl)  msEl.textContent  = `Cleared in ${ms.toFixed ? ms.toFixed(1) : ms}ms ✓`;
  if (blkEl) blkEl.textContent = auditHash ? auditHash.substring(0, 16) + '...' : '—';

  goScreen('screen-success');
  playQuantumPaymentSound(amt);
  showToast('✅', 'Payment Sent!', `₹${amt} → ${upi} via quantum channel`, true);
}



// ── QRNG ─────────────────────────────────────────────
async function fetchQRNGToken() {
  // Try real backend proxy first (no CORS issue)
  try {
    const r = await fetch(`${API}/api/qrng?count=16`, { signal: AbortSignal.timeout(5000) });
    if (r.ok) {
      const data = await r.json();
      return data.hex || data.data.map(n => n.toString(16).padStart(2,'0')).join('');
    }
  } catch {}
  // Direct ANU call (may fail due to CORS)
  try {
    const resp = await fetch(
      'https://qrng.anu.edu.au/API/jsonI.php?length=16&type=uint8',
      { signal: AbortSignal.timeout(5000) }
    );
    const data = await resp.json();
    if (data.success) return data.data.map(n => n.toString(16).padStart(2, '0')).join('');
  } catch {}
  throw new Error('QRNG unavailable');
}

async function getQRNGTokenFallback(upi, amt) {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  const hex = Array.from(arr).map(n => n.toString(16).padStart(2,'0')).join('');
  return `QP-${hex.substring(0,8).toUpperCase()}-${hex.substring(8,16).toUpperCase()}-DEMO`;
}

function hashStr(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h) ^ s.charCodeAt(i);
  return Math.abs(h).toString(16).padStart(64,'0');
}


async function fetchLiveQRNG() {
  const el = document.getElementById('live-token');
  if (el) el.textContent = '⚛ Fetching from quantum source...';
  try {
    const token = await fetchQRNGToken();
    displayQRNGResult(token, true);
  } catch(e) {
    const token = generateFallbackToken();
    displayQRNGResult(token, false);
  }
}

function displayQRNGResult(token, isReal) {
  const el = document.getElementById('live-token');
  const src = document.querySelector('.qrng-source');
  if (el) el.textContent = token.toUpperCase();
  if (src) src.textContent = isReal
    ? '✅ Source: ANU Quantum Lab, Australia (real photon measurement)'
    : '⚡ Source: Fallback CSPRNG (ANU API unreachable from browser)';
  drawQRNGBits(token);
}

function drawQRNGBits(token) {
  const container = document.getElementById('qrng-bits');
  if (!container) return;
  const bits = token.split('').map(c => parseInt(c, 16).toString(2).padStart(4, '0')).join('').split('');
  container.innerHTML = bits.slice(0, 64).map(b => `
    <div class="qbit ${b === '1' ? 'one' : 'zero'}">${b}</div>
  `).join('');
}

function generateFallbackToken() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(n => n.toString(16).padStart(2, '0')).join('');
}

function buildQuantumToken(qrng, upi, amt) {
  const ts = Date.now().toString(36);
  const upiHash = [...upi].reduce((a, c) => a + c.charCodeAt(0), 0).toString(16);
  const amtHex = Math.floor(amt).toString(16).padStart(4, '0');
  return `QP-${qrng.substring(0, 8).toUpperCase()}-${ts.toUpperCase()}-${upiHash.toUpperCase()}-${amtHex.toUpperCase()}`;
}

function updateLiveToken(token) {
  const el = document.getElementById('live-token');
  if (el) el.textContent = token;
  drawQRNGBits(token.replace(/[^0-9a-f]/gi, ''));
}

// ── QR CODE GENERATOR ────────────────────────────────
function buildQRMini() {
  const el = document.getElementById('qr-mini');
  if (!el) return;
  el.innerHTML = Array.from({ length: 25 }, () =>
    `<div style="background:${Math.random() > 0.5 ? '#000' : '#fff'};border-radius:1px"></div>`
  ).join('');
}

function buildQRLarge() {
  const el = document.getElementById('qr-large');
  if (!el) return;
  el.innerHTML = Array.from({ length: 100 }, (_, i) => {
    const edge = i < 10 || i >= 90 || i % 10 === 0 || i % 10 === 9;
    const corner = (i < 3 && (i % 10 < 3)) || (i < 3 && i % 10 > 6);
    return `<div style="background:${Math.random() > 0.45 || edge ? '#000' : '#fff'};border-radius:1px"></div>`;
  }).join('');
}

// ── TRANSACTIONS ─────────────────────────────────────
function buildTransactions() {
  const list = document.getElementById('tx-list');
  if (!list) return;
  list.innerHTML = TRANSACTIONS.map(t => `
    <div class="tx-item" onclick="showToast('⚛','Quantum Verified','Transaction secured with PQC + QRNG',true)">
      <div class="tx-avatar" style="background:linear-gradient(135deg,${t.color}44,${t.color}88)">
        <span style="color:${t.color}">${t.init}</span>
      </div>
      <div style="flex:1">
        <div class="tx-name">${t.name}</div>
        <div class="tx-note">${t.note}</div>
        ${t.q ? '<div class="tx-q">⚛ Quantum secured</div>' : ''}
      </div>
      <div class="tx-amount">
        <div class="tx-val ${t.amount.startsWith('+') ? 'pos' : 'neg'}">${t.amount}</div>
        <div class="tx-time">${t.time}</div>
      </div>
    </div>
  `).join('');
}

// ── THREAT LOG ────────────────────────────────────────
function buildThreatLog() {
  const log = document.getElementById('threat-log');
  if (!log) return;
  log.innerHTML = THREATS.map(t => `
    <div class="threat-item ${t.type}">
      <span class="ti-icon">${t.icon}</span>
      <span class="ti-msg">${t.msg}</span>
      <span class="ti-time">${t.time}</span>
    </div>
  `).join('');
}

function startLiveThreatFeed() {
  const newThreats = [
    { type:'blocked', icon:'🛡', msg:'Brute force attack on API — rate limiter activated' },
    { type:'blocked', icon:'✅', msg:'Deepfake voice call detected — employee alerted' },
    { type:'warn',    icon:'⚠', msg:'Anomalous access pattern detected for user' },
    { type:'blocked', icon:'🛡', msg:'XSS injection attempt blocked by RASP' },
    { type:'blocked', icon:'✅', msg:'Quantum token replay rejected — token already used' },
  ];
  let i = 0;
  setInterval(() => {
    const log = document.getElementById('threat-log');
    if (!log) return;
    const t = newThreats[i % newThreats.length];
    const item = document.createElement('div');
    item.className = `threat-item ${t.type}`;
    item.innerHTML = `
      <span class="ti-icon">${t.icon}</span>
      <span class="ti-msg">${t.msg}</span>
      <span class="ti-time">just now</span>
    `;
    log.insertBefore(item, log.firstChild);
    if (log.children.length > 8) log.removeChild(log.lastChild);
    if (t.type === 'blocked') { fraudCount++; updateStats(); }
    i++;
  }, 12000);
}

// ── STATS ─────────────────────────────────────────────
function updateStats() {
  const s = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  s('stat-tokens', tokenCount.toLocaleString());
  s('stat-txs', txCount.toLocaleString());
  s('stat-fraud', fraudCount.toLocaleString());
}

// ── DEMO SCAN ─────────────────────────────────────────
function demoScan() {
  document.getElementById('pay-upi').value = 'merchant@quantumpay';
  goScreen('screen-pay');
  showToast('📷', 'QR Scanned!', 'merchant@quantumpay detected', true);
}

// ── CIRCUIT ANIMATION ─────────────────────────────────
function animateCircuit() {
  const canvas = document.getElementById('circuit-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let frame = 0;

  const lines = [
    { y: 25 }, { y: 55 }, { y: 85 }, { y: 110 }
  ];
  const gates = [
    { x: 50, line: 0, label: 'H' },
    { x: 100, line: 1, label: 'X' },
    { x: 150, line: 2, label: 'H' },
    { x: 200, line: 0, label: 'Z' },
    { x: 200, line: 2, label: 'Y' },
  ];

  function draw() {
    ctx.clearRect(0, 0, 260, 120);
    ctx.strokeStyle = 'rgba(0,245,255,0.2)';
    ctx.lineWidth = 1;

    // qubit lines
    lines.forEach(l => {
      ctx.beginPath();
      ctx.moveTo(10, l.y); ctx.lineTo(250, l.y);
      ctx.stroke();
      ctx.fillStyle = 'rgba(0,245,255,0.6)';
      ctx.font = '9px Space Mono';
      ctx.fillText('|0⟩', 1, l.y + 3);
    });

    // gates
    gates.forEach((g, i) => {
      const alpha = Math.min(1, (frame - i * 8) / 12);
      if (alpha <= 0) return;
      ctx.globalAlpha = alpha;
      ctx.fillStyle = g.label === 'H' ? 'rgba(0,245,255,0.3)' : 'rgba(123,47,255,0.3)';
      ctx.strokeStyle = g.label === 'H' ? '#00f5ff' : '#7b2fff';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.roundRect(g.x - 10, lines[g.line].y - 10, 20, 20, 3);
      ctx.fill(); ctx.stroke();
      ctx.fillStyle = g.label === 'H' ? '#00f5ff' : '#7b2fff';
      ctx.font = 'bold 10px Space Mono';
      ctx.textAlign = 'center';
      ctx.fillText(g.label, g.x, lines[g.line].y + 4);
      ctx.globalAlpha = 1;
    });

    // travelling signal
    const sigX = (frame * 2.5) % 260;
    ctx.beginPath();
    ctx.arc(sigX, lines[frame % 4].y, 3, 0, Math.PI * 2);
    ctx.fillStyle = '#00f5ff';
    ctx.shadowBlur = 8; ctx.shadowColor = '#00f5ff';
    ctx.fill(); ctx.shadowBlur = 0;

    frame++;
    if (frame < 120) requestAnimationFrame(draw);
  }
  draw();
}

// ── BACKGROUND CANVAS ─────────────────────────────────
function initBgCanvas() {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let particles = [];

  const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
  resize(); window.addEventListener('resize', resize);

  class P {
    constructor() { this.reset(); }
    reset() {
      this.x = Math.random() * canvas.width; this.y = Math.random() * canvas.height;
      this.vx = (Math.random() - .5) * .4; this.vy = (Math.random() - .5) * .4;
      this.r = Math.random() * 1.5 + .4;
      this.hue = Math.random() > .5 ? 190 : 270;
      this.alpha = Math.random() * .35 + .1;
    }
    update() {
      this.x += this.vx; this.y += this.vy;
      if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
      if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
    }
    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${this.hue},100%,70%,${this.alpha})`;
      ctx.fill();
    }
  }

  for (let i = 0; i < 60; i++) particles.push(new P());

  (function frame() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach(p => { p.update(); p.draw(); });
    requestAnimationFrame(frame);
  })();
}

// ── TOAST ─────────────────────────────────────────────
function showToast(icon, title, msg, isGood) {
  const box = document.getElementById('toast-box');
  if (!box) return;
  const t = document.createElement('div');
  t.className = 'toast';
  if (isGood) t.style.borderColor = 'rgba(0,255,170,0.4)';
  t.innerHTML = `<span class="ti">${icon}</span><div class="tb"><div class="tt">${title}</div><div class="tm">${msg}</div></div>`;
  box.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 400); }, 4000);
}

// ── UTILS ─────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
