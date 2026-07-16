(function(){
"use strict";

/* ===========================================================
   Helpers
   =========================================================== */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

let toastTimer = null;
function toast(msg, ms = 2200){
  const el = $("#toast");
  el.textContent = msg;
  el.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("is-visible"), ms);
}

function vibrate(pattern){
  if (getSetting("haptic", true) && "vibrate" in navigator) {
    try { navigator.vibrate(pattern); } catch(e){ /* no-op */ }
  }
}

function getSetting(key, fallback){
  try {
    const v = localStorage.getItem("qrshield_" + key);
    if (v === null) return fallback;
    return JSON.parse(v);
  } catch(e){ return fallback; }
}
function setSetting(key, value){
  try { localStorage.setItem("qrshield_" + key, JSON.stringify(value)); }
  catch(e){ /* storage unavailable (e.g. Safari Private Browsing) — setting just won't persist */ }
}

function escapeHtml(str){
  return String(str).replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
  }[c]));
}

function truncate(str, n){
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}

/* ===========================================================
   Navigation between views
   =========================================================== */
function showView(name){
  $$("[data-view]").forEach(v => v.hidden = (v.id !== "view-" + name));
  $$(".nav-btn").forEach(b => b.classList.toggle("is-active", b.dataset.nav === name));
  if (name === "settings") renderHistory();
  if (name !== "scan") stopScanning();
}

$("#navScan").addEventListener("click", () => showView("scan"));
$("#navGenerate").addEventListener("click", () => showView("generate"));
$("#navSettings").addEventListener("click", () => showView("settings"));

/* ===========================================================
   Theme (auto / light / dark)
   =========================================================== */
function applyTheme(theme){
  document.documentElement.dataset.theme = theme;
  $$(".theme-btn").forEach(b => b.classList.toggle("is-active", b.dataset.themeChoice === theme));
}
applyTheme(getSetting("theme", "auto"));

$$(".theme-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const choice = btn.dataset.themeChoice;
    setSetting("theme", choice);
    applyTheme(choice);
  });
});

/* ===========================================================
   Risk knowledge base
   =========================================================== */
const SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly",
  "rebrand.ly","tiny.cc","shorte.st","rb.gy","shorturl.at","soo.gd","s.id",
  "v.gd","lnkd.in","tr.im","clck.ru","qr.ae","bl.ink","po.st","adf.ly"
]);

// Services whose specific purpose is to capture a visitor's IP address and
// approximate location and report it back to whoever created the link —
// distinct from (and worse than) an ordinary link shortener that merely
// hides a destination. Any match here is treated as an immediate danger.
const IP_LOGGERS = new Set([
  "iplogger.org","iplogger.com","iplogger.ru","iplogger.co","iplogger.info",
  "grabify.link","2no.co","yip.su","iplis.ru","blasze.com","blasze.tk",
  "whatstheirip.com","ezstat.ru","stopmodreposts.org","ipgrabber.ru",
  "trackurl.link","spylink.net","copy-paste.link","shorturl.tips"
]);

const SUSPICIOUS_TLDS = new Set([
  "tk","ml","ga","cf","gq","xyz","top","work","click","link","loan","win",
  "review","country","kim","gdn","men","party","science","date","faith",
  "icu","cam","cyou","buzz","rest","sbs","quest","monster"
]);

const BRANDS = [
  "paypal.com","apple.com","google.com","microsoft.com","amazon.com",
  "facebook.com","instagram.com","netflix.com","chase.com","bankofamerica.com",
  "wellsfargo.com","dropbox.com","whatsapp.com","linkedin.com","twitter.com",
  "x.com","coinbase.com","binance.com","outlook.com","icloud.com","office.com",
  "adobe.com","ebay.com","americanexpress.com","usbank.com","citibank.com",
  "yahoo.com","steamcommunity.com","docusign.com"
];

const SENSITIVE_KEYWORDS = [
  "login","verify","secure","account","update","confirm","password","wallet",
  "support","signin","billing","suspended","unlock","recover","security-alert"
];

const TWO_LEVEL_TLDS = new Set([
  "co.uk","com.au","co.jp","co.in","com.br","co.nz","co.za","com.mx","co.id","com.sg"
]);

function levenshtein(a, b){
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  const d = Array.from({length: m+1}, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j=0;j<=n;j++) d[0][j] = j;
  for (let i=1;i<=m;i++){
    for (let j=1;j<=n;j++){
      d[i][j] = a[i-1]===b[j-1] ? d[i-1][j-1] : 1 + Math.min(d[i-1][j], d[i][j-1], d[i-1][j-1]);
    }
  }
  return d[m][n];
}

function hostnameRoot(hostname){
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  const lastThree = parts.slice(-3).join(".");
  return TWO_LEVEL_TLDS.has(lastTwo) ? lastThree : lastTwo;
}

/* ===========================================================
   Content type detection
   =========================================================== */
function parseContent(raw){
  const t = raw.trim();
  if (/^WIFI:/i.test(t)) return { type: "wifi", raw: t };
  if (/^BEGIN:VCARD/i.test(t)) return { type: "vcard", raw: t };
  if (/^MECARD:/i.test(t)) return { type: "mecard", raw: t };
  if (/^otpauth:\/\//i.test(t)) return { type: "otpauth", raw: t };
  if (/^(intent|market|android-app):/i.test(t)) return { type: "intent", raw: t };
  if (/^(javascript|data|vbscript|file):/i.test(t)) return { type: "script", raw: t };
  if (/^mailto:/i.test(t)) return { type: "mailto", raw: t };
  if (/^tel:/i.test(t)) return { type: "tel", raw: t };
  if (/^sms(to)?:/i.test(t)) return { type: "sms", raw: t };
  if (/^geo:/i.test(t)) return { type: "geo", raw: t };
  if (/^https?:\/\//i.test(t)) return { type: "url", raw: t };
  if (/^[a-z0-9.-]+\.[a-z]{2,}(\/|$|\?)/i.test(t) && !/\s/.test(t)) return { type: "url-noscheme", raw: t };
  return { type: "text", raw: t };
}

/* ===========================================================
   Safety analysis — everything below runs 100% locally.
   Nothing here ever fetches the destination.
   =========================================================== */
function computeConfidence(score, verdict, thresholds, critical){
  if (critical) return 99;
  let conf;
  if (verdict === "danger") {
    const span = Math.max(1, 100 - thresholds.danger);
    conf = 60 + Math.round(Math.min(1, (score - thresholds.danger) / span) * 39);
  } else if (verdict === "caution") {
    const span = Math.max(1, thresholds.danger - thresholds.caution);
    const mid = thresholds.caution + span / 2;
    const distFromMid = Math.abs(score - mid);
    conf = 60 + Math.round((1 - Math.min(1, distFromMid / (span / 2))) * 25);
  } else {
    conf = 99 - Math.round(Math.min(1, score / thresholds.caution) * 35);
  }
  return Math.max(50, Math.min(99, conf));
}

function analyze(parsed){
  const strict = getSetting("strict", true);
  let score = 0;
  let critical = false;
  const reasons = []; // {sev: 'high'|'med'|'low'|'ok', text}
  let advisory = "";
  let label = "Detected content";

  const add = (sev, pts, text) => { reasons.push({ sev, text }); score += pts; };

  switch(parsed.type){

    case "script": {
      critical = true;
      label = "Script / local-resource link";
      add("high", 100, "Uses a script or data-URI scheme that can run code or load local content directly — this is blocked from being opened by this app.");
      break;
    }

    case "intent": {
      label = "App-launch link";
      add("high", 45, "This is an app-launch link (intent / market / android-app) that can open or trigger installation of another app.");
      advisory = "Only continue if you fully trust whoever produced this code — it can bypass the normal web link path.";
      break;
    }

    case "otpauth": {
      label = "Authenticator (2FA) secret";
      add("high", 55, "Contains a one-time-passcode secret. Anyone who imports this can generate the same login codes as you.");
      advisory = "Treat this exactly like a password. Only add it to an authenticator app you trust, and never share a photo or copy of it.";
      break;
    }

    case "wifi": {
      label = "Wi-Fi network credentials";
      const hasPass = /P:([^;]*);/i.exec(parsed.raw);
      const ssid = /S:([^;]*);/i.exec(parsed.raw);
      add("med", 20, `Configures your device to join a Wi-Fi network${ssid ? ` ("${ssid[1]}")` : ""} automatically if accepted.`);
      if (hasPass && hasPass[1]) add("low", 5, "Includes a saved network password.");
      advisory = "Only join networks from sources you trust — a malicious hotspot can intercept or inspect your traffic.";
      break;
    }

    case "vcard":
    case "mecard": {
      label = "Contact card";
      add("low", 10, "Adds a contact with personal details (name, phone, email, etc.) to your device.");
      advisory = "Review the details before saving — contact cards can be used to plant a convincing but fake entry.";
      break;
    }

    case "mailto": {
      label = "Email link";
      add("low", 8, "Opens your email app addressed to an embedded address.");
      break;
    }

    case "tel": {
      label = "Phone call";
      add("low", 8, "Dials a phone number directly when opened.");
      advisory = "Verify the number before calling — QR codes have been used to route calls to premium-rate numbers.";
      break;
    }

    case "sms": {
      label = "Text message";
      add("low", 8, "Opens your messaging app addressed to an embedded number, sometimes with pre-filled text.");
      break;
    }

    case "geo": {
      label = "Map location";
      add("low", 4, "Opens a map centered on embedded coordinates.");
      break;
    }

    case "text": {
      label = "Plain text";
      add("ok", 0, "Plain text with no link, app action, or network request — nothing here executes automatically.");
      break;
    }

    case "url":
    case "url-noscheme": {
      label = "Web address";
      let url;
      try {
        url = new URL(parsed.type === "url" ? parsed.raw : "https://" + parsed.raw);
      } catch (e) {
        add("high", 45, "Could not be parsed as a structurally valid web address.");
        break;
      }

      if (parsed.type === "url-noscheme") {
        add("low", 8, "No scheme (http/https) was specified in the code — assuming https for this check.");
      }

      const hostname = url.hostname.toLowerCase();
      const root = hostnameRoot(hostname);

      const isIpLogger = IP_LOGGERS.has(hostname) || IP_LOGGERS.has(root) ||
        Array.from(IP_LOGGERS).some(d => hostname === d || hostname.endsWith("." + d));
      if (isIpLogger) {
        critical = true;
        add("high", 80, "This domain is a known IP/location-logging service. Opening it can send your IP address and approximate location straight to whoever created this code — not just the destination site, a third party watching specifically for you.");
        advisory = "Do not open this link. IP-logging services exist purely to identify and track whoever clicks, with no legitimate content on the other end.";
      }

      if (url.protocol === "http:") {
        add("med", 18, "Uses unencrypted HTTP — any data exchanged with this site travels in plain text.");
      }

      const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
      const isIPv6ish = hostname.includes(":");
      if (isIPv4 || isIPv6ish) {
        add("high", 42, "Points to a raw IP address instead of a domain name — a common way to hide a site's real identity.");
      }

      if (hostname.includes("xn--")) {
        add("high", 38, "Uses an internationalized (punycode) domain — sometimes used to imitate a trusted brand with look-alike characters.");
      }

      const afterScheme = parsed.raw.replace(/^https?:\/\//i, "");
      const beforeFirstSlash = afterScheme.split("/")[0];
      if (beforeFirstSlash.includes("@")) {
        add("high", 40, 'Contains an "@" before the domain — a classic trick to disguise the real destination in a link.');
      }

      const labelCount = hostname.split(".").length;
      if (labelCount > 4) {
        add("med", 20, "Unusually many subdomain levels, which can be used to bury the real domain deep in the address.");
      }

      const hyphens = (hostname.match(/-/g) || []).length;
      if (hyphens >= 4) {
        add("med", 14, "Domain name contains an unusually large number of hyphens.");
      }

      const tld = hostname.split(".").pop();
      if (SUSPICIOUS_TLDS.has(tld)) {
        add("med", 20, `Uses the ".${tld}" domain ending, a low-cost extension frequently abused for throwaway or malicious sites.`);
      }

      if (SHORTENERS.has(hostname) || SHORTENERS.has(root)) {
        add("med", 26, "Uses a link-shortening service, so the real destination stays hidden until you actually open it.");
      }

      let knownBrand = false;
      for (const brand of BRANDS) {
        if (hostname === brand || hostname.endsWith("." + brand)) { knownBrand = true; break; }
      }
      if (!knownBrand) {
        const rootBase = root.split(".")[0] || "";
        const tokens = Array.from(new Set([rootBase, ...rootBase.split(/[-_]/)])).filter(t => t.length >= 4);
        outer:
        for (const token of tokens) {
          for (const brand of BRANDS) {
            const brandBase = brand.split(".")[0];
            if (Math.abs(token.length - brandBase.length) > 2) continue;
            const dist = levenshtein(token, brandBase);
            if (dist > 0 && dist <= 2) {
              add("high", 48, `Domain closely resembles "${brand}" but is not the same site — a common phishing pattern.`);
              break outer;
            }
          }
        }
      }

      if (!knownBrand) {
        for (const kw of SENSITIVE_KEYWORDS) {
          if (hostname.includes(kw)) {
            add("med", 16, `Domain name contains "${kw}", a word frequently used in phishing links.`);
            break;
          }
        }
      }

      if (url.port && !["80","443",""].includes(url.port)) {
        add("med", 14, `Specifies a non-standard network port (${url.port}).`);
      }

      if (parsed.raw.length > 120) {
        add("low", 8, "Unusually long web address — length is sometimes used to bury suspicious parts of a link.");
      }

      const encodedCount = (parsed.raw.match(/%[0-9A-Fa-f]{2}/g) || []).length;
      if (encodedCount >= 5) {
        add("low", 8, "Contains many percent-encoded characters, which can obscure the real content of the link.");
      }

      if (/utm_|fbclid|gclid|msclkid/i.test(url.search)) {
        add("low", 4, "Includes tracking parameters that can identify you personally to advertisers if you open it.");
      }

      if (reasons.length === 0) {
        add("ok", 0, "No suspicious structure, look-alike domain, or hidden redirect pattern was detected in this address.");
      }
      break;
    }
  }

  let verdict, thresholds;
  thresholds = strict ? { caution: 22, danger: 55 } : { caution: 38, danger: 72 };

  if (critical || score >= thresholds.danger) verdict = "danger";
  else if (score >= thresholds.caution) verdict = "caution";
  else verdict = "safe";

  const clampedScore = Math.min(score, 100);
  const confidence = computeConfidence(clampedScore, verdict, thresholds, critical);

  return { verdict, score: clampedScore, confidence, reasons, advisory, label, contentType: parsed.type };
}

/* ===========================================================
   Result rendering
   =========================================================== */
const VERDICT_META = {
  safe:    { title: "No red flags found",  sub: "Local checks did not detect known risk patterns.", icon: "check" },
  caution: { title: "Proceed with caution", sub: "Some patterns here are worth a second look.",       icon: "warn"  },
  danger:  { title: "This looks dangerous", sub: "Strong risk indicators were detected.",             icon: "danger" }
};

const ICONS = {
  check: '<svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M9 16.2L4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4z"/></svg>',
  warn:  '<svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>',
  danger:'<svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M12 2 1 21h22L12 2zm1 14h-2v2h2v-2zm0-6h-2v4h2v-4z" opacity="0"/><path fill="currentColor" d="M12 2c-.7 0-1.3.4-1.7 1L1.4 19a2 2 0 0 0 1.7 3h17.8a2 2 0 0 0 1.7-3L13.7 3A2 2 0 0 0 12 2zm0 6c.6 0 1 .4 1 1v5a1 1 0 1 1-2 0V9c0-.6.4-1 1-1zm0 9a1.3 1.3 0 1 1 0-2.6 1.3 1.3 0 0 1 0 2.6z"/></svg>',
  spinner: '<svg class="spin-icon" viewBox="0 0 24 24" width="22" height="22"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-dasharray="38 56"/></svg>'
};

let lastAnalysis = null;
let lastParsed = null;

function renderResult(parsed, result){
  lastAnalysis = result; lastParsed = parsed;

  const banner = $("#verdictBanner");
  banner.className = "verdict-banner " + result.verdict;
  $("#verdictIcon").innerHTML = ICONS[VERDICT_META[result.verdict].icon];
  $("#verdictTitle").textContent = VERDICT_META[result.verdict].title;
  $("#verdictSubtitle").textContent = VERDICT_META[result.verdict].sub;
  $("#verdictScore").textContent = "risk " + result.score + "/100";
  $("#verdictConfidence").textContent = result.confidence + "% confidence";

  $("#contentTypeLabel").textContent = result.label;
  $("#contentValue").textContent = parsed.raw;

  const list = $("#reasonsList");
  list.innerHTML = "";
  result.reasons.forEach(r => {
    const li = document.createElement("li");
    li.className = "sev-" + r.sev;
    li.innerHTML = `<span class="tag"></span><span>${escapeHtml(r.text)}</span>`;
    list.appendChild(li);
  });

  const advBlock = $("#advisoryBlock");
  if (result.advisory) {
    advBlock.hidden = false;
    $("#advisoryText").textContent = result.advisory;
  } else {
    advBlock.hidden = true;
  }

  const proceedBtn = $("#proceedBtn");
  const openable = ["url","url-noscheme","tel","sms","mailto","geo","intent","otpauth"];
  if (openable.includes(parsed.type)) {
    proceedBtn.hidden = false;
    proceedBtn.disabled = false;
    proceedBtn.textContent = result.verdict === "safe" ? "Open" : "Open anyway";
  } else {
    proceedBtn.hidden = true;
  }

  document.body.classList.toggle("verdict-safe", result.verdict === "safe");
  showView("result");
  saveHistory(parsed, result);

  if (result.verdict === "danger") vibrate([60, 40, 60, 40, 120]);
  else if (result.verdict === "caution") vibrate([50]);
  else vibrate([20]);
  playScanSound(result.verdict);
}

$("#proceedBtn").addEventListener("click", () => {
  if (!lastParsed) return;
  const goingOut = () => {
    try {
      if (["url","url-noscheme"].includes(lastParsed.type)) {
        const href = lastParsed.type === "url" ? lastParsed.raw : "https://" + lastParsed.raw;
        window.open(href, "_blank", "noopener,noreferrer");
      } else {
        window.location.href = lastParsed.raw;
      }
    } catch (e) {
      toast("Couldn't open this content.");
    }
  };
  if (lastAnalysis.verdict !== "safe") {
    const ok = confirm(
      (lastAnalysis.verdict === "danger"
        ? "QRShield flagged strong risk indicators for this content.\n\n"
        : "QRShield found some suspicious patterns here.\n\n") +
      "Do you still want to continue?"
    );
    if (!ok) return;
  }
  goingOut();
});

$("#copyBtn").addEventListener("click", async () => {
  if (!lastParsed) return;
  try {
    await navigator.clipboard.writeText(lastParsed.raw);
    toast("Copied to clipboard");
  } catch (e) {
    toast("Copy failed — try selecting the text manually");
  }
});

$("#rescanBtn").addEventListener("click", () => showView("scan"));

/* ===========================================================
   History (local only)
   =========================================================== */
const HISTORY_KEY = "qrshield_history_v1";
const MAX_HISTORY = 50;
const HISTORY_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

function loadHistory(){
  try {
    const list = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    const now = Date.now();
    return Array.isArray(list) ? list.filter(h => h && (now - h.ts) < HISTORY_MAX_AGE_MS) : [];
  } catch(e){ return []; }
}

function saveHistory(parsed, result){
  let history = loadHistory();
  history.unshift({
    preview: truncate(parsed.raw, 90),
    type: result.label,
    verdict: result.verdict,
    ts: Date.now()
  });
  history = history.slice(0, MAX_HISTORY);
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(history)); }
  catch(e){ /* storage unavailable — history just won't persist this session */ }
}

function renderHistory(){
  const history = loadHistory();
  const ul = $("#historyList");
  const empty = $("#historyEmpty");
  ul.querySelectorAll(".history-item").forEach(n => n.remove());

  if (!history.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  history.forEach(item => {
    const li = document.createElement("li");
    li.className = "history-item " + item.verdict;
    const date = new Date(item.ts);
    const when = date.toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
                 " · " + date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    li.innerHTML = `
      <span class="h-dot"></span>
      <div class="h-body">
        <div class="h-url">${escapeHtml(item.preview)}</div>
        <div class="h-time">${item.type} · ${when}</div>
      </div>`;
    ul.appendChild(li);
  });
}

$("#clearHistoryBtn").addEventListener("click", () => {
  if (!confirm("Clear all scan history on this device?")) return;
  try { localStorage.removeItem(HISTORY_KEY); } catch(e){ /* storage unavailable */ }
  renderHistory();
  toast("History cleared");
});

/* ===========================================================
   Settings toggles
   =========================================================== */
const strictToggle = $("#strictToggle");
const hapticToggle = $("#hapticToggle");
const soundToggle = $("#soundToggle");
strictToggle.checked = getSetting("strict", true);
hapticToggle.checked = getSetting("haptic", true);
soundToggle.checked = getSetting("sound", true);
strictToggle.addEventListener("change", () => setSetting("strict", strictToggle.checked));
hapticToggle.addEventListener("change", () => setSetting("haptic", hapticToggle.checked));
soundToggle.addEventListener("change", () => setSetting("sound", soundToggle.checked));

/* ===========================================================
   Scan feedback sounds (synthesized — no audio file needed)
   =========================================================== */
let audioCtx = null;
function ensureAudioCtx(){
  if (!audioCtx) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (Ctx) audioCtx = new Ctx();
  }
  if (audioCtx && audioCtx.state === "suspended") audioCtx.resume().catch(() => {});
  return audioCtx;
}

function beepTone(freq, startOffset, duration, ctx){
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = "sine";
  osc.frequency.value = freq;
  const t0 = ctx.currentTime + startOffset;
  gain.gain.setValueAtTime(0.0001, t0);
  gain.gain.exponentialRampToValueAtTime(0.22, t0 + 0.012);
  gain.gain.exponentialRampToValueAtTime(0.0001, t0 + duration);
  osc.connect(gain).connect(ctx.destination);
  osc.start(t0);
  osc.stop(t0 + duration + 0.02);
}

function playScanSound(verdict){
  if (!getSetting("sound", true)) return;
  const ctx = ensureAudioCtx();
  if (!ctx) return;
  try {
    if (verdict === "danger") {
      beepTone(520, 0, 0.11, ctx);
      beepTone(340, 0.13, 0.16, ctx);
    } else if (verdict === "caution") {
      beepTone(700, 0, 0.09, ctx);
      beepTone(700, 0.11, 0.09, ctx);
    } else {
      beepTone(920, 0, 0.14, ctx);
    }
  } catch (e) { /* audio unavailable — silently skip */ }
}

/* ===========================================================
   QR code generation
   =========================================================== */
const generateInput = $("#generateInput");
const generateCanvas = $("#generateCanvas");
const generatePreviewEmpty = $("#generatePreviewEmpty");
const generateDownloadBtn = $("#generateDownloadBtn");
const generateCopyBtn = $("#generateCopyBtn");
let generateDebounce = null;
let generatedValue = "";

function runGenerate(){
  const value = generateInput.value.trim();
  if (!value) {
    generateCanvas.hidden = true;
    generatePreviewEmpty.hidden = false;
    generateDownloadBtn.disabled = true;
    generateCopyBtn.disabled = true;
    generatedValue = "";
    return;
  }
  if (typeof window.QRious !== "function") {
    toast("QR generator failed to load — check your connection and reload.");
    return;
  }
  try {
    generateCanvas.hidden = false;
    generatePreviewEmpty.hidden = true;
    new window.QRious({
      element: generateCanvas,
      value: value,
      size: 560,
      level: "M",
      background: "#ffffff",
      foreground: "#0a0a0a",
      padding: 28
    });
    // restart the pop-in animation on every regeneration
    generateCanvas.classList.remove("qr-generated");
    void generateCanvas.offsetWidth; // force reflow so the class removal registers
    generateCanvas.classList.add("qr-generated");

    generatedValue = value;
    generateDownloadBtn.disabled = false;
    generateCopyBtn.disabled = false;
  } catch (e) {
    toast("Couldn't generate a QR code for that content.");
  }
}

generateInput.addEventListener("input", () => {
  clearTimeout(generateDebounce);
  generateDebounce = setTimeout(runGenerate, 260);
});

generateDownloadBtn.addEventListener("click", () => {
  if (!generatedValue) return;
  const a = document.createElement("a");
  a.download = "qrshield-code.png";
  a.href = generateCanvas.toDataURL("image/png");
  a.click();
  toast("Downloaded");
});

generateCopyBtn.addEventListener("click", async () => {
  if (!generatedValue) return;
  try {
    generateCanvas.toBlob(async (blob) => {
      if (!blob) throw new Error("no blob");
      await navigator.clipboard.write([ new ClipboardItem({ "image/png": blob }) ]);
      toast("Image copied to clipboard");
    }, "image/png");
  } catch (e) {
    toast("Copy isn't supported in this browser — try Download instead.");
  }
});

/* ===========================================================
   Camera + decoding
   =========================================================== */
const video = $("#video");
const canvas = $("#canvas");
const ctx = canvas.getContext("2d", { willReadFrequently: true });
let stream = null;
let rafId = null;
let scanning = false;
let usingBarcodeDetector = false;
let detector = null;
let engineReady = false;

async function initEngineStatus(){
  if ("BarcodeDetector" in window) {
    try {
      const formats = await window.BarcodeDetector.getSupportedFormats();
      if (formats.includes("qr_code")) {
        usingBarcodeDetector = true;
        detector = new window.BarcodeDetector({ formats: ["qr_code"] });
      }
    } catch(e) { /* fall back to jsQR */ }
  }
  engineReady = usingBarcodeDetector || typeof window.jsQR === "function";
  const chip = $("#engineStatus");
  if (!engineReady) {
    chip.classList.add("offline");
    $("#engineStatusText").textContent = "Scanner engine failed to load";
    toast("QR engine failed to load — check your connection and reload.", 4000);
    $("#startBtn").disabled = true;
    $("#uploadBtn").disabled = true;
  } else {
    $("#engineStatusText").textContent = usingBarcodeDetector
      ? "On-device engine ready (native)"
      : "On-device engine ready (jsQR)";
  }
}
initEngineStatus();

async function startScanning(){
  $("#scannerBlocked").hidden = true;
  $("#scannerIdle").classList.remove("hidden");

  if (!window.isSecureContext || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    toast("Camera needs HTTPS or localhost — this page isn't loaded securely.", 4500);
    return;
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" } },
      audio: false
    });
  } catch (e) {
    if (e && e.name === "NotAllowedError") {
      showCameraBlocked(
        "Camera permission denied",
        "Enable camera access for this site in your browser settings, then try again."
      );
    } else if (e && e.name === "NotFoundError") {
      showCameraBlocked("No camera found", "This device doesn't have a camera available to use.");
    } else {
      showCameraBlocked("Camera couldn't start", (e && e.name) ? e.name : "An unknown error occurred.");
    }
    return;
  }
  video.srcObject = stream;
  await video.play();
  video.classList.add("is-live");
  $("#scannerIdle").classList.add("hidden");
  $("#scannerFrame").querySelector(".viewfinder").classList.add("is-active");
  $("#startBtn").textContent = "Stop scanning";
  scanning = true;
  setupTorch();
  setupZoom();
  tick();
}

function showCameraBlocked(title, help){
  $("#scannerIdle").classList.add("hidden");
  $("#scannerBlockedTitle").textContent = title;
  $("#scannerBlockedHelp").textContent = help;
  $("#scannerBlocked").hidden = false;
}

$("#retryCameraBtn").addEventListener("click", () => startScanning());

/* ---------- flashlight / torch ---------- */
let torchTrack = null;
let torchOn = false;

function setupTorch(){
  torchTrack = null;
  torchOn = false;
  const torchBtn = $("#torchBtn");
  torchBtn.classList.remove("is-on");
  torchBtn.hidden = true;

  const track = stream && stream.getVideoTracks()[0];
  if (!track || typeof track.getCapabilities !== "function") return;
  let caps;
  try { caps = track.getCapabilities(); } catch(e){ return; }
  if (caps && caps.torch) {
    torchTrack = track;
    torchBtn.hidden = false;
  }
}

$("#torchBtn").addEventListener("click", async () => {
  if (!torchTrack) return;
  try {
    torchOn = !torchOn;
    await torchTrack.applyConstraints({ advanced: [{ torch: torchOn }] });
    $("#torchBtn").classList.toggle("is-on", torchOn);
  } catch (e) {
    toast("Flashlight isn't available on this camera.");
    torchOn = false;
  }
});

/* ---------- pinch-to-zoom ---------- */
let zoomTrack = null;
let zoomCaps = null; // {min, max, step} when the camera supports real optical/digital zoom
let currentZoom = 1;
let pinchBaseDist = null;
let pinchBaseZoom = 1;

function setupZoom(){
  zoomTrack = null;
  zoomCaps = null;
  currentZoom = 1;
  video.style.transform = "";

  const track = stream && stream.getVideoTracks()[0];
  if (!track || typeof track.getCapabilities !== "function") return;
  let caps;
  try { caps = track.getCapabilities(); } catch(e){ return; }
  if (caps && caps.zoom) {
    zoomTrack = track;
    zoomCaps = caps.zoom;
    currentZoom = (caps.zoom.min != null) ? caps.zoom.min : 1;
  }
}

function setZoom(z){
  if (zoomTrack && zoomCaps) {
    z = Math.min(zoomCaps.max, Math.max(zoomCaps.min, z));
    currentZoom = z;
    zoomTrack.applyConstraints({ advanced: [{ zoom: z }] }).catch(() => {});
  } else {
    z = Math.min(3, Math.max(1, z));
    currentZoom = z;
    video.style.transform = z > 1 ? `scale(${z})` : "";
  }
}

function touchDistance(touches){
  const dx = touches[0].clientX - touches[1].clientX;
  const dy = touches[0].clientY - touches[1].clientY;
  return Math.hypot(dx, dy);
}

const scannerFrameEl = $("#scannerFrame");
scannerFrameEl.addEventListener("touchstart", (e) => {
  if (scanning && e.touches.length === 2) {
    pinchBaseDist = touchDistance(e.touches);
    pinchBaseZoom = currentZoom;
  }
}, { passive: true });

scannerFrameEl.addEventListener("touchmove", (e) => {
  if (scanning && e.touches.length === 2 && pinchBaseDist) {
    e.preventDefault();
    const dist = touchDistance(e.touches);
    const ratio = dist / pinchBaseDist;
    setZoom(pinchBaseZoom * ratio);
  }
}, { passive: false });

scannerFrameEl.addEventListener("touchend", (e) => {
  if (e.touches.length < 2) pinchBaseDist = null;
});

function stopScanning(){
  scanning = false;
  if (rafId) cancelAnimationFrame(rafId);
  if (stream) {
    stream.getTracks().forEach(t => t.stop());
    stream = null;
  }
  torchTrack = null;
  torchOn = false;
  zoomTrack = null;
  zoomCaps = null;
  currentZoom = 1;
  pinchBaseDist = null;
  video.style.transform = "";
  const torchBtn = $("#torchBtn");
  if (torchBtn) { torchBtn.hidden = true; torchBtn.classList.remove("is-on"); }
  video.classList.remove("is-live");
  const idle = $("#scannerIdle");
  if (idle) idle.classList.remove("hidden");
  const vf = $("#scannerFrame")?.querySelector(".viewfinder");
  if (vf) vf.classList.remove("is-active");
  const startBtn = $("#startBtn");
  if (startBtn) startBtn.innerHTML = startBtnDefaultHTML;
}
const startBtnDefaultHTML = $("#startBtn").innerHTML;

async function tick(){
  if (!scanning) return;
  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    let content = null;

    if (usingBarcodeDetector) {
      try {
        const codes = await detector.detect(video);
        if (codes && codes.length) content = codes[0].rawValue;
      } catch (e) { /* native detector unavailable/broken this frame — fall through to jsQR below */ }
    }

    if (!content && window.jsQR) {
      try {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const result = window.jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: "attemptBoth" });
        if (result && result.data) content = result.data;
      } catch (e) { /* keep scanning */ }
    }

    if (content) {
      stopScanning();
      const parsed = parseContent(content);
      showAnalyzingState();
      vibrate([15]);
      const delay = 130 + Math.floor(Math.random() * 90); // ~130-220ms
      setTimeout(() => {
        const result = analyze(parsed);
        renderResult(parsed, result);
      }, delay);
      return;
    }
  }
  rafId = requestAnimationFrame(tick);
}

function showAnalyzingState(){
  $("#verdictBanner").className = "verdict-banner analyzing";
  $("#verdictIcon").innerHTML = ICONS.spinner;
  $("#verdictTitle").textContent = "Analyzing…";
  $("#verdictSubtitle").textContent = "Running local checks";
  $("#verdictScore").textContent = "";
  $("#verdictConfidence").textContent = "";
  $("#contentValue").textContent = "";
  $("#reasonsList").innerHTML = "";
  $("#advisoryBlock").hidden = true;
  $("#proceedBtn").hidden = true;
  document.body.classList.remove("verdict-safe");
  showView("result");
}

$("#startBtn").addEventListener("click", () => {
  ensureAudioCtx();
  if (scanning) stopScanning();
  else startScanning();
});

/* ---------- upload-image fallback ---------- */
$("#uploadBtn").addEventListener("click", () => $("#fileInput").click());

$("#fileInput").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const img = new Image();
  const url = URL.createObjectURL(file);
  img.onload = async () => {
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    ctx.drawImage(img, 0, 0);
    URL.revokeObjectURL(url);

    let content = null;
    try {
      if (usingBarcodeDetector) {
        const codes = await detector.detect(canvas);
        if (codes && codes.length) content = codes[0].rawValue;
      }
      if (!content && window.jsQR) {
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const result = window.jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: "attemptBoth" });
        if (result && result.data) content = result.data;
      }
    } catch (err) { /* ignore */ }

    if (content) {
      const parsed = parseContent(content);
      showAnalyzingState();
      const delay = 130 + Math.floor(Math.random() * 90);
      setTimeout(() => {
        const result = analyze(parsed);
        renderResult(parsed, result);
      }, delay);
    } else {
      toast("No QR code found in that image.");
    }
  };
  img.src = url;
  e.target.value = "";
});

/* ===========================================================
   Service worker registration (offline shell, no push)
   =========================================================== */
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js").catch(() => {});
  });
}

/* ===========================================================
   Install-app nudge
   =========================================================== */
function isStandaloneDisplay(){
  return window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;
}

const installNudge = $("#installNudge");
const installNudgeInstallBtn = $("#installNudgeInstall");
const installNudgeDismissBtn = $("#installNudgeDismiss");
let deferredInstallPrompt = null;

function hideInstallNudge(){ installNudge.hidden = true; }

function showInstallNudge(mode){
  if (isStandaloneDisplay() || getSetting("installDismissed", false)) return;
  if (mode === "ios") {
    $("#installNudgeTitle").textContent = "Install QRShield";
    $("#installNudgeHelp").textContent = "Tap the Share icon, then \"Add to Home Screen\".";
    installNudgeInstallBtn.hidden = true;
  } else {
    $("#installNudgeTitle").textContent = "Install QRShield";
    $("#installNudgeHelp").textContent = "Add it to your home screen for quick, full-screen access.";
    installNudgeInstallBtn.hidden = false;
  }
  installNudge.hidden = false;
}

window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  showInstallNudge("chromium");
});

window.addEventListener("appinstalled", () => {
  hideInstallNudge();
  deferredInstallPrompt = null;
});

installNudgeInstallBtn.addEventListener("click", async () => {
  hideInstallNudge();
  if (!deferredInstallPrompt) return;
  deferredInstallPrompt.prompt();
  try { await deferredInstallPrompt.userChoice; } catch (e) { /* dismissed */ }
  deferredInstallPrompt = null;
});

installNudgeDismissBtn.addEventListener("click", () => {
  hideInstallNudge();
  setSetting("installDismissed", true);
});

// iOS Safari never fires beforeinstallprompt — offer manual instructions instead.
(function checkIosInstall(){
  const ua = window.navigator.userAgent || "";
  const isIOS = /iPad|iPhone|iPod/.test(ua) && !window.MSStream;
  const isSafari = /Safari/.test(ua) && !/CriOS|FxiOS|EdgiOS/.test(ua);
  if (isIOS && isSafari && !isStandaloneDisplay()) {
    setTimeout(() => showInstallNudge("ios"), 1500);
  }
})();

})();
