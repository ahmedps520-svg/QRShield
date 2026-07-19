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
  if (name === "history") renderHistory();
  if (name === "blocked") renderBlockedList();
  if (name !== "scan") stopScanning();
}

$("#navScan").addEventListener("click", () => showView("scan"));
$("#navGenerate").addEventListener("click", () => showView("generate"));
$("#navHistory").addEventListener("click", () => showView("history"));
$("#navBlocked").addEventListener("click", () => showView("blocked"));
$("#navSettings").addEventListener("click", () => showView("settings"));

/* ===========================================================
   Theme (auto / light / dark)
   =========================================================== */
function applyTheme(theme){
  document.documentElement.dataset.theme = theme;
  $$(".theme-btn").forEach(b => b.classList.toggle("is-active", b.dataset.themeChoice === theme));
}
applyTheme(getSetting("theme", "auto"));

/* ===========================================================
   Offline badge
   =========================================================== */
function updateOnlineStatus(){
  $("#offlineBadge").hidden = navigator.onLine;
}
window.addEventListener("online", updateOnlineStatus);
window.addEventListener("offline", updateOnlineStatus);
updateOnlineStatus();

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
  "v.gd","lnkd.in","tr.im","clck.ru","qr.ae","bl.ink","po.st","adf.ly",
  "cli.re","short.io","tiny.one","urlgeni.us","chilp.it","x.co","1url.com",
  "vzturl.com","zi.ma","kutt.it","git.io","cutt.us","gg.gg"
]);

// Services whose specific purpose is to capture a visitor's IP address and
// approximate location and report it back to whoever created the link —
// distinct from (and worse than) an ordinary link shortener that merely
// hides a destination. Any match here is treated as an immediate danger.
const IP_LOGGERS = new Set([
  "iplogger.org","iplogger.com","iplogger.ru","iplogger.co","iplogger.info",
  "grabify.link","2no.co","yip.su","iplis.ru","blasze.com","blasze.tk",
  "whatstheirip.com","ezstat.ru","stopmodreposts.org","ipgrabber.ru",
  "trackurl.link","spylink.net","copy-paste.link","shorturl.tips",
  "grabify.io","yourip.pro","catchip.net","ip-grabber.com","logger.ru",
  "definitely-not-a-virus.com","freegiftcard-mobile.com","ipogger.com"
]);

const SUSPICIOUS_TLDS = new Set([
  "tk","ml","ga","cf","gq","xyz","top","work","click","link","loan","win",
  "review","country","kim","gdn","men","party","science","date","faith",
  "icu","cam","cyou","buzz","rest","sbs","quest","monster","support",
  "fit","zip","mom","lol","biz","surf","cfd","bond","beauty","skin",
  "wang","live","stream","download","racing","accountant"
]);

const BRANDS = [
  "paypal.com","apple.com","google.com","microsoft.com","amazon.com",
  "facebook.com","instagram.com","netflix.com","chase.com","bankofamerica.com",
  "wellsfargo.com","dropbox.com","whatsapp.com","linkedin.com","twitter.com",
  "x.com","coinbase.com","binance.com","outlook.com","icloud.com","office.com",
  "adobe.com","ebay.com","americanexpress.com","usbank.com","citibank.com",
  "yahoo.com","steamcommunity.com","docusign.com","microsoft365.com",
  "live.com","hotmail.com","github.com","gitlab.com","spotify.com",
  "venmo.com","zelle.com","cashapp.com","robinhood.com","kraken.com",
  "metamask.io","tiktok.com","snapchat.com","discord.com","telegram.org",
  "usps.com","fedex.com","ups.com","dhl.com","irs.gov"
];

const SENSITIVE_KEYWORDS = [
  "login","verify","secure","account","update","confirm","password","wallet",
  "support","signin","billing","suspended","unlock","recover","security-alert",
  "authenticate","validate","reactivate","restricted","limited","invoice",
  "refund","delivery","tracking-id","gift","prize","winner","claim"
];

// Dangerous executable/script file extensions — a QR code pointing straight
// at one of these is trying to get a file installed/run, not viewed.
const DANGEROUS_EXTENSIONS = new Set([
  "exe","apk","msi","scr","bat","cmd","jar","ps1","vbs","com","gadget",
  "wsf","reg","dmg","pkg","run","sh"
]);

// Query parameters commonly used to bounce a visitor through to a second,
// hidden URL — the display domain isn't necessarily where you'd land.
const REDIRECT_PARAMS = ["url","redirect","redirect_uri","next","return","continue","goto","dest","destination","target"];

const TWO_LEVEL_TLDS = new Set([
  "co.uk","com.au","co.jp","co.in","com.br","co.nz","co.za","com.mx","co.id","com.sg"
]);

/* ===========================================================
   User's personal blocklist (this device only)
   =========================================================== */
const BLOCKLIST_KEY = "qrshield_blocklist_v1";

function loadBlocklist(){
  try {
    const list = JSON.parse(localStorage.getItem(BLOCKLIST_KEY) || "[]");
    return Array.isArray(list) ? list : [];
  } catch(e){ return []; }
}

function persistBlocklist(list){
  try { localStorage.setItem(BLOCKLIST_KEY, JSON.stringify(list)); }
  catch(e){ /* storage unavailable — blocklist just won't persist this session */ }
}

function normalizeBlockEntry(input){
  let t = (input || "").trim().toLowerCase();
  if (!t) return null;
  t = t.replace(/^https?:\/\//, "").replace(/^www\./, "");
  t = t.split("/")[0].split("?")[0].split("#")[0];
  return t || null;
}

function isDomainBlocked(hostname, root){
  const list = loadBlocklist();
  for (const entry of list) {
    const d = entry.domain;
    if (hostname === d || root === d || hostname.endsWith("." + d)) return d;
  }
  return null;
}

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

      const blockedMatch = isDomainBlocked(hostname, root);
      if (blockedMatch) {
        critical = true;
        add("high", 100, `You've manually blocked "${blockedMatch}" on this device — this code points to it.`);
        advisory = "This domain is on your personal blocklist. Manage it from the Blocked URLs tab.";
      }

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
      } else if (/[^\x00-\x7f]/.test(hostname)) {
        add("high", 40, "Domain contains non-standard (non-ASCII) characters — a common homograph trick to visually imitate a trusted domain.");
      }

      const doubleExtMatch = url.pathname.match(/\.([a-z0-9]{2,5})\.([a-z0-9]{2,5})$/i);
      if (doubleExtMatch) {
        const firstExt = doubleExtMatch[1].toLowerCase();
        const lastExt = doubleExtMatch[2].toLowerCase();
        if (DANGEROUS_EXTENSIONS.has(lastExt) && /^(pdf|docx?|jpe?g|png|gif|xlsx?|zip|txt|csv|mp3|mp4)$/i.test(firstExt)) {
          add("high", 55, `Filename disguises a ${lastExt.toUpperCase()} file behind a fake ".${firstExt}" extension — a classic double-extension trick.`);
        } else if (DANGEROUS_EXTENSIONS.has(lastExt)) {
          add("high", 55, `Link points directly to a downloadable ${lastExt.toUpperCase()} file — this would run code or install something rather than open a page.`);
        }
      } else {
        const singleExtMatch = url.pathname.match(/\.([a-z0-9]{2,5})$/i);
        if (singleExtMatch && DANGEROUS_EXTENSIONS.has(singleExtMatch[1].toLowerCase())) {
          add("high", 55, `Link points directly to a downloadable ${singleExtMatch[1].toUpperCase()} file — this would run code or install something rather than open a page.`);
        }
      }

      let redirectTarget = null;
      for (const p of REDIRECT_PARAMS) {
        const v = url.searchParams.get(p);
        if (v && /^https?:\/\//i.test(v)) { redirectTarget = v; break; }
      }
      if (redirectTarget) {
        add("med", 24, `Contains a "${redirectTarget.length > 60 ? redirectTarget.slice(0,60) + "…" : redirectTarget}" redirect embedded in the link — where you actually land may differ from this domain.`);
      }

      const digitHeavySub = hostname.split(".").slice(0, -2).some(label => (label.match(/\d/g) || []).length >= 4);
      if (digitHeavySub) {
        add("med", 16, "Contains a subdomain packed with digits, a pattern common in auto-generated phishing infrastructure.");
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
        for (const brand of BRANDS) {
          if (hostname.includes(brand)) {
            add("high", 52, `Contains "${brand}" embedded earlier in the address, while the actual domain is "${root}" — a common trick to make a fake link look legitimate at a glance.`);
            break;
          }
        }
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

let lastHistoryEntryId = null;

const SCORE_BAR_SEGMENTS = 10;
function renderScoreBar(container, value, filledClass){
  container.innerHTML = "";
  const filledCount = Math.max(value > 0 ? 1 : 0, Math.round((value / 100) * SCORE_BAR_SEGMENTS));
  for (let i = 0; i < SCORE_BAR_SEGMENTS; i++) {
    const seg = document.createElement("span");
    seg.className = "score-seg" + (i < filledCount ? " " + filledClass : "");
    seg.style.setProperty("--seg-i", String(i));
    container.appendChild(seg);
  }
  container.setAttribute("role", "img");
  container.setAttribute("aria-label", String(value) + " out of 100");
}

function renderResult(parsed, result, options){
  options = options || {};
  lastAnalysis = result; lastParsed = parsed;

  const banner = $("#verdictBanner");
  banner.className = "verdict-banner " + result.verdict;
  $("#verdictIcon").innerHTML = ICONS[VERDICT_META[result.verdict].icon];
  $("#verdictTitle").textContent = VERDICT_META[result.verdict].title;
  $("#verdictSubtitle").textContent = VERDICT_META[result.verdict].sub;
  renderScoreBar($("#riskBar"), result.score, "filled-risk");
  renderScoreBar($("#confidenceBar"), result.confidence, "filled-confidence");
  $("#analyzingBarWrap").hidden = true;
  $("#scoreBars").hidden = false;

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

  // Safe preview + Link X-Ray only make sense for web addresses.
  $("#previewBtn").hidden = !["url","url-noscheme"].includes(parsed.type);
  renderXray(parsed);

  document.body.classList.toggle("verdict-safe", result.verdict === "safe");
  showView("result");

  if (options.fromHistory) {
    lastHistoryEntryId = options.historyId;
  } else {
    lastHistoryEntryId = saveHistory(parsed, result);
    if (result.verdict === "safe") fireConfetti();
  }
  const favEntry = loadHistory().find(h => h.id === lastHistoryEntryId);
  $("#favoriteBtn").classList.toggle("is-on", !!(favEntry && favEntry.fav));

  if (result.verdict === "danger") vibrate([60, 40, 60, 40, 120]);
  else if (result.verdict === "caution") vibrate([50]);
  else vibrate([20]);
  playScanSound(result.verdict);
}

$("#favoriteBtn").addEventListener("click", () => {
  if (!lastHistoryEntryId) return;
  const history = loadHistory();
  const entry = history.find(h => h.id === lastHistoryEntryId);
  if (!entry) return;
  entry.fav = !entry.fav;
  persistHistory(history);
  $("#favoriteBtn").classList.toggle("is-on", entry.fav);
});

/* ---------- confetti (verified-safe celebration) ---------- */
function fireConfetti(){
  const colors = ["#ff2d4d","#ff5470","#2fe3a3","#ffb020","#ffffff"];
  const count = 36;
  for (let i = 0; i < count; i++) {
    const el = document.createElement("div");
    el.className = "confetti-piece";
    const size = 6 + Math.random() * 6;
    el.style.width = size + "px";
    el.style.height = (size * 0.4) + "px";
    el.style.left = Math.random() * 100 + "vw";
    el.style.background = colors[Math.floor(Math.random() * colors.length)];
    el.style.animationDuration = (2.1 + Math.random() * 1.3) + "s";
    el.style.animationDelay = (Math.random() * 0.25) + "s";
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }
}

/* ---------- clean-link opening: strip trackers, prefer HTTPS ---------- */
const TRACKING_PARAM_EXACT = new Set([
  "fbclid","gclid","dclid","msclkid","yclid","twclid","ttclid","wbraid","gbraid",
  "igshid","mc_eid","mkt_tok","oly_enc_id","oly_anon_id","vero_id","s_cid","icid",
  "_hsenc","_hsmi","spm","ref_src","cmpid","soc_src","soc_trk","mc_cid","ml_subscriber",
  "ml_subscriber_hash","rb_clickid","oicd","wickedid","irclickid"
]);

function isTrackingParam(name){
  return /^utm_/i.test(name) || TRACKING_PARAM_EXACT.has(name.toLowerCase());
}

function sanitizeUrlForOpen(href){
  const info = { href, removed: 0, upgraded: false };
  let url;
  try { url = new URL(href); } catch(e){ return info; }
  if (getSetting("stripTrackers", true)) {
    const toDelete = [];
    url.searchParams.forEach((v, k) => { if (isTrackingParam(k)) toDelete.push(k); });
    toDelete.forEach(k => url.searchParams.delete(k));
    info.removed = toDelete.length;
  }
  if (getSetting("httpsUpgrade", true) && url.protocol === "http:") {
    url.protocol = "https:";
    info.upgraded = true;
  }
  info.href = url.toString();
  return info;
}

$("#proceedBtn").addEventListener("click", () => {
  if (!lastParsed) return;
  const goingOut = () => {
    try {
      if (["url","url-noscheme"].includes(lastParsed.type)) {
        const href = lastParsed.type === "url" ? lastParsed.raw : "https://" + lastParsed.raw;
        const cleaned = sanitizeUrlForOpen(href);
        window.open(cleaned.href, "_blank", "noopener,noreferrer");
        const notes = [];
        if (cleaned.removed) notes.push(cleaned.removed + " tracking parameter" + (cleaned.removed === 1 ? "" : "s") + " removed");
        if (cleaned.upgraded) notes.push("upgraded to HTTPS");
        if (notes.length) toast("Opened — " + notes.join(", "));
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

$("#shareBtn").addEventListener("click", async () => {
  if (!lastParsed || !lastAnalysis) return;
  const text = "QRShield scan — " + VERDICT_META[lastAnalysis.verdict].title +
    " (risk " + lastAnalysis.score + "/100, confidence " + lastAnalysis.confidence + "%)\n\n" +
    lastParsed.raw;
  if (navigator.share) {
    try { await navigator.share({ title: "QRShield scan result", text }); } catch(e){ /* user cancelled */ }
  } else {
    try {
      await navigator.clipboard.writeText(text);
      toast("Result copied — paste it anywhere to share");
    } catch(e){ toast("Sharing isn't supported in this browser."); }
  }
});

/* ===========================================================
   Link X-Ray — a fully local breakdown of the address
   =========================================================== */
function safeDecode(str){
  try { return decodeURIComponent(str); } catch(e){ return str; }
}

function xrayRow(label, value, flag, flagSev){
  const row = document.createElement("div");
  row.className = "xray-row";
  const l = document.createElement("span");
  l.className = "xray-label";
  l.textContent = label;
  const v = document.createElement("span");
  v.className = "xray-value";
  v.textContent = value;
  row.appendChild(l);
  row.appendChild(v);
  if (flag) {
    const f = document.createElement("span");
    f.className = "xray-flag " + (flagSev || "med");
    f.textContent = flag;
    row.appendChild(f);
  }
  return row;
}

function renderXray(parsed){
  const block = $("#xrayBlock");
  const content = $("#xrayContent");
  content.innerHTML = "";
  content.hidden = true;
  const toggle = $("#xrayToggle");
  toggle.setAttribute("aria-expanded", "false");
  toggle.classList.remove("is-open");

  if (!["url","url-noscheme"].includes(parsed.type)) { block.hidden = true; return; }
  let url;
  try { url = new URL(parsed.type === "url" ? parsed.raw : "https://" + parsed.raw); }
  catch(e){ block.hidden = true; return; }
  block.hidden = false;

  content.appendChild(xrayRow("Scheme", url.protocol.replace(":", ""),
    url.protocol === "http:" ? "unencrypted" : null, "high"));
  content.appendChild(xrayRow("Host", url.hostname,
    url.hostname.includes("xn--") ? "punycode" : null, "high"));
  if (url.username) content.appendChild(xrayRow("Credentials", "embedded before the host", "decoy trick", "high"));
  if (url.port) content.appendChild(xrayRow("Port", url.port, "non-standard", "med"));
  if (url.pathname && url.pathname !== "/") content.appendChild(xrayRow("Path", safeDecode(url.pathname)));
  url.searchParams.forEach((v, k) => {
    let flag = null, sev = "med";
    if (isTrackingParam(k)) { flag = "tracker"; }
    else if (REDIRECT_PARAMS.includes(k.toLowerCase()) && /^https?:\/\//i.test(v)) { flag = "hidden redirect"; sev = "high"; }
    content.appendChild(xrayRow("Param · " + k, safeDecode(v) || "(empty)", flag, sev));
  });
  if (url.hash) content.appendChild(xrayRow("Fragment", safeDecode(url.hash.slice(1))));
}

$("#xrayToggle").addEventListener("click", () => {
  const content = $("#xrayContent");
  content.hidden = !content.hidden;
  const toggle = $("#xrayToggle");
  toggle.setAttribute("aria-expanded", String(!content.hidden));
  toggle.classList.toggle("is-open", !content.hidden);
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

function persistHistory(history){
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(history)); }
  catch(e){ /* storage unavailable — history just won't persist this session */ }
}

function extractDomain(raw){
  try {
    const t = raw.trim();
    if (/^https?:\/\//i.test(t)) return new URL(t).hostname.toLowerCase();
    if (/^[a-z0-9.-]+\.[a-z]{2,}(\/|$|\?)/i.test(t) && !/\s/.test(t)) return new URL("https://" + t).hostname.toLowerCase();
  } catch(e){ /* not a URL-shaped value */ }
  return null;
}

function saveHistory(parsed, result){
  let history = loadHistory();
  const id = Date.now() + "-" + Math.random().toString(36).slice(2, 7);
  history.unshift({
    id,
    raw: parsed.raw,
    preview: truncate(parsed.raw, 90),
    type: result.label,
    verdict: result.verdict,
    domain: extractDomain(parsed.raw),
    fav: false,
    tags: [],
    ts: Date.now()
  });
  history = history.slice(0, MAX_HISTORY);
  persistHistory(history);
  return id;
}

let historySearchTerm = "";
let showFavoritesOnly = false;

function renderHistory(){
  const allHistory = loadHistory();
  renderStats(allHistory);

  let history = allHistory;
  if (showFavoritesOnly) history = history.filter(h => h.fav);
  if (historySearchTerm) {
    const q = historySearchTerm.toLowerCase();
    history = history.filter(h =>
      (h.raw || "").toLowerCase().includes(q) ||
      (h.tags || []).some(t => t.toLowerCase().includes(q))
    );
  }

  const ul = $("#historyList");
  const empty = $("#historyEmpty");
  ul.querySelectorAll(".history-item").forEach(n => n.remove());

  if (!history.length) {
    empty.hidden = false;
    empty.textContent = allHistory.length
      ? "No scans match your filters."
      : "No scans yet — your history stays on this device only.";
    return;
  }
  empty.hidden = true;

  history.forEach(item => {
    const li = document.createElement("li");
    li.className = "history-item " + item.verdict;
    li.dataset.id = item.id;
    const date = new Date(item.ts);
    const when = date.toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
                 " · " + date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    const tagsHtml = (item.tags && item.tags.length)
      ? `<div class="h-tags">${item.tags.map(t => `<span class="history-tag">${escapeHtml(t)}</span>`).join("")}</div>`
      : "";
    li.innerHTML = `
      <span class="h-dot"></span>
      <div class="h-body" data-action="review">
        <div class="h-url">${escapeHtml(item.preview)}</div>
        <div class="h-time">${item.type} · ${when} · <button class="h-tag-edit" data-action="tags" type="button">+ tag</button></div>
        ${tagsHtml}
      </div>
      <button class="h-fav ${item.fav ? "is-fav" : ""}" data-action="fav" type="button" aria-label="Favorite">
        <svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M12 17.3 6.2 21l1.6-6.7L2 9.7l6.9-.6L12 2.5l3.1 6.6 6.9.6-5.8 4.6L17.8 21z"/></svg>
      </button>`;
    ul.appendChild(li);
  });
}

$("#historyList").addEventListener("click", (e) => {
  const li = e.target.closest(".history-item");
  if (!li) return;
  const id = li.dataset.id;
  const history = loadHistory();
  const entry = history.find(h => h.id === id);
  if (!entry) return;

  if (e.target.closest('[data-action="fav"]')) {
    entry.fav = !entry.fav;
    persistHistory(history);
    renderHistory();
    return;
  }

  if (e.target.closest('[data-action="tags"]')) {
    const current = (entry.tags || []).join(", ");
    const input = prompt("Tags (comma-separated):", current);
    if (input !== null) {
      entry.tags = input.split(",").map(t => t.trim()).filter(Boolean).slice(0, 6);
      persistHistory(history);
      renderHistory();
    }
    return;
  }

  if (e.target.closest('[data-action="review"]')) {
    const parsed = parseContent(entry.raw);
    const result = analyze(parsed);
    renderResult(parsed, result, { fromHistory: true, historyId: entry.id });
  }
});

$("#historySearch").addEventListener("input", (e) => {
  historySearchTerm = e.target.value;
  renderHistory();
});

$("#favoriteFilterBtn").addEventListener("click", () => {
  showFavoritesOnly = !showFavoritesOnly;
  const btn = $("#favoriteFilterBtn");
  btn.classList.toggle("is-active", showFavoritesOnly);
  btn.setAttribute("aria-pressed", String(showFavoritesOnly));
  renderHistory();
});

/* ---------- stats / activity calendar ---------- */

function renderStats(history){
  const counts = { safe: 0, caution: 0, danger: 0 };
  const domainCounts = {};
  history.forEach(h => {
    if (counts[h.verdict] !== undefined) counts[h.verdict]++;
    if (h.domain) domainCounts[h.domain] = (domainCounts[h.domain] || 0) + 1;
  });
  $("#statTotal").textContent = history.length;
  $("#statSafe").textContent = counts.safe;
  $("#statCaution").textContent = counts.caution;
  $("#statDanger").textContent = counts.danger;

  const wrap = $("#topDomainsWrap");
  const list = $("#topDomains");
  list.innerHTML = "";
  const topDomains = Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  if (topDomains.length) {
    wrap.hidden = false;
    topDomains.forEach(([domain, count]) => {
      const row = document.createElement("div");
      row.className = "top-domain-row";
      row.innerHTML = `<span>${escapeHtml(domain)}</span><span class="count">${count}</span>`;
      list.appendChild(row);
    });
  } else {
    wrap.hidden = true;
  }

  renderActivityCalendar(history);
}

function renderActivityCalendar(history){
  const days = 70; // ~10 weeks
  const dayCounts = {};
  history.forEach(h => {
    const key = new Date(h.ts).toISOString().slice(0, 10);
    dayCounts[key] = (dayCounts[key] || 0) + 1;
  });

  const cal = $("#activityCalendar");
  cal.innerHTML = "";
  const today = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const count = dayCounts[key] || 0;
    let level = 0;
    if (count >= 1) level = 1;
    if (count >= 3) level = 2;
    if (count >= 6) level = 3;
    if (count >= 10) level = 4;
    const cell = document.createElement("div");
    cell.className = "activity-cell";
    cell.dataset.level = String(level);
    cell.title = `${key}: ${count} scan${count === 1 ? "" : "s"}`;
    cal.appendChild(cell);
  }
}

/* ---------- export ---------- */

function csvEscape(val){
  const s = String(val == null ? "" : val);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

$("#exportCsvBtn").addEventListener("click", () => {
  const history = loadHistory();
  if (!history.length) { toast("No history to export."); return; }
  const rows = [["Date", "Verdict", "Type", "Content", "Tags", "Favorite"]];
  history.forEach(h => {
    rows.push([
      new Date(h.ts).toISOString(),
      h.verdict,
      h.type,
      h.raw,
      (h.tags || []).join("; "),
      h.fav ? "Yes" : "No"
    ]);
  });
  const csv = rows.map(r => r.map(csvEscape).join(",")).join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "qrshield-history.csv";
  a.click();
  URL.revokeObjectURL(url);
  toast("CSV downloaded");
});

$("#exportPdfBtn").addEventListener("click", () => {
  const history = loadHistory();
  if (!history.length) { toast("No history to export."); return; }
  const rowsHtml = history.map(h => `
    <tr>
      <td>${escapeHtml(new Date(h.ts).toLocaleString())}</td>
      <td>${escapeHtml(h.verdict)}</td>
      <td>${escapeHtml(h.type)}</td>
      <td style="word-break:break-all;">${escapeHtml(h.raw)}</td>
      <td>${escapeHtml((h.tags || []).join(", "))}</td>
    </tr>`).join("");
  const doc = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>QRShield Scan History</title>
    <style>
      body{ font-family: -apple-system, Arial, sans-serif; padding:24px; color:#111; }
      h1{ font-size:18px; margin-bottom:4px; }
      p{ color:#555; font-size:12px; margin-top:0; }
      table{ width:100%; border-collapse:collapse; font-size:11px; }
      th,td{ border:1px solid #ddd; padding:6px 8px; text-align:left; vertical-align:top; }
      th{ background:#f4f4f4; }
    </style></head><body>
    <h1>QRShield Scan History</h1>
    <p>Exported ${escapeHtml(new Date().toLocaleString())} · ${history.length} scans</p>
    <table><thead><tr><th>Date</th><th>Verdict</th><th>Type</th><th>Content</th><th>Tags</th></tr></thead>
    <tbody>${rowsHtml}</tbody></table>
    </body></html>`;
  const win = window.open("", "_blank");
  if (!win) { toast("Pop-up blocked — allow pop-ups to export."); return; }
  win.document.write(doc);
  win.document.close();
  win.focus();
  setTimeout(() => { try { win.print(); } catch(e){} }, 300);
});

$("#clearHistoryBtn").addEventListener("click", () => {
  if (!confirm("Clear all scan history on this device?")) return;
  try { localStorage.removeItem(HISTORY_KEY); } catch(e){ /* storage unavailable */ }
  renderHistory();
  toast("History cleared");
});

/* ===========================================================
   Blocked URLs view
   =========================================================== */
function renderBlockedList(){
  const list = loadBlocklist();
  const ul = $("#blockedList");
  const empty = $("#blockedEmpty");
  ul.querySelectorAll(".history-item").forEach(n => n.remove());

  if (!list.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  list.slice().reverse().forEach(entry => {
    const li = document.createElement("li");
    li.className = "history-item blocked-item";
    li.dataset.domain = entry.domain;
    const when = new Date(entry.ts).toLocaleDateString(undefined, { month: "short", day: "numeric" });
    li.innerHTML = `
      <span class="h-dot blocked-dot"></span>
      <div class="h-body">
        <div class="h-url">${escapeHtml(entry.domain)}</div>
        <div class="h-time">Blocked ${when}</div>
      </div>
      <button class="h-fav" data-action="unblock" type="button" aria-label="Remove from blocklist">
        <svg viewBox="0 0 24 24" width="15" height="15"><path fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" d="M6 6l12 12M18 6L6 18"/></svg>
      </button>`;
    ul.appendChild(li);
  });
}

$("#blockAddBtn").addEventListener("click", () => {
  const domain = normalizeBlockEntry($("#blockInput").value);
  if (!domain) { toast("Enter a URL or domain to block."); return; }
  const list = loadBlocklist();
  if (list.some(e => e.domain === domain)) {
    toast("Already on your blocklist.");
    $("#blockInput").value = "";
    return;
  }
  list.push({ domain, ts: Date.now() });
  persistBlocklist(list);
  $("#blockInput").value = "";
  renderBlockedList();
  toast(`Blocked "${domain}"`);
});

$("#blockInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); $("#blockAddBtn").click(); }
});

$("#blockedList").addEventListener("click", (e) => {
  if (!e.target.closest('[data-action="unblock"]')) return;
  const li = e.target.closest(".history-item");
  if (!li) return;
  const domain = li.dataset.domain;
  const list = loadBlocklist().filter(entry => entry.domain !== domain);
  persistBlocklist(list);
  renderBlockedList();
  toast("Removed from blocklist");
});

$("#clearBlocklistBtn").addEventListener("click", () => {
  if (!confirm("Clear your entire blocklist?")) return;
  persistBlocklist([]);
  renderBlockedList();
  toast("Blocklist cleared");
});

/* ===========================================================
   Settings toggles
   =========================================================== */
const strictToggle = $("#strictToggle");
const hapticToggle = $("#hapticToggle");
const soundToggle = $("#soundToggle");
const stripTrackersToggle = $("#stripTrackersToggle");
const httpsUpgradeToggle = $("#httpsUpgradeToggle");
strictToggle.checked = getSetting("strict", true);
hapticToggle.checked = getSetting("haptic", true);
soundToggle.checked = getSetting("sound", true);
stripTrackersToggle.checked = getSetting("stripTrackers", true);
httpsUpgradeToggle.checked = getSetting("httpsUpgrade", true);
strictToggle.addEventListener("change", () => setSetting("strict", strictToggle.checked));
hapticToggle.addEventListener("change", () => setSetting("haptic", hapticToggle.checked));
soundToggle.addEventListener("change", () => setSetting("sound", soundToggle.checked));
stripTrackersToggle.addEventListener("change", () => setSetting("stripTrackers", stripTrackersToggle.checked));
httpsUpgradeToggle.addEventListener("change", () => setSetting("httpsUpgrade", httpsUpgradeToggle.checked));

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
  $("#scannerFrame").querySelector(".viewfinder").classList.remove("found");
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
  if (vf) { vf.classList.remove("is-active"); vf.classList.remove("found"); }
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
      const parsed = parseContent(content);
      showFoundState();
      vibrate([15]);
      setTimeout(() => {
        stopScanning();
        showAnalyzingState();
        setTimeout(() => {
          const result = analyze(parsed);
          renderResult(parsed, result);
        }, 950); // matches the analyzing bar's CSS fill duration
      }, 550); // lets the "found" lock-on animation play before moving on
      return;
    }
  }
  rafId = requestAnimationFrame(tick);
}

function showFoundState(){
  scanning = false; // stop the detection loop but leave the camera visibly live
  if (rafId) cancelAnimationFrame(rafId);
  const vf = $("#scannerFrame")?.querySelector(".viewfinder");
  if (vf) vf.classList.add("found");
}

function showAnalyzingState(){
  $("#verdictBanner").className = "verdict-banner analyzing";
  $("#verdictIcon").innerHTML = ICONS.spinner;
  $("#verdictTitle").textContent = "Analyzing…";
  $("#verdictSubtitle").textContent = "Running local checks";
  $("#contentValue").textContent = "";
  $("#reasonsList").innerHTML = "";
  $("#advisoryBlock").hidden = true;
  $("#proceedBtn").hidden = true;
  $("#previewBtn").hidden = true;
  $("#xrayBlock").hidden = true;
  document.body.classList.remove("verdict-safe");

  const bar = $("#analyzingBar");
  $("#scoreBars").hidden = true;
  $("#analyzingBarWrap").hidden = false;
  bar.style.transition = "none";
  bar.style.width = "0%";
  void bar.offsetWidth; // force reflow so the next width change actually transitions
  bar.style.transition = "";
  requestAnimationFrame(() => { bar.style.width = "100%"; });

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
      const delay = 950; // matches the analyzing bar's CSS fill duration
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
   Paste-to-check — analyze any link or text without a camera
   =========================================================== */
const checkLinkInput = $("#checkLinkInput");

function checkPastedContent(){
  const value = checkLinkInput.value.trim();
  if (!value) { toast("Paste a link or some text first."); return; }
  checkLinkInput.value = "";
  checkLinkInput.blur();
  const parsed = parseContent(value);
  stopScanning();
  showAnalyzingState();
  setTimeout(() => {
    const result = analyze(parsed);
    renderResult(parsed, result);
  }, 950); // matches the analyzing bar's CSS fill duration
}

$("#checkLinkBtn").addEventListener("click", checkPastedContent);
checkLinkInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); checkPastedContent(); }
});

/* ===========================================================
   Safe Preview — read the destination WITHOUT touching it.

   The fetch is performed by a public anonymizing relay, so the
   destination server sees the relay's IP address — never this
   device's. The request carries no cookies and no referrer, and
   whatever comes back is parsed with DOMParser (inert: scripts
   never execute, images and subresources never load) and rendered
   as escaped plain text only. The page's own CSP additionally
   blocks every network destination except the two relays.
   =========================================================== */
const PREVIEW_TIMEOUT_MS = 14000;
let previewAbort = null;

function previewTargetHref(){
  if (!lastParsed || !["url","url-noscheme"].includes(lastParsed.type)) return null;
  return lastParsed.type === "url" ? lastParsed.raw : "https://" + lastParsed.raw;
}

function openPreviewSheet(){
  const backdrop = $("#previewBackdrop");
  const sheet = $("#previewSheet");
  backdrop.hidden = false;
  sheet.hidden = false;
  void sheet.offsetWidth; // force reflow so the slide-up transition actually runs
  backdrop.classList.add("is-open");
  sheet.classList.add("is-open");
  document.body.classList.add("sheet-locked");
  runPreview();
}

function closePreviewSheet(){
  if (previewAbort) { previewAbort.abort(); previewAbort = null; }
  $("#previewBackdrop").classList.remove("is-open");
  $("#previewSheet").classList.remove("is-open");
  document.body.classList.remove("sheet-locked");
  setTimeout(() => {
    $("#previewBackdrop").hidden = true;
    $("#previewSheet").hidden = true;
  }, 280); // matches the sheet's slide-down transition
}

$("#previewBtn").addEventListener("click", openPreviewSheet);
$("#previewCloseBtn").addEventListener("click", closePreviewSheet);
$("#previewBackdrop").addEventListener("click", closePreviewSheet);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("#previewSheet").hidden) closePreviewSheet();
});

/* ---------- relay fetchers ---------- */
async function fetchViaAllOrigins(target, signal){
  const res = await fetch("https://api.allorigins.win/get?url=" + encodeURIComponent(target), {
    signal, credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store"
  });
  if (!res.ok) throw new Error("relay HTTP " + res.status);
  const data = await res.json();
  if (!data || typeof data.contents !== "string" || !data.contents) throw new Error("empty relay response");
  return { html: data.contents, via: "AllOrigins relay" };
}

async function fetchViaJina(target, signal){
  const res = await fetch("https://r.jina.ai/" + target, {
    signal, credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store"
  });
  if (!res.ok) throw new Error("relay HTTP " + res.status);
  const text = await res.text();
  if (!text) throw new Error("empty relay response");
  return { text, via: "Jina reader relay" };
}

/* ---------- inspect fetched HTML (inert, local) ---------- */
function inspectFetchedHtml(html, targetHref){
  const doc = new DOMParser().parseFromString(html, "text/html");
  const attr = (sel, name) => {
    const el = doc.querySelector(sel);
    return el ? (el.getAttribute(name) || "").trim() : "";
  };

  const title = (doc.title || "").trim() || attr('meta[property="og:title"]', "content");
  const description = attr('meta[name="description"]', "content") || attr('meta[property="og:description"]', "content");
  const canonical = attr('link[rel="canonical"]', "href") || attr('meta[property="og:url"]', "content");

  let metaRefreshUrl = null;
  const mr = doc.querySelector('meta[http-equiv="refresh" i]');
  if (mr) {
    const m = /url\s*=\s*['"]?([^'">\s]+)/i.exec(mr.getAttribute("content") || "");
    if (m) metaRefreshUrl = m[1];
  }

  const passwordInputs = doc.querySelectorAll('input[type="password"]').length;
  const forms = doc.querySelectorAll("form").length;
  const extScripts = doc.querySelectorAll("script[src]").length;
  const iframes = doc.querySelectorAll("iframe").length;

  const domainCounts = {};
  doc.querySelectorAll("a[href]").forEach(a => {
    try {
      const u = new URL(a.getAttribute("href"), targetHref);
      if (/^https?:$/.test(u.protocol)) domainCounts[u.hostname] = (domainCounts[u.hostname] || 0) + 1;
    } catch(e){ /* unparseable href */ }
  });

  doc.querySelectorAll("script,style,noscript,template").forEach(n => n.remove());
  const excerpt = (doc.body ? doc.body.textContent : "").replace(/\s+/g, " ").trim().slice(0, 700);

  return { title, description, canonical, metaRefreshUrl, passwordInputs, forms, extScripts, iframes, domainCounts, excerpt };
}

function buildPreviewSignals(inspection, targetHref){
  const signals = []; // {sev, text}
  let targetRoot = "";
  try { targetRoot = hostnameRoot(new URL(targetHref).hostname.toLowerCase()); } catch(e){}

  if (inspection.passwordInputs > 0) {
    signals.push({ sev: "high", text: "The page contains a password / login form. If you weren't expecting to sign in here, treat it as a phishing page." });
  }
  if (inspection.metaRefreshUrl) {
    signals.push({ sev: "high", text: "The page auto-redirects visitors to: " + truncate(inspection.metaRefreshUrl, 90) });
  }
  if (inspection.canonical) {
    try {
      const canonRoot = hostnameRoot(new URL(inspection.canonical, targetHref).hostname.toLowerCase());
      if (targetRoot && canonRoot && canonRoot !== targetRoot) {
        signals.push({ sev: "med", text: 'The page identifies itself as belonging to "' + canonRoot + '" — a different site than the address you scanned.' });
      }
    } catch(e){ /* bad canonical URL */ }
  }
  if (inspection.forms > 0 && inspection.passwordInputs === 0) {
    signals.push({ sev: "low", text: "Contains " + inspection.forms + " form" + (inspection.forms === 1 ? "" : "s") + " that would submit data if filled in." });
  }
  if (inspection.iframes > 0) {
    signals.push({ sev: "low", text: "Embeds " + inspection.iframes + " frame" + (inspection.iframes === 1 ? "" : "s") + " loading other pages inside it." });
  }
  if (inspection.extScripts > 12) {
    signals.push({ sev: "low", text: "Loads an unusually high number of external scripts (" + inspection.extScripts + ")." });
  }
  if (!signals.length) {
    signals.push({ sev: "ok", text: "No login form, auto-redirect, or identity mismatch found in the fetched page." });
  }
  return signals;
}

/* ---------- preview rendering (textContent only — never innerHTML) ---------- */
function pvSection(labelText){
  const wrap = document.createElement("div");
  wrap.className = "pv-section";
  const label = document.createElement("span");
  label.className = "content-label";
  label.textContent = labelText;
  wrap.appendChild(label);
  return wrap;
}

function showPreviewLoading(target){
  const body = $("#previewBody");
  body.innerHTML = "";
  const chip = document.createElement("div");
  chip.className = "pv-relay-chip";
  chip.textContent = "Relay is fetching " + truncate(target, 70) + " …";
  body.appendChild(chip);
  for (let i = 0; i < 4; i++) {
    const sk = document.createElement("div");
    sk.className = "pv-skeleton" + (i === 0 ? " wide" : "");
    body.appendChild(sk);
  }
}

function showPreviewError(message){
  if ($("#previewSheet").hidden) return;
  const body = $("#previewBody");
  body.innerHTML = "";
  const err = document.createElement("div");
  err.className = "pv-error";
  const p = document.createElement("p");
  p.textContent = message;
  err.appendChild(p);
  const retry = document.createElement("button");
  retry.className = "btn btn-outline";
  retry.textContent = "Try again";
  retry.addEventListener("click", runPreview);
  err.appendChild(retry);
  body.appendChild(err);
}

function renderPreviewCommon(body, via, finalUrl, targetHref){
  const chip = document.createElement("div");
  chip.className = "pv-relay-chip ok";
  chip.textContent = "Fetched anonymously via " + via + " — your IP was never sent to the site";
  body.appendChild(chip);

  const dest = pvSection("Destination");
  const destVal = document.createElement("div");
  destVal.className = "content-value pv-dest";
  destVal.textContent = finalUrl || targetHref;
  dest.appendChild(destVal);
  body.appendChild(dest);
}

function renderPreviewMeta(body, title, description){
  const sec = pvSection("What the page says it is");
  const t = document.createElement("p");
  t.className = "pv-page-title";
  t.textContent = title || "(no title)";
  sec.appendChild(t);
  if (description) {
    const d = document.createElement("p");
    d.className = "pv-page-desc";
    d.textContent = description;
    sec.appendChild(d);
  }
  body.appendChild(sec);
}

function renderPreviewSignals(body, signals){
  const sec = pvSection("Page inspection");
  const ul = document.createElement("ul");
  ul.className = "pv-signals";
  signals.forEach(s => {
    const li = document.createElement("li");
    li.className = "sev-" + s.sev;
    const tag = document.createElement("span");
    tag.className = "tag";
    const txt = document.createElement("span");
    txt.textContent = s.text;
    li.appendChild(tag);
    li.appendChild(txt);
    ul.appendChild(li);
  });
  sec.appendChild(ul);
  body.appendChild(sec);
}

function renderPreviewExcerpt(body, excerpt){
  if (!excerpt) return;
  const sec = pvSection("Page text (first part, scripts stripped)");
  const p = document.createElement("p");
  p.className = "pv-excerpt";
  p.textContent = excerpt + (excerpt.length >= 700 ? " …" : "");
  sec.appendChild(p);
  body.appendChild(sec);
}

function renderPreviewFromHtml(result, targetHref){
  if ($("#previewSheet").hidden) return;
  const inspection = inspectFetchedHtml(result.html, targetHref);
  const body = $("#previewBody");
  body.innerHTML = "";

  renderPreviewCommon(body, result.via, inspection.canonical || null, targetHref);
  renderPreviewMeta(body, inspection.title, inspection.description);
  renderPreviewSignals(body, buildPreviewSignals(inspection, targetHref));
  renderPreviewExcerpt(body, inspection.excerpt);

  const topDomains = Object.entries(inspection.domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  if (topDomains.length) {
    const sec = pvSection("Where its links point");
    const wrap = document.createElement("div");
    wrap.className = "pv-linkmap";
    topDomains.forEach(([domain, count]) => {
      const rowEl = document.createElement("div");
      rowEl.className = "top-domain-row";
      const d = document.createElement("span");
      d.textContent = domain;
      const c = document.createElement("span");
      c.className = "count";
      c.textContent = String(count);
      rowEl.appendChild(d);
      rowEl.appendChild(c);
      wrap.appendChild(rowEl);
    });
    sec.appendChild(wrap);
    body.appendChild(sec);
  }
}

function renderPreviewFromJina(result, targetHref){
  if ($("#previewSheet").hidden) return;
  const text = result.text;
  const titleM = /^Title:\s*(.+)$/m.exec(text);
  const urlM = /^URL Source:\s*(\S+)/m.exec(text);
  let content = text;
  const idx = text.indexOf("Markdown Content:");
  if (idx !== -1) content = text.slice(idx + "Markdown Content:".length);
  const excerpt = content.replace(/\s+/g, " ").trim().slice(0, 700);

  const body = $("#previewBody");
  body.innerHTML = "";
  const finalUrl = urlM ? urlM[1] : null;
  renderPreviewCommon(body, result.via, finalUrl, targetHref);

  // A shortener's real destination is the single most useful fact here.
  if (finalUrl) {
    try {
      const finalRoot = hostnameRoot(new URL(finalUrl).hostname.toLowerCase());
      const targetRoot = hostnameRoot(new URL(targetHref).hostname.toLowerCase());
      if (finalRoot !== targetRoot) {
        renderPreviewSignals(body, [{ sev: "med", text: 'This link actually leads to "' + finalRoot + '", not the domain shown in the code.' }]);
      }
    } catch(e){ /* unparseable final URL */ }
  }

  renderPreviewMeta(body, titleM ? titleM[1].trim() : null, null);
  renderPreviewExcerpt(body, excerpt);
}

async function runPreview(){
  const target = previewTargetHref();
  if (!target) return;
  if (!/^https?:\/\//i.test(target)) { showPreviewError("Only web links can be previewed."); return; }
  if (!navigator.onLine) { showPreviewError("Safe Preview needs an internet connection — you're offline right now."); return; }

  showPreviewLoading(target);
  previewAbort = new AbortController();
  const signal = previewAbort.signal;
  const timeout = setTimeout(() => { if (previewAbort) previewAbort.abort(); }, PREVIEW_TIMEOUT_MS);

  try {
    let rendered = false;
    try {
      const r = await fetchViaAllOrigins(target, signal);
      renderPreviewFromHtml(r, target);
      rendered = true;
    } catch(e){
      if (signal.aborted) throw e; // timed out / closed — don't bother the fallback
    }
    if (!rendered) {
      const r = await fetchViaJina(target, signal);
      renderPreviewFromJina(r, target);
    }
  } catch(e){
    showPreviewError(signal.aborted
      ? "The relay took too long to answer. Try again in a moment."
      : "Neither preview relay could fetch this page right now. The site may be down, or it may block relays.");
  } finally {
    clearTimeout(timeout);
    previewAbort = null;
  }
}

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
