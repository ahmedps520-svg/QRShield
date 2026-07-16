# QRShield

An installable PWA that scans a QR code and runs an on-device safety check
before you ever open whatever it points to. No accounts, no notifications,
no analytics, no server component — every check happens in the browser.

## Files

- `index.html` — app shell (scan / result / settings screens)
- `style.css` — black-and-red glossy theme + animations
- `app.js` — camera capture, QR decoding, the safety-check engine, history, settings
- `manifest.json` — PWA metadata
- `sw.js` — service worker for offline install (no push/notification code at all)
- `icons/` — generated app icons (regular + maskable, multiple sizes)

## Running it

Camera access (`getUserMedia`) and service workers both require a **secure
context** — `https://` or `http://localhost`. Opening `index.html` directly
from disk (`file://`) will show the UI but the camera and "install app"
prompt won't work.

Easiest options:
- **Local test:** from this folder, run `python3 -m http.server 8000`, then
  visit `http://localhost:8000` on the same device.
- **Real install:** drop the whole folder into any static host (GitHub
  Pages, Netlify, Vercel, Cloudflare Pages, etc.) and open the resulting
  `https://` URL. Your browser will then offer "Add to Home Screen" /
  "Install app".

## How the safety check works

QRShield never visits the link inside a QR code automatically — doing that
would hand your IP address and browser fingerprint to whatever server is on
the other end before you've had a chance to judge it. Instead it inspects
the *text* of the code against a local rule set:

- dangerous schemes (`javascript:`, `data:`, `file:`) — blocked outright
- raw IP addresses or punycode domains standing in for a normal domain
- `@`-symbol and open-redirect style tricks
- domains that closely resemble (but aren't) major brands
- known link-shortening services, which hide the real destination
- suspicious/free TLDs, excess subdomains or hyphens, non-standard ports
- plain HTTP instead of HTTPS
- QR types that carry sensitive payloads: Wi-Fi passwords, contact cards,
  2FA/OTP secrets, app-launch (`intent:`) links

Each check adds to a risk score; "Strict mode" (on by default, toggle in
Settings) lowers the bar for flagging something as Caution or Dangerous.

This is a heuristic, not a verdict from a threat-intelligence database —
treat "no red flags" as "nothing obvious," not a guarantee.

## Scan history

Stored only in the browser's local storage on that device. Nothing is sent
anywhere; clearing it from Settings deletes it for good.
