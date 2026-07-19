# QRShield — version 13.46

An installable PWA that scans a QR code and runs an on-device safety check
before you ever open whatever it points to. No accounts, no notifications,
no analytics, no server component — every check happens in the browser.

## New in 13.46

- **Safe Preview** — read a link's destination page *before* opening it,
  without your device ever contacting the site. A public anonymizing relay
  (AllOrigins, with Jina Reader as fallback) fetches the page, so the
  destination sees the relay's IP address — never yours — and receives no
  cookies, no referrer, and nothing identifying. The result is parsed with
  an inert `DOMParser` and rendered as escaped plain text: no scripts run,
  no images load, nothing from the page can make a network request.
  The preview also inspects the fetched page for phishing signals (password
  / login forms, meta-refresh auto-redirects, canonical-domain mismatches)
  and, for shortened links, reveals where they actually lead.
  Honest fine print: the relay itself sees the URL being previewed —
  previews only run when you tap the button, never automatically.
- **Link X-Ray** — every URL result can be broken down into scheme, host,
  port, decoded path, and each decoded query parameter, with trackers and
  hidden-redirect parameters flagged inline.
- **Clean opening** — before a link opens, tracking parameters (`utm_*`,
  `fbclid`, `gclid`, and ~30 more) are stripped and plain `http://` links
  are upgraded to `https://` (both toggleable in Settings).
- **Paste to check** — paste any link or text on the Scan tab to analyze it
  without needing a camera or a printed code.
- **Share results** via the system share sheet (or clipboard fallback).
- **Hardened shell** — a strict Content-Security-Policy meta tag now blocks
  every network destination except the app's own files, the two pinned QR
  libraries, and the two preview relays; frames, objects, and form
  submissions are disabled entirely, and a `no-referrer` policy means the
  app never leaks where you came from.

## Files

- `index.html` — app shell (scan / result / generate / settings screens)
- `style.css` — black-and-red glossy theme + animations
- `app.js` — camera capture, QR decoding, the safety-check engine, QR generation, history, settings
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
- direct links to downloadable executable/script files, including the
  classic "invoice.pdf.exe" double-extension disguise
- homograph/mixed-script domains, embedded open-redirect parameters, and
  brand names embedded as a fake subdomain prefix (e.g. `paypal.com.evil.win`)
- your own personal blocklist (see below)

Each check adds to a risk score; "Strict mode" (on by default, toggle in
Settings) lowers the bar for flagging something as Caution or Dangerous.
Each result also shows a confidence percentage — how far the evidence sits
from a borderline call, not a certainty rating.

This is a heuristic, not a verdict from a threat-intelligence database —
treat "no red flags" as "nothing obvious," not a guarantee.

## Generating QR codes

The Generate tab lets you create your own QR code from any text or link,
entirely on-device (via the QRious library, loaded from a CDN — nothing you
type is sent anywhere). Codes are rendered in plain black-on-white for
maximum real-world scan reliability, regardless of the app's own theme.
Download as PNG or copy the image directly.

## Blocking domains yourself

The Blocked tab lets you maintain a personal list of domains — anything on
it makes QRShield flag matching QR codes as Dangerous automatically, on top
of the built-in checks. Stored only on this device.

## Other settings

- **Strict mode** — tightens the risk thresholds (on by default)
- **Scan vibration** / **Scan sound** — feedback on detection, each toggleable independently
- **Appearance** — Auto (follows system), Light, or Dark
- Pinch-to-zoom works on the camera view while scanning (uses real optical/digital
  zoom on cameras that support it, falls back to a visual zoom otherwise)
- A flashlight toggle appears automatically on devices/cameras that support it

## Scan history

Stored only in the browser's local storage on that device. Nothing is sent
anywhere; clearing it from Settings deletes it for good.
