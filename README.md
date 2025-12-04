**Web Vulnerability Scanner (Educational)**
A lightweight Flask-based web vulnerability scanner for educational and authorized testing. It performs basic crawling, tests for common web vulnerabilities, and generates consumable reports (JSON/TXT/PDF).

**Ethical Use Only** — Scan only systems you own or are explicitly authorized to test. The DDoS module is a **non-intrusive posture assessment** and does not perform load testing.

✨ Features
- Crawl within domain scope with page cap and Safe Mode.
- Form parsing with SQLi & XSS reflection/error heuristics (reduces false positives).
- Security headers & clickjacking checks (modern set; CSP-aware).
- Cookie flags (HttpOnly/Secure), permissive HTTP methods, open-redirect hints.
- Non-intrusive **DDoS Posture Assessment** (rate-limit signals, CDN/WAF hints, slowloris indicator, small concurrency probe).
- Real-time progress/status via REST endpoints.
- Export results as **JSON**, **TXT**, or **PDF**.
- Simple Bootstrap UI; also supports headless/API usage.

🧩 Architecture
- **Flask API** provides `/scan`, `/status/<id>`, `/results/<id>`, and `/export/<id>/{json|txt|pdf}`.
- **Scanner** uses `requests` session, `BeautifulSoup` for parsing, and controlled concurrency.
- **Thread-safe** result store using a lock.
- **Heuristics**:
  - SQLi: payload reflection + DB error signatures / 5xx status
  - XSS: reflection without CSP (naive but practical)
  - Headers: CSP, HSTS, XFO, XCTO, Referrer-Policy
  - DDoS posture: signals only (no stress test)

🚀 Getting Started

1) Setup
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt  # or: pip install flask requests beautifulsoup4 reportlab
```

2) Run
```bash
python app.py
# Open http://localhost:5000
```

3) API Usage (Headless)
Start a scan:
```bash
curl -X POST http://localhost:5000/scan   -H "Content-Type: application/json"   -d '{"url":"http://testphp.vulnweb.com","safe_mode":true,"max_pages":10,"max_workers":6}'
```
Poll status:
```bash
curl http://localhost:5000/status/<scan_id>
```
Get results:
```bash
curl http://localhost:5000/results/<scan_id>
```
Export:
```bash
curl -O http://localhost:5000/export/<scan_id>/json
curl -O http://localhost:5000/export/<scan_id>/txt
curl -O http://localhost:5000/export/<scan_id>/pdf
```

⚠️ Limitations & Notes
- Heuristics are intentionally conservative for a browser-based demo; findings **must be manually validated**.
- SQLi/XSS detection focuses on reflected issues; no DOM XSS or deep blind SQLi.
- DDoS module is **signal-based** and non-intrusive; not a benchmark/load test.
- Crawler scope is same-origin; ignores `mailto:`, `tel:`, `javascript:`.

🧭 Roadmap
- Add CSRF hints, IDOR patterns, SSRF indicators.
- Add DOM-XSS sink/source checks.
- Add SARIF export for CI integration.
- Add per-check enable/disable in UI.
- Add authentication helper (manual cookie/JWT input).



 📜 License
Educational use only. Use responsibly and lawfully.
