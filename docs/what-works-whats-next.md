# What Works

## End-to-End Pipeline

The full pipeline is working:
`traffic_gen` → `data/capture.pcap` + `data/ground_truth.txt` → `feature_extract` → `http_validator` / `dns_validator` → `detector` → `results.log` + `metrics.csv` + `summary.json`

`make up && make demo` runs on a fresh clone in under 5 minutes.

---

## Traffic Generation

Synthetic pcap generation using `pcap_open_dead` + `pcap_dump_open` — no live network required.

Produces **1000 packets total**: 850 legit and 150 malicious, interleaved in a 17:3 ratio per 20-packet block (85%/15%). The 15% malicious rate reflects realistic low-rate attack traffic rather than an obvious flood.

**Legit packets (850):**
- HTTP GET, POST, PUT, HEAD on TCP port 80
- HTTP GET, POST on TCP port 443
- DNS A-record queries on UDP port 53 (example.com, test.local, google.com)

**Malicious packets (150) — 12 attack variants cycling:**

Structural attacks (fail early in validator):
- HTTP payload on UDP port 53 (protocol/port impersonation)
- DNS binary header on TCP port 80 (protocol impersonation)
- Invalid HTTP method (`BADVERB`)
- HTTP request missing Host header
- HTTP request missing version string
- Truncated DNS header (4 bytes, below 12-byte minimum)
- HTTP POST on UDP port 53

Subtle attacks (pass basic checks, caught by behavioral rules):
- HTTP version spoof (`HTTP/1.9`) — passes method/Host checks, fails tightened version rule
- DNS tunneling (40-char base64 subdomain label) — passes port/header/QDCOUNT checks, fails label-length heuristic
- DNS response masquerading as query (QR bit=1) — passes port/length/QDCOUNT, fails QR bit check
- HTTP request smuggling (duplicate `Content-Length`) — passes all structural rules, fails duplicate-header check
- HTTP null byte injection (binary appended after valid headers) — fails null byte payload check

---

## Protocol Validation

- **HTTP validator (9 rules):** TCP protocol, port (80/443), non-empty payload, no null bytes, valid method, recognized HTTP version (1.0/1.1/2 only), Host header, header structure, no duplicate Content-Length
- **DNS validator (7 rules):** UDP/TCP protocol, port (53), minimum header length (12 bytes), QR bit=0 (query not response), QDCOUNT > 0, valid label-prefixed question name with max 32-byte label length, recognized QTYPE

---

## Detection & Metrics

- Binary classifier: a packet is flagged if both validators reject it
- TP/FP/TN/FN computed against ground truth labels
- Detection rate, false positive rate, and accuracy exported to `summary.json`
- Per-packet results exported to `metrics.csv`

---

## Observability

- Timestamped per-packet log at `artifacts/release/results.log`
- No raw payload bytes written to disk

---

## Hardening

- Non-root Docker execution (`USER appuser`)
- Pcap path traversal check in `main.c`
- Packet generation bounded at `TOTAL = 100` in `traffic_gen.c`
- Localhost-only synthetic traffic (`127.0.0.1`)

---

## Testing

- 4 test modules covering all core components
- 25 individual test cases (happy path, negative, edge cases, and subtle attack cases)
- `tests/run_tests.sh` entry point for CI

---

## CI

GitHub Actions pipeline: builds the Docker image, runs the test suite, and prints a gcov coverage summary.
