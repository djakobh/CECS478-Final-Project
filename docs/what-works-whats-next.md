# What Works

## End-to-End Pipeline

The full pipeline is working:
`traffic_gen` → `data/capture.pcap` + `data/ground_truth.txt` → `feature_extract` → `http_validator` / `dns_validator` → `detector` → `results.log` + `metrics.csv` + `summary.json`

`make up && make demo` runs on a fresh clone in under 5 minutes.

---

## Traffic Generation

Synthetic pcap generation using `pcap_open_dead` + `pcap_dump_open` — no live network required.

Produces **100 packets total**: 40 legit and 60 malicious, interleaved in a 4:6 ratio per 10-packet block.

**Legit packets (40):**
- HTTP GET, POST, PUT, HEAD on TCP port 80
- HTTP GET, POST on TCP port 443
- DNS A-record queries on UDP port 53

**Malicious packets (60):**
- HTTP payload sent to UDP port 53 (protocol impersonation)
- DNS binary header sent to TCP port 80
- Invalid HTTP method (`BADVERB`)
- HTTP request missing Host header
- Empty payload on HTTP port
- HTTP request missing version string
- Truncated DNS header (4 bytes, below the 12-byte minimum)

---

## Protocol Validation

- **HTTP validator:** checks protocol (TCP), port (80/443), method, HTTP version, Host header, and header structure
- **DNS validator:** checks protocol (UDP/TCP), port (53), minimum header length (12 bytes), QDCOUNT > 0, and valid label-prefixed question name

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
- 18 individual test cases (happy path, negative, and edge cases)
- `tests/run_tests.sh` entry point for CI

---

## CI

GitHub Actions pipeline: builds the Docker image, runs the test suite, and prints a gcov coverage summary.
