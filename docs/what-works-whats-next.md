# What Works / What's Next

## What Works (Alpha-Beta Release)

### End-to-End Pipeline
The full vertical slice is operational:
`traffic_gen` → `data/capture.pcap` + `data/ground_truth.txt` → `feature_extract` → `http_validator` / `dns_validator` → `detector` → `results.log` + `metrics.csv` + `summary.json`

`make up && make demo` runs on a fresh clone in under 5 minutes.

### Traffic Generation
Synthetic pcap generation using `pcap_open_dead` + `pcap_dump_open` — no live network required.
Produces 4 legit packets (2 HTTP GET/POST, 2 DNS queries) and 6 malicious packets:
- HTTP payload on UDP port 53 (protocol impersonation)
- DNS binary on TCP port 80
- Invalid HTTP method
- HTTP missing Host header
- Empty payload on HTTP port
- Truncated DNS header

### Protocol Validation
- HTTP validator: checks protocol (TCP), port (80/443), method, HTTP version, Host header, header structure
- DNS validator: checks protocol (UDP/TCP), port (53), minimum header length (12 bytes), QDCOUNT > 0, valid label-prefixed question name

### Detection & Metrics
- Binary classifier: packet flagged if both validators reject it
- TP/FP/TN/FN computed against ground truth
- Detection rate, false positive rate, and accuracy exported to `summary.json`
- Per-packet results exported to `metrics.csv`

### Observability
- Timestamped per-packet log at `artifacts/release/results.log`
- No raw payload bytes written to disk (privacy/security invariant)

### Hardening
- Non-root Docker execution (`USER appuser`)
- Pcap path traversal prevention in `main.c`
- Bounded packet generation (`MAX_PACKETS = 100`)
- Localhost-only synthetic traffic

### Testing
- 4 test modules covering all core components
- 18 individual test cases including happy path, negative, and edge cases
- `tests/run_tests.sh` entry point for CI

### CI
- GitHub Actions pipeline: builds Docker image, runs test suite, prints gcov coverage summary

---

## What's Next (Week 16 — Final Release)

- **Larger evaluation dataset:** expand to 50–100 packets with a wider variety of attack types to generate statistically meaningful detection rates
- **PCAP from real tools:** supplement synthetic traffic with captures from `curl` and `dig` to validate against real protocol behaviour
- **Charts:** generate detection rate / FP rate bar charts from `metrics.csv` using Python/matplotlib and commit to `artifacts/release/`
- **Final results section:** replace `docs/results-draft.md` with a complete analysis including comparison against the 85% / 15% targets
- **DNS-over-TCP support:** the DNS validator currently accepts TCP/53 but the feature extractor doesn't distinguish DNS-over-TCP framing — improve handling
- **Demo video:** record and link a ≤2 minute screen capture of the full pipeline running
