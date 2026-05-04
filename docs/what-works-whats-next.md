# What Works / What's Next

## What Works

The full end-to-end pipeline is complete:

`traffic_gen` -> `data/capture.pcap` + `data/ground_truth.txt` -> `feature_extract` -> `http_validator` / `dns_validator` -> `detector` -> `results.log` + `metrics.csv` + `summary.json`

`make up && make demo` builds/runs the system and reproduces the main result.

---

## Traffic Generation

Synthetic pcap generation works without live network traffic. The generator uses `pcap_open_dead` and `pcap_dump_open`, so packets are written directly to `data/capture.pcap`.

The final dataset contains 1000 packet:

- 850 legitimate packets
- 150 malicious packets
- 17:3 legit-to-malicious ratio per 20-packet block

---

## Protocol Validation

The HTTP validator checks protocol, port, payload presence, null bytes, method, HTTP version, Host header, header structure, and duplicate `Content-Length`.

The DNS validator checks protocol, port, minimum header length, QR bit, QDCOUNT, question-name structure, label length, and QTYPE.

The detector classifies a packet as malicious when both validators reject it.

---

## Final Results

The final demo result is:

| Metric | Result |
|---|---:|
| Packets processed | 1000 |
| True positives | 150 |
| False positives | 0 |
| True negatives | 850 |
| False negatives | 0 |
| Detection rate | 100.0% |
| False positive rate | 0.0% |
| Accuracy | 100.0% |
| Processing time | 23.58 ms |

Evidence artifacts are stored in `artifacts/release/`, including `results.log`, `metrics.csv`, `summary.json`, and the result charts.

---

## Hardening

- Docker runs the detector as non-root `appuser`
- Pcap path validation rejects traversal attempts
- Raw payload bytes are not written to logs
- Synthetic traffic stays localhost-only
- Malicious packets are written to a pcap file, not transmitted live

---

## Testing And CI

The test suite covers the HTTP validator, DNS validator, detector, and feature extractor. The Docker test target passes with 4 test binaries and 0 failures.

GitHub Actions builds the Docker image, runs the unit tests, and prints a coverage summary.

---

## What's Next

- Test against real benign captures from `curl`, browser traffic, `dig`, and `nslookup`
- Add deeper HTTP/DNS parsing and clearer HTTPS/TLS separation
- Add connection-level or flow-level analysis for repeated suspicious behavior
