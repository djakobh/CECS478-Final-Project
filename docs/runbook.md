# Runbook — Protocol Impersonation Detection System

## Prerequisites

- Docker Desktop (or Docker Engine + Docker Compose v2)
- Make
- Git

Tested on Ubuntu 22.04 and macOS 14. Windows users should use WSL2.

---

## Fresh Clone & Full Run

```bash
git clone https://github.com/djakobh/CECS478-Final-Project.git
cd CECS478-Final-Project
make up      # builds image + generates synthetic pcap
make demo    # runs detector pipeline, prints results
```

Expected output from `make demo`:

```
=== Protocol Impersonation Detection — Results ===
Packets processed : 100
Parse errors      : 0
True  Positives   : 60
False Positives   : 0
True  Negatives   : 40
False Negatives   : 0
Detection rate    : 100.0%
False positive    : 0.0%
Accuracy          : 100.0%
Processing time   : X.XX ms
Log               : artifacts/release/results.log
Metrics CSV       : artifacts/release/metrics.csv
Summary JSON      : artifacts/release/summary.json
```

The dataset is 100 packets — 40 legit and 60 malicious, interleaved in a 4:6 ratio per 10-packet block.

---

## Running Tests

```bash
make test
```

Runs all four unit test binaries inside the container via `tests/run_tests.sh`. All tests must pass.

---

## Coverage Report

```bash
make coverage
```

Recompiles with `-fprofile-arcs -ftest-coverage`, runs the test suite, then prints a `gcov` coverage summary to stdout.

---

## Rebuild from Scratch

```bash
make clean   # removes containers, images, volumes
make up
make demo
```

Total time on a clean machine: under 5 minutes (mostly Docker image pull).

---

## Output Artifacts

After `make demo`, these files are written:

| File | Description |
|---|---|
| `artifacts/release/results.log` | Timestamped per-packet log |
| `artifacts/release/metrics.csv` | Per-packet verdict table |
| `artifacts/release/summary.json` | Aggregate detection metrics |
| `data/capture.pcap` | Generated synthetic pcap |
| `data/ground_truth.txt` | Ground truth labels (0=legit, 1=malicious) |

---

## Troubleshooting

**`make up` fails with "permission denied" on data/**
Run `chmod 777 data/` on the host before `make up`.

**Docker build fails on libpcap**
Make sure you have internet access during the build — the Dockerfile installs `libpcap-dev` via apt.

**`make demo` reports "cannot open ground_truth file"**
Run `make up` first. It generates `data/ground_truth.txt` before the detector can use it.
