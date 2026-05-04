# Security Invariants

These are the security properties the finished system relies on. Future changes should keep these intact.

---

## 1. Non-Root Execution

All application code runs as `appuser` and not the root level

The Dockerfile creates a non-privileged user with `useradd -m appuser` and switches to it before the container starts. This limits damage if packet parsing code ever mishandles malformed input.

---

## 2. Pcap Path Validation

The detector only opens pcap files whose path starts with `data/` or `/app/data/` and contains no `..` sequences.

This check lives in `src/main.c::path_is_safe()`. Invalid paths are rejected before analysis begins.

---

## 3. No Raw Payload Bytes Written to Logs

Packet payload bytes are not written to `artifacts/release/results.log`.

The logger records metadata only: packet index, protocol, ports, payload length, predicted verdict, ground truth verdict, and detection reason. This keeps the evidence useful without dumping raw packet contents.

---

## 4. Bounded Packet Generation

`traffic_gen` writes exactly `TOTAL` packets, currently `1000`, defined as a compile-time constant in `src/traffic_gen.c`.

The final generated dataset is 850 legitimate packets and 150 malicious packets. This fixed size keeps the demo reproducible and prevents runaway pcap generation.

---

## 5. Localhost-Only Synthetic Traffic

All generated packets use `127.0.0.1` as both source and destination IP.

The traffic is synthetic lab data and is not aimed at an external host.

---

## 6. Attacks Stay Inside The Pcap

Malicious payloads are written into `data/capture.pcap`, not sent over a real network socket.

The generator uses `pcap_open_dead` and `pcap_dump_open`, so the simulated attacks exist only as offline pcap evidence for the detector to analyze.
