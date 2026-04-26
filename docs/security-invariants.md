# Security Invariants

These invariants hold throughout the system and must not be broken by future changes.

---

## 1. Non-Root Execution

**Invariant:** All application code runs as `appuser`, never as root.

The Dockerfile creates a non-privileged user with `useradd -m appuser` and switches to it with
`USER appuser` before the container starts. This limits the blast radius if an attacker exploits
a parser vulnerability in the packet processing code.

---

## 2. Pcap Path Validation

**Invariant:** The detector will only open pcap files whose path starts with `data/` or
`/app/data/` and contains no `..` sequences.

Enforced in `src/main.c::path_is_safe()`. An invalid path causes an immediate exit with a
non-zero return code and an error message. This prevents path traversal attacks if the binary
were ever called with attacker-controlled arguments.

---

## 3. No Raw Payload Bytes Written to Log

**Invariant:** Packet payloads are never written to `artifacts/release/results.log` or any
output file.

The logger (`src/logger.c`) only writes metadata: packet index, protocol, ports, payload
*length*, predicted verdict, and ground truth verdict. This ensures that sensitive payload
content (e.g., credentials in HTTP bodies) cannot leak through the logging pipeline.

---

## 4. Bounded Packet Generation

**Invariant:** `traffic_gen` writes at most `MAX_PACKETS` (100) packets, defined as a
compile-time constant in `src/common.h`.

This prevents runaway pcap files from filling disk and acts as a rate-limiting control on
synthetic traffic output.

---

## 5. Localhost-Only Traffic

**Invariant:** All synthetic traffic uses `127.0.0.1` as both source and destination IP.

The traffic generator hardcodes `src = dst = 127.0.0.1` in all generated frames. No real
network interfaces are involved. This ensures no external systems are targeted and no
real network data is captured or transmitted.

---

## 6. Attack Scripts Affect Localhost Only

**Invariant:** Malicious packet payloads are written to a pcap file, not sent over any
real network socket.

The traffic generator uses `pcap_open_dead` + `pcap_dump_open` — a write-only pcap API
that never opens a network interface. Malicious payloads exist only within the `.pcap` file.
