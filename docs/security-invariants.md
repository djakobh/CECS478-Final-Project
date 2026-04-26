# Security Invariants

These are the security properties the system guarantees. None of them should be broken by future changes.

---

## 1. Non-Root Execution

All application code runs as `appuser`, not root.

The Dockerfile creates a non-privileged user with `useradd -m appuser` and switches to it before the container starts. This limits the damage if someone exploits a bug in the packet parsing code.

---

## 2. Pcap Path Validation

The detector only opens pcap files whose path starts with `data/` or `/app/data/` and contains no `..` sequences.

This check lives in `src/main.c::path_is_safe()`. An invalid path causes an immediate exit with an error message. It's a safeguard against path traversal if the binary is ever called with untrusted arguments.

---

## 3. No Raw Payload Bytes Written to Log

Packet payloads are never written to `artifacts/release/results.log` or any output file.

The logger (`src/logger.c`) only records metadata: packet index, protocol, ports, payload *length*, predicted verdict, and ground truth verdict. This ensures payload content (like credentials in HTTP bodies) can't leak through the log.

---

## 4. Bounded Packet Generation

`traffic_gen` writes exactly `TOTAL` (100) packets, defined as a compile-time constant at the top of `src/traffic_gen.c`.

This keeps the synthetic dataset at a fixed size and prevents runaway pcap files from filling disk.

---

## 5. Localhost-Only Traffic

All synthetic traffic uses `127.0.0.1` as both source and destination IP.

The traffic generator hardcodes `src = dst = 127.0.0.1` in every frame. No real network interfaces are used — nothing is sent over the network.

---

## 6. Malicious Packets Stay in the Pcap File

Malicious packet payloads are written to a pcap file, not sent over any real network socket.

The traffic generator uses `pcap_open_dead` + `pcap_dump_open`, which is a write-only pcap API that never touches a network interface. The "attacks" only exist inside the `.pcap` file.
