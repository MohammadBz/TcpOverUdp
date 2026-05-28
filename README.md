# TcpOverUdp — Reliable TCP-like Transport over UDP (with Encryption)

## Project Overview

This project was developed for a Computer Networks course as a hands-on implementation of TCP concepts on top of UDP. It demonstrates a user-space reliable transport with a three-way handshake, sequence/acknowledgment handling, retransmission logic, flow/congestion control, and optional ECDH+AES payload encryption.

## Tech Stack

- **Language:** Python (3.x)
- **Cryptography:** PyCryptodome (`Crypto` package used for AES, ECC, SHA256)
- **Standard Library:** `socket`, `threading`, `queue`, `json`, `time`, `random`

## Key Features

- **Reliable transport over UDP:** Sequence numbers, acknowledgments, retransmissions, and FIN/RST semantics.
- **Secure key exchange & encryption:** ECDH key exchange (P-256) to derive a 256-bit AES key and AES-CBC encryption of payloads.
- **Adaptive retransmission (RTO):** RTT sampling with SRTT/DevRTT and adaptive RTO updates.
- **Flow & congestion control:** Receiver window (rwnd), send window, congestion window (`cwnd`) and slow-start threshold (`ssthresh`).
- **Test harnesses:** Dedicated test folders for retransmission, fast-retransmit, and accumulative-ack scenarios.

## Getting Started

Prerequisites

- **Python 3** (any modern 3.x interpreter). The codebase uses only standard Python APIs plus PyCryptodome.
- **pip** to install third-party packages.

Installation

1. Create and activate a virtual environment (recommended).

   - Windows (PowerShell):

     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```

   - macOS / Linux:

     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

2. Install required package:

   ```bash
   pip install pycryptodome
   ```

Run Locally

- Start the server (listens on 127.0.0.1:12346 by default):

  ```bash
  python serverV3.py
  ```

- Run the example client to establish a connection, send an encrypted message, receive a response, and close:

  ```bash
  python clientV3.py
  ```

Notes

- The server and client scripts include ECDH key exchange and AES encryption; the console logs show packet-level events (SYN, ACK, FIN, payloads, window updates).
- If you want to run the test scenarios, each test folder contains server and client variants (e.g. `retransmission_test/retransmission_test.py`). Run those scripts similarly to exercise specific behaviors.

## Project Structure

```
├─ clientV3.py              # current client implementation (ECDH + AES, reliable transport)
├─ serverV3.py              # current server implementation (handshake, retransmit, flow/cwnd, encryption)
├─ README.md                # <-- this file
├─ accumulativeAck_test/    # test scenarios for cumulative ack behavior
│  ├─ clientV3.py
│  ├─ retransmission_test.py
  │  └─ serverV3.py
├─ fast_retransmit_test/    # fast retransmit testing scripts
│  ├─ clientV3.py
│  ├─ fast_retransmit_test.py
  │  └─ serverV3.py
└─ retransmission_test/     # retransmission-focused tests
   ├─ clientV3.py
   ├─ retransmission_test.py
   └─ serverV3.py
```

- **`serverV3.py`**: Server-side implementation with connection management, handshake, ECDH key exchange, AES helpers, adaptive RTO, retransmit watcher, flow and congestion control.
- **`clientV3.py`**: Client-side implementation performing handshake (SYN/SYN-ACK/ACK), ECDH key exchange, data encryption/decryption, retransmission and listener threads, and graceful closure.

## Logging & Debugging

- The code uses a `log_packet` helper to print packet details (source/destination ports, seq/ack, flags, payload, window). Use the console output during runs to follow protocol exchanges.

