# mvfst HTTP/3 adapter audit for Paper-v1

Audit date: 2026-08-31. This records the adapter that was built and exercised on
the Linux experiment host. It does not make the adapter an upstream mvfst
application and does not replace the remaining shaped-network preflight.

## Frozen identity

- Transport base: `80168ffa14efcb5c5dd662cec82682e78788f8b3`
  (`v2026.08.03.00`).
- Paper identity: `mvfst + paper-v1 minimal H3 adapter`.
- Adapter kind: `minimal-native-h3` (not Proxygen/HQ).
- Base-to-adapter binary-diff SHA-256:
  `7aa116ff44894b79d067979ba46f1fbe3b5d49b5dcae457f60c21a5ffef86437`.
- Linux verification branch/head: `agent/paper-v1-h3-port` at
  `0370083d44f629dfc928f88d123bfec183aa6c55`.
- Linux worktree was clean after that commit.
- Verified binary SHA-256:
  `1809b56f5ad7712e32841f6333ea9a0e79f8b82990a5b492ce8d53c3073ff460`.
- Build command: `cmake --build /home/ioio33/mvfst-h3-build --target echo -j2`.
- Toolchain: CMake 3.22.1, Ubuntu GCC 11.4.0, Ubuntu 22.04 x86-64.

The local macOS isolation branch has different commit IDs because the same
patch was reconstructed locally, but its base-to-head binary diff has the same
SHA-256. The patch hash, not the workstation-local commit ID, is the portable
adapter identity.

## Patch classification

| File | Class | Effect |
|---|---|---|
| `quic/samples/echo/EchoHandler.h` | H3 application + telemetry | Parses the fixed GET contract, emits QPACK/HEADERS, streams bounded DATA frames, records body and transport samples. |
| `quic/samples/echo/EchoServer.h` | Application launcher + telemetry | Supplies the reusable response chunk, configures CC/pacing/batching, qlog and graceful shutdown. |
| `quic/samples/echo/main.cpp` | Application CLI | Adds the Paper-v1 H3, CC, pacing, response-size and runtime-report contract. |
| `quic/samples/echo/EchoTransportServer.h` | Application build compatibility | Updates the sample transport construction for the pinned mvfst API. |
| `quic/samples/CMakeLists.txt` | Build glue | Links the dependencies used by the adapter. |

No file under mvfst congestion control, loss recovery, ACK processing, packet
scheduling or pacing implementation is changed. The adapter selects existing
mvfst CC and pacing controls and reads their runtime state; it does not alter
those mechanisms. Legacy tperf/ACK_FREQUENCY modifications are not present in
this clean branch or binary.

## Workload behavior verified on Linux

- ALPN `h3`, HTTP/3 status 200 and exact decoded body length were verified with
  the quic-go ACK-policy client.
- A single request for exactly 1 GiB completed without allocating a 1 GiB
  response buffer. The server reuses a 64 KiB source chunk and queues DATA only
  from stream write-ready callbacks.
- The 1 GiB loopback smoke produced exactly 1,073,741,824 decoded body bytes;
  observed server RSS stayed approximately 15--18 MiB.
- Two concurrent connections with distinct local UDP ports completed exact
  16 MiB responses under opposite receiver-policy assignments; the server
  produced two distinct qlogs and two transport-ready events.
- CUBIC off/on, NewReno off/on and BBR-on completed H3 downloads. Requested and
  active CC agreed; no fallback was observed. BBR-off is rejected at startup.
- CUBIC-on and BBR-on showed non-zero runtime pacing interval samples. The
  short loopback NewReno-on smoke initialized pacing but did not show a
  non-zero interval, so it is not an effective-pacing certification.
- SIGTERM stopped the server with exit status zero and no abort stack trace.
- Client and server qlogs, server transport/H3 events, exact body counters and
  the requested server configuration JSONL were produced.

## Deliberate scope and remaining differences

This is a narrow experiment adapter, not a general-purpose browser server. Its
QPACK/request decoder accepts the request pattern emitted by the pinned
quic-go client and its response encoder uses a minimal static representation.
It does not implement the breadth of Proxygen/HQ: dynamic QPACK tables,
arbitrary methods and request bodies, priority, WebTransport, push, or a
production HTTP routing stack. Therefore the paper must identify it exactly as
`mvfst + paper-v1 minimal H3 adapter`, never as upstream mvfst H3 or Proxygen.

The following gates are still open:

1. Run the four paper cells (NewReno off, CUBIC off/on, BBR on) under the actual
   20 Mbps shared bottleneck and 50 ms RTT, once for every policy pair.
2. Derive effective pacing, application/flow-control limitation and body
   goodput from artifacts rather than accepting requested configuration.
3. Verify two-connection mapping and ACK behavior from pcap plus both endpoint
   qlogs, including transition boundary, batch, spacing, delay and trigger.
4. Convert the adapter's per-connection transport events into the canonical
   `sender-runtime-v1.0.0` final record expected by the fail-closed validator.
5. Freeze the final binary, runtime libraries, kernel/offload state and checksums
   after shaped-network preflight. A rebuild requires a new binary identity.

Until those gates pass, mvfst-H3 is implementation-complete enough for Linux
preflight, but it is not admitted to the formal Paper-v1 corpus.
