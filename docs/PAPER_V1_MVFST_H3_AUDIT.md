# mvfst HTTP/3 patch audit for Paper-v1

Audit date: 2026-08-31. This document records the local source evidence; it does
not certify a Linux binary or a completed H3 preflight.

## Identity and finding

- Base mvfst commit: `80168ffa14efcb5c5dd662cec82682e78788f8b3`.
- Required Proxygen commit: `db21b21a4f98524e68e775aa11a70db0f5bc057a`.
- Paper identity: `mvfst + paper-v1 H3 adapter`.
- Current mvfst branch: `main` and dirty.
- No local Proxygen checkout or HQ executable was found during the audit.
- The H3 adapter source/diff is therefore not present and cannot yet be
  certified. mvfst itself is the QUIC transport; its maintained HTTP/3 path is
  through Proxygen, as stated by the [mvfst project](https://github.com/facebook/mvfst)
  and [Proxygen project](https://github.com/facebook/proxygen).

The previously mentioned custom echo/H3 commits `e5009bb9` and `e7918e5f`
could not be resolved from the local repository. They are not accepted as build
identity without recoverable commit objects and a reviewed diff.

## Complete local file classification

### H3 contract / application launcher (untracked, not adapter source)

| File | Classification | SHA-256 after this audit |
|---|---|---|
| `experiments/h3/versions.env` | Pinned dependency contract | `a7d72eaa703dbe2aad79b4341597b64d485e82b8f85d6d7ddfae42a59320a7d0` |
| `experiments/h3/preflight.sh` | Fail-closed identity/preflight wrapper | `6ad7aa1ff53b7ac3f82fc812232e0b49f9719ec4889a155893c5c9353dbe8fca` |
| `experiments/h3/run_h3_server.sh` | HQ server launcher/workload contract | `97257d1466b348283b0d564bd1f4743d7f8d6a1361b595f7fff3c8650b3958c7` |
| `experiments/h3/README.md` | Documentation | `cd645c13670cf920469ac69a5c69820c3f5af33e16675570f247edbd9bb15132` |

These files select H3 and demand custom runtime-report flags. They do not
implement HTTP/3, QPACK, response streaming, controller selection, recovery or
pacing.

### Transport experiment modifications (tracked dirty diff; excluded)

| File | Classification |
|---|---|
| `quic/tools/tperf/TperfServer.cpp` | tperf ACK_FREQUENCY transport experiment |
| `quic/tools/tperf/TperfServer.h` | tperf ACK_FREQUENCY state/configuration |
| `quic/tools/tperf/tperf.cpp` | tperf ACK_FREQUENCY CLI/configuration |

The combined binary diff SHA-256 is
`f34435558d899a2dc1007fd930df0fe9b4c50dde4a17895aee77d6ceb984cf37`.
It changes receiver ACK processing behavior and must not enter an H3 Paper-v1
transport build. It is legacy/transport-experiment work, not application glue.

`collect_build_env_mvfst.sh` is untracked provenance tooling and not runtime
transport or application code.

## Required patch split

Before a valid mvfst-H3 build, use three independent identities:

1. A minimal Proxygen/HQ H3 application adapter: numeric path, status/headers,
   bounded streaming of at least 1 GiB, one process/port and two connections.
2. Necessary telemetry only: requested/active CC, fallback, pacing configured
   and effective, pacer init/ticks, ICW, flow-control/application-limited state,
   H3 body counters, commit and binary identity.
3. Any transport experiment change: separate commit/patch, excluded from the
   canonical H3 build unless explicitly made a matrix treatment.

The build manifest must record each commit/patch SHA separately. A dirty hash
is permitted only for a canary and is never paper eligible.

## Four required mvfst-H3 cells and gates

| CC | Requested pacing | Required runtime result |
|---|---:|---|
| NewReno | off | active NewReno, unpaced |
| CUBIC | off | active CUBIC, unpaced |
| CUBIC | on | active CUBIC, pacer initialized and ticks observed |
| BBR | on | active BBR, no fallback, pacer initialized and ticks observed |

There is deliberately no BBR-off cell. A BBR→CUBIC fallback or absent pacing
evidence invalidates the run.

## Current disposition

The matrix and launcher route mvfst through H3, and old tperf/raw-QUIC is marked
legacy. However, all 16 mvfst Linux preflights (four cells × four policy pairs)
remain blocked until the actual Proxygen adapter patch, clean source identities,
build command/toolchain, executable HQ hash and runtime telemetry are supplied.
This is an explicit failed-preflight condition, not a silent fallback to raw
QUIC.
