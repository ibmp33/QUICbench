# QUICbench Paper Dataset v1 workflow

Paper-v1 is an all-HTTP/3, fail-closed dataset workflow. Legacy configs and old
mvfst tperf/raw-QUIC artifacts remain on disk but are not discoverable by the
Paper-v1 exporter.

## Frozen design

- 11 sender/CC/pacing paths, including four
  `mvfst + paper-v1 minimal H3 adapter` paths.
- Four receiver policy pairs in role order: Neqo/Neqo, Chrome/Chrome,
  Neqo/Chrome, Chrome/Neqo.
- Per-path repetitions: ten for CUBIC and Reno/NewReno, five for exploratory
  BBR. This produces 400 baseline-network runs.
- Two anchor paths, three additional loss-free network profiles and five
  repetitions produce 120 core network-sensitivity runs.
- Every profile fixes configured loss, jitter and intentional reordering to
  zero. Paper-v1 contains no active-loss appendix.
- One 30 s run, 5–25 s measurement window, one shared server process/listening
  port, two independent client local ports/connections, one long H3 stream per
  connection and at least 1 GiB available per response.
- Client-decoded H3 body bytes are the goodput numerator. tperf counters are
  invalid for this suite.

## Canonical commands

```bash
cp configs/paper-v1/local.example.json /absolute/private/location/local.json
scripts/paper_v1_plan --repetitions 1
scripts/paper_v1_plan --suite sensitivity
scripts/paper_v1_plan --suite all
scripts/paper_v1_preflight --local-config /absolute/private/location/local.json
sudo -E scripts/paper_v1_smoke --local-config /absolute/private/location/local.json
scripts/paper_v1_plan
scripts/paper_v1_validate /absolute/path/to/one/attempt
scripts/paper_v1_export /absolute/path/to/dataset /absolute/new/export/path
```

`plan --repetitions 1` prints the 44 Linux smoke attempts: one for each of
11 paths × four policy pairs. It does not start them. The default full plan
prints 400 baseline-network identities, `--suite sensitivity` prints 120, and
`--suite all` prints 520 (400 baseline plus 120 loss-free sensitivity runs).
Planning never starts collection implicitly.

`paper_v1_smoke` is the minimal end-to-end Linux gate. It executes five-second
attempts for all 11 paths × four ordered policy pairs, validates every attempt,
and writes an incremental JSON summary under `dataset_root/_smoke_reports`.
It returns zero only when all 44 cells are valid. Use `--resume` after an
interruption to skip cells that already have a `completed_valid` smoke attempt;
use repeated `--path-id` arguments to test selected paths while developing.
These attempts are always marked non-paper-eligible and cannot enter exports.

The exact queue byte counts in `configs/paper-v1/matrix.json` are normative.
The historical `q0p5`/`q2` strings are profile labels, not values that the
runner may recompute from an implicit BDP convention. At 20 Mbps and 50 ms
total RTT, 0.5 BDP is 62,500 bytes. The reverse path has propagation delay but
no bandwidth limiter. Any configured loss, jitter, or intentional reordering
is rejected before network setup.

Build manifests are generated explicitly. mvfst-H3 needs an extra metadata
file containing `application_identity`, `h3_adapter_kind`, `transport_commit`
and `h3_adapter_patch_sha256`. The adapter is deliberately minimal and native
to this pinned mvfst tree; it is not Proxygen/HQ and must not be described as
an upstream mvfst application:

```bash
python3 -m paper_v1.cli build-manifest \
  --component-id mvfst-h3 \
  --repository /absolute/path/to/mvfst \
  --binary /absolute/path/to/mvfst-paper-v1-h3-server \
  --build-command 'record the exact reproducible build command' \
  --build-flag paper-v1-h3-adapter \
  --supported-cc newreno --supported-cc cubic --supported-cc bbr \
  --pacing-control runtime-toggle \
  --expected-effective-pacing runtime-verified \
  --workload-protocol http3 \
  --metadata-json /absolute/path/to/mvfst-h3-metadata.json \
  --output /absolute/path/to/build-manifests/mvfst-h3.json
```

## Attempt lifecycle and retries

Each attempt has a unique immutable `attempt_id` and atomic manifest state:
`created → preflight_passed → running → collecting → validating →
completed_valid|completed_invalid`. Start/runtime/collection/validation failures
and interrupts are terminal. A retry creates a new attempt, points `supersedes`
to the old attempt and never overwrites it.

The runner records exact argv, PID, monotonic start/end, exit code, termination
reason and stdout/stderr for the server, both clients and capture. Cleanup acts
only on owned PIDs. A missing process, nonzero client exit, residual process,
empty artifact or checksum mismatch is a hard validation issue.

## Validation gates

Requested configuration, runtime-reported behavior and validator conclusions
are separate manifest sections. Eligibility requires:

1. Exact two-flow policy mapping and one initialization identity per connection.
2. Valid state transitions/ACK episodes; no ACK_FREQUENCY event.
3. H3 ALPN/status/headers/body and two distinct client ports/connections.
4. Requested CC equals active CC, no fallback, effective pacing matches the
   matrix, and paced cells show initialization plus callback/tick evidence.
5. Before/active/after qdisc and offload evidence; shared saturated bottleneck,
   both flows active, valid start skew and no application limitation in-window.
6. Client and sender qlog, pcap/keylog where configured, process logs, metrics,
   system metadata and checksums.
7. pcap/qlog-derived ACK batch, spacing, delay and transition results agree with
   receiver JSONL, including ACK-delay units.

Only attempts listed explicitly in `dataset_manifest.json` are exported. The
exporter does not scan by filename or modification time and rejects any schema
other than `quicbench-paper-v1`.

Illustrative field layouts are in `docs/EXAMPLE_PAPER_V1_RUN_MANIFEST.json`,
`docs/EXAMPLE_PAPER_V1_POLICY_TRANSITION.jsonl`, and
`docs/EXAMPLE_PAPER_V1_ACK_EPISODE.jsonl`. The manifest example intentionally
omits the long process/artifact inventory and is not itself validator input.

The first Linux network-only evidence and its qdisc-counter interpretation are
recorded in `docs/PAPER_V1_NETWORK_PREFLIGHT.md`.

## Formal-run hold

Do not start the 400-run baseline corpus until all 44 Linux smoke attempts
pass, the four mvfst-H3 configurations pass all H3/CC/pacing/wire/artifact
gates, and the operator explicitly authorizes formal collection. Run the 120
loss-free network-sensitivity attempts only after the baseline corpus and its
network evidence pass. Paper-v1 does not schedule an active-loss suite.
