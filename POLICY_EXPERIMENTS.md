# Neqo vs. Chromium ACK policy experiment

This experiment compares two receiver-side ACK policies implemented in the
same quic-go client binary. Both flows use the same server process, congestion
controller, object, path, duration, and synchronized request start.

## Scope

- Neqo abstraction: ACK every two ACK-eliciting application packets, at most
  20 ms delay, and immediately on observable reordering.
- Chromium abstraction: ACK every two packets initially; after the application
  packet number advances by 100, ACK every ten packets, with a timer bounded by
  `max(1 ms, min(max_ack_delay, min_rtt / 4))`.
- Both retain quic-go's existing loss/reordering and ECN safety triggers where
  applicable.
- ACK_FREQUENCY and IMMEDIATE_ACK control frames are intentionally out of scope.

The manifest parameter definitions are versioned in
`config/ack_policies_default.json`. Every flow records both the policy name and
the complete `ack_policy_config`; the client binary SHA256 and build commit bind
those declared parameters to the exact executable used by the run.

## Linux build

Build the policy client from the modified quic-go tree:

```sh
go build -trimpath \
  -ldflags "-X main.gitCommit=$(git rev-parse HEAD) -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o /home/ioio33/QUIC_project/bin/quic-go-policy-client \
  ./example/ack-policy-client
```

Keep the existing quic-go server binary at:

```text
/home/ioio33/QUIC_project/bin/quic-go-server
```

## Run order

Workloads are defined in `config/workloads_conf_default.json`. Adapter smoke
tests use the `smoke` profile; the main P0 campaign selects `fairness`, which
generates a 1 GiB target and runs for 60 seconds. A completed process is not by
itself a valid fairness sample: check `saturation_validation.valid` in
`run_manifest.json` or `saturation_valid` in `summary.csv`.

The main P0 matrix contains eight ordered pairs: fixed2/fixed2,
fixed10/fixed10, fixed2/fixed10, fixed10/fixed2, Neqo/Chromium,
Chromium/Neqo, Neqo/Neqo, and Chromium/Chromium. Reversed heterogeneous pairs
control for flow identity and client launch order.

First run the small qlog-enabled validation:

```sh
cd /home/ioio33/QUIC_project/QUICbench
chmod +x run_policy_experiments.sh
./run_policy_experiments.sh dry-run
./run_policy_experiments.sh validate
```

Inspect the summary columns `realized_ack_ratio` and
`mean_ack_interval_ms`. Chromium should show a materially larger realized ratio
after the first 100 packet numbers than Neqo. Do not expect either ratio to
equal the configured packet threshold: multiple packets can arrive while an
ACK is already queued, and timer, loss, reordering, and packet-writer
scheduling all affect the wire-observed ratio.

Only after this check passes, run the qlog-disabled main campaign:

```sh
./run_policy_experiments.sh main
```

The main matrix contains four network profiles: RTT 10/50 ms crossed with
0.5/1.0 BDP buffering at 20 Mbit/s. Each profile includes both cross-policy
orders and the Neqo-vs-Neqo and Chromium-vs-Chromium baselines.

## Primary outputs

- `avg_throughput_mbps`: downstream wire throughput from pcap.
- `app_goodput_mbps`: response-body goodput measured by each client.
- `share` and `jain_index`: competition outcome.
- `realized_ack_ratio` and `mean_ack_interval_ms`: qlog validation metrics.

The steady-state window is relative to each request's first client packet, not
to tcpdump startup. The clients bind fixed UDP ports and wait for the same Unix
timestamp before sending, allowing deterministic flow matching without qlog.

## P2F fixed-ratio mechanism extension

P2F isolates the ACK-threshold contribution from the Neqo/Chromium policy
state machines. It runs quiche and xquic with CUBIC, pacing enabled and
disabled, and the ordered fixed2/fixed10 pairs plus both homogeneous
baselines. Ten repetitions produce 160 runs. Pcap files are parsed and removed;
qlogs are retained only for the first repetition of each pair.

Start P2F after the existing P2 sender-mechanism suite has finished:

```sh
./scripts/run_overnight_fixed_ratio_mechanism.sh
```

To queue it safely while P2 is still running, use:

```sh
./scripts/queue_fixed_ratio_after_current.sh
./scripts/check_overnight_fixed_ratio_mechanism.sh
```

The queue refreshes the existing sudo authorization, waits for the current P2
launcher to exit, and starts P2F only when all eight P2 conditions are recorded
as successful. It does not use a fixed sleep interval and will not overlap the
two suites.

After P2F completes, calculate policy-centered fixed2 share, role sensitivity,
homogeneous fairness, pacing effects, and implementation differences:

```sh
python3 scripts/analyze_fixed_ratio_mechanism.py \
  /home/ioio33/QUIC_project/results
```
