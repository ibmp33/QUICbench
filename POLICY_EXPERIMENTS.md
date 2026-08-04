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
