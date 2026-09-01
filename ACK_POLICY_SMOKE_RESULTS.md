# Modeled ACK policy smoke results

Date: 2026-08-31. Environment: macOS loopback, quic-go HTTP/3 server, two
concurrent 4 MiB downloads per pair. This is a functional/wire-observability
smoke, not a paper network-condition result.

## Commands

Build:

```sh
go build -o /tmp/quic-ack-smoke/bin/ack-policy-client ./example/ack-policy-client
go build -o /tmp/quic-ack-smoke/bin/h3-server ./example/server
```

Each endpoint in a pair used the same command shape; only `POLICY`, `FLOW`, and
the fixed local port differ:

```sh
/tmp/quic-ack-smoke/bin/ack-policy-client \
  -protocol http3 -url https://127.0.0.1:6121/16m.bin -insecure \
  -duration 3s -max-bytes 4194304 \
  -ack-policy POLICY \
  -metrics /tmp/quic-ack-smoke/FLOW/metrics.csv \
  -ack-policy-log /tmp/quic-ack-smoke/FLOW/events.jsonl \
  -qlog-dir /tmp/quic-ack-smoke/FLOW/qlog
```

The four concurrent pairs were:

```text
real1: neqo-like-ack   / neqo-like-ack
real2: chrome-like-ack / chrome-like-ack
real3: neqo-like-ack   / chrome-like-ack
real4: chrome-like-ack / neqo-like-ack
```

Capture and validation:

```sh
tcpdump -i lo0 -n udp port 6121 -w /tmp/quic-ack-smoke/four-pairs-real.pcap
python3 scripts/validate_ack_policy_smoke.py /tmp/quic-ack-smoke \
  --output /tmp/quic-ack-smoke/validation.csv
```

## Results

All eight clients returned status 200, read 4,194,304 bytes, and exited 0. The
pcap contains 29,367 captured UDP packets. The validator matched every
implementation-side ACK episode to an application-space ACK frame in qlog,
including largest-acked and encoded ACK delay.

| Pair/flow | Policy | Transition PN | Intent ACKs = qlog ACKs | Largest match | Median batch | P90 batch | Median spacing (us) | P90 delay (us) | Pass |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| real1/a | neqo-like | — | 548=548 | 548/548 | 4.5 | 11 | 47.709 | 22.375 | yes |
| real1/b | neqo-like | — | 611=611 | 611/611 | 4 | 10 | 36.708 | 18.500 | yes |
| real2/a | chrome-like | 100 | 187=187 | 187/187 | 16 | 32 | 164.688 | 65.500 | yes |
| real2/b | chrome-like | 100 | 198=198 | 198/198 | 15 | 32 | 148.208 | 66.792 | yes |
| real3/a | neqo-like | — | 529=529 | 529/529 | 4 | 13 | 44.792 | 21.958 | yes |
| real3/b | chrome-like | 100 | 233=233 | 233/233 | 12 | 28 | 130.667 | 39.125 | yes |
| real4/a | chrome-like | 100 | 236=236 | 236/236 | 12 | 22 | 137.625 | 28.500 | yes |
| real4/b | neqo-like | — | 506=506 | 506/506 | 4 | 12 | 41.917 | 19.291 | yes |

Batch size can exceed the decision threshold because more datagrams may be
processed before the already-queued ACK is serialized. This is exactly why the
wire qlog/pcap check is retained rather than treating a configured ratio as the
observed process.

## Example manifest fragment

```json
{
  "ack_policy_config_schema_version": 2,
  "flows": [{
    "flow_id": "flow_a",
    "ack_policy": "chrome-like-ack",
    "ack_policy_config": {
      "policy_name": "chrome-like-ack",
      "policy_version": "1.0.0",
      "state_scope": "per-connection-per-packet-number-space",
      "initial_threshold": 2,
      "steady_threshold": 10,
      "switch_after_packet_number_advance": 100,
      "transition_boundary": "ack_instigating_pn>=least_observed_pn+100",
      "max_ack_delay_ms": 25,
      "timer_rule": "initial:25ms; steady:max(1ms,min(25ms,min_rtt/4))"
    },
    "ack_policy_event_log": ".../ack-policy-events.jsonl",
    "client_qlog_path": ".../qlogs/client",
    "server_qlog_path": ".../qlogs/server"
  }],
  "pcap_path": ".../packets.pcap"
}
```

## Example policy events

```json
{"event":"policy_transition","policy_name":"chrome-like-ack","policy_version":"1.0.0","packet_number":100,"packet_number_space":"application_data","old_state":"initial-ack-every-2","new_state":"decimated-ack-every-10","monotonic_time_ns":3111041,"reason":"packet-number-reached-peer-first-plus-100","threshold":10}
{"event":"ack_episode","policy_name":"chrome-like-ack","policy_version":"1.0.0","packet_number":3253,"packet_number_space":"application_data","monotonic_time_ns":44573458,"reason":"threshold","trigger":"threshold","ack_batch_size":10,"ack_spacing_ns":109542,"ack_delay_ns":8292,"threshold":10}
```

The remote Ubuntu/netem rerun on `58.206.207.226` was not performed because SSH
authentication currently fails (`Permission denied (publickey,password)`).
That rerun remains required before promoting these smoke observations to paper
data.
