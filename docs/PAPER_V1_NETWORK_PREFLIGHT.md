# Paper-v1 Linux network preflight

Date: 2026-08-31. Host: `ioio33-OptiPlex-Tower-Plus-7010`, Ubuntu 22.04.4,
kernel 6.8.0-87-generic. QUICbench commit: `58613e2`.

This was a short namespace/iperf3 network validation. It did not run an H3
sender path and is not a paper performance result.

## Baseline profile

The explicit `base_20m_50ms_q0p5_loss0` profile produced:

- `veth-host`: 25 ms netem plus ingress redirect, with no reverse TBF;
- `ifb0`: 25 ms netem plus one shared 20 Mbit/s TBF;
- TBF burst: 10,000 bytes;
- TBF reported latency: 46 ms, corresponding to the configured 125,000-byte
  limit: `2,500,000 B/s × 0.046 s + 10,000 B = 125,000 B`;
- steady ping RTT: 50.3–50.5 ms;
- two forward iperf3 streams: 20.5 Mbit/s aggregate sender rate;
- two reverse iperf3 streams: 930 Mbit/s aggregate sender rate, confirming
  that the reverse path was not capped at 20 Mbit/s.

The first ping was 75.5 ms while neighbor/path state warmed up. Steady samples,
not the first probe, must be used for the RTT gate.

## Optional appendix: forward-only 0.1% random loss

This profile is an implementation micro-test and an optional appendix
treatment. It is not part of the core main or network-sensitivity plan and does
not block core corpus admission.

The `loss0p1_20m_50ms_q0p5` profile installed `loss-random.loss=0.001` only on
the forward `ifb0` netem. The reverse netem contained no loss rule.

A 10-second, 20 Mbit/s UDP probe sent 20,832 datagrams. Qdisc counters showed:

- parent forward netem total drops: 599;
- child TBF queue drops: 580;
- netem-only random drops: 19;
- inferred injected random loss: `19 / 20,832 = 0.091%`.

The validator must not interpret the parent netem total-drop counter as random
loss. For this hierarchy, injected-loss evidence is the parent drop delta minus
the child TBF drop delta; queue drops and injected random loss must be reported
separately.

## Cleanup result

After the probe, both namespaces, both veth pairs, `ifb0`, its qdiscs and the
two test-specific FORWARD rules were removed. Physical interfaces retained only
their pre-existing qdiscs.

## Remaining gates

This preflight validates the network primitive only. Paper-v1 still requires a
canonical runner, bidirectional ACK-visible capture, per-run qdisc counter
deltas, H3 body-byte metrics and sender-specific CC/pacing/runtime preflights.
