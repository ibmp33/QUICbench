# Receiver ACK policy state machines

Status: modeled policies, version 1.0.0. These names intentionally say
`-like-ack`: they do not claim browser equivalence.

## Source pins

| Model | Primary reference | Pin | Relevant rules |
|---|---|---|---|
| `neqo-like-ack` | [Neqo `tracking.rs`](https://github.com/mozilla/neqo/blob/e2a2a7459b8b51778b50209251a61fc5ca020893/neqo-transport/src/tracking.rs) | `e2a2a7459b8b51778b50209251a61fc5ca020893` | `DEFAULT_LOCAL_ACK_DELAY`, `DEFAULT_ACK_PACKET_TOLERANCE`, `RecvdPackets::new`, `ack_now`, `set_received`, `immediate_ack` |
| `chrome-like-ack` | [QUICHE `quic_received_packet_manager.cc`](https://github.com/google/quiche/blob/38097a7a48d5f7d0853ec0ece88269c08283c9c7/quiche/quic/core/quic_received_packet_manager.cc) and [constants](https://github.com/google/quiche/blob/38097a7a48d5f7d0853ec0ece88269c08283c9c7/quiche/quic/core/quic_constants.h) | `38097a7a48d5f7d0853ec0ece88269c08283c9c7` | `GetMaxAckDelay`, `MaybeEnableAckDecimation`, `MaybeUpdateAckTimeout`, `HasNewMissingPackets`, decimation constants |

Chromium uses QUICHE, but this audit has not yet replayed the browser's complete
runtime configuration. Therefore the model is `chrome-like-ack`, not “Chrome”.

## State-machine comparison

| Rule | `neqo-like-ack` v1.0.0 | `chrome-like-ack` v1.0.0 |
|---|---|---|
| State scope | Per connection and per packet-number space | Per connection and per packet-number space |
| Initial / Handshake in this model | Every ACK-eliciting packet, zero intentional delay | Every ACK-eliciting packet, zero intentional delay |
| Application initial state | `application-delayed-ack`, threshold 2 | `initial-ack-every-2`, threshold 2 |
| Autonomous threshold change | None | One-way transition to `decimated-ack-every-10` |
| Exact boundary | N/A | On an ACK-instigating application packet where `pn >= least_observed_pn + 100`; the boundary packet uses threshold 10. Once enabled, a later lower reordered PN does not revert the state. |
| Application timer | First pending ACK-eliciting packet + 20 ms. ACK is also eligible once one smoothed RTT has elapsed since the previous ACK. | Initial: 25 ms. Decimated: `max(1 ms, min(25 ms, min_rtt / 4))`. Existing earlier deadline is retained. |
| Threshold trigger | `unacknowledged_count >= 2` (Neqo expresses this as tolerance 1 and `count > tolerance`) | `unacknowledged_count >= current threshold` |
| Reordering / gap | Immediate when ACK-eliciting PN differs from the next in-order PN, covering a forward gap or a backward fill | Default immediate ACK for the first four packets in the newest range after a new gap; filling an older reported gap is not a separate default trigger |
| ECN-CE | No additional immediate-ACK rule in the pinned receiver tracker | Immediate only on a transition from non-CE to CE, not on every CE packet |
| Explicit immediate signal | Pinned Neqo calls `immediate_ack` for PING and several connection-control paths | QUICHE `IMMEDIATE_ACK` sets ACK-now when that extension is enabled |
| ACK_FREQUENCY | Can change application tolerance, delay, and order handling; not part of the main modeled-policy runs | Can replace application threshold, delay, and reordering threshold; not part of the main modeled-policy runs |

The main four-pair runs keep ACK_FREQUENCY disabled so that the selected
receiver policy, rather than a sender request, controls the ACK process.

## Implemented transitions and observability

The implementation is in quic-go's
`internal/ackhandler/received_packet_tracker.go`. Each connection constructs its
own `ReceivedPacketHandler`; no package-global mutable policy state exists.

The client writes `ack-policy-events.jsonl`. A `policy_transition` record
contains packet number, packet-number space, old/new state, monotonic nanoseconds
from policy-state construction, reason, and resulting threshold. An
`ack_episode` contains the ACK-eliciting batch size, spacing since the previous
ACK, ACK delay relative to the largest observed packet, active threshold, and
the trigger (`threshold`, `timer`, `reordering`, `immediate-ecn-ce`,
`immediate-ack-frame`, or `opportunistic`). qlog and pcap remain independent wire
evidence; the JSONL file is implementation-side intent evidence.

## Known model/reference differences

1. The Chrome-like model uses quic-go's existing immediate Initial/Handshake
   ACK behavior. Pinned QUICHE instead uses its normal threshold machinery and
   adjusts crypto-space delayed-ACK timers (including 1 ms behavior). Application
   data is the modeled comparison space.
2. Neqo forces an immediate ACK for a received PING and some connection-close or
   lost-handshake-ACK paths. quic-go exposes explicit immediate-ACK handling but
   does not distinguish PING at the receiver ACK tracker, so those frame-specific
   paths are not reproduced.
3. QUICHE connection options can select a 1/8-RTT delay, unlimited decimation,
   or one immediate ACK after a gap. v1.0.0 models the pinned defaults: 1/4 RTT,
   threshold 10, and up to four immediate ACKs after a new gap.
4. ACK_FREQUENCY draft/version negotiation differs across Neqo, QUICHE, quic-go,
   and mvfst. Main modeled runs disable it; the existing mvfst-draft mode remains
   a separate interoperability treatment.
5. quic-go's scheduler can opportunistically coalesce an ACK with outgoing data.
   Event logs label that trigger, and pcap/qlog must be used to measure the
   resulting wire spacing and delay.
6. No browser-process (Firefox/Chrome) path has yet been captured and compared
   against these traces. Until that validation is complete the names remain
   `neqo-like-ack` and `chrome-like-ack`.
