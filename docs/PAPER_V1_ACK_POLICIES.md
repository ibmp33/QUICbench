# Paper-v1 receiver ACK policy specification

Normative machine-readable specification: `specs/receiver_ack_policy_v1.json`.
Schema identity: `receiver-ack-policy-v1.0.0`. These are modeled policies named
`neqo-like-ack` and `chrome-like-ack`; they are not claims of browser equivalence.
ACK_FREQUENCY and IMMEDIATE_ACK negotiation are forbidden in Paper-v1.

## State-machine comparison

| Rule | `neqo-like-ack` | `chrome-like-ack` |
|---|---|---|
| State scope | Per connection, per packet-number space | Per connection, per packet-number space |
| Initial / Handshake | Immediate ACK, threshold 1, delay 0 | Immediate ACK, threshold 1, delay 0 |
| Application initial state | `application-delayed-ack`, threshold 2 | `initial-ack-every-2`, threshold 2 |
| Transition | None | One-way to `decimated-ack-every-10` |
| Exact boundary | None | First ACK-eliciting application packet with `observed_pn >= least_observed_application_pn + 100`; that boundary packet uses threshold 10 and the steady timer |
| Steady threshold | 2 | 10 |
| ACK timer | At most 20 ms; when a prior ACK and SRTT exist, deadline is also capped at one SRTT after the prior ACK | Initial at most 25 ms; steady `max(1ms, min(25ms, minRTT/4))` |
| Reordering / loss | Immediate when the packet is not the next in-order application PN (therefore including a filled older gap) | Immediate for the first four packets in the newest PN range after a new gap; filling an older previously reported gap is not a separate immediate-ACK rule in the pinned default path |
| ECN CE | No extra modeled rule | Immediate only on transition from non-CE to CE |
| Reset | A new connection constructs new trackers; no modeled migration reset inside a connection | Same |

The transition counter is packet-number position, not received-packet count and
not ACK count. Application 0-RTT and 1-RTT use the same application-data packet
number space. Only ACK-eliciting packets increment the threshold batch.

## Code and source map

| Rule | QUICbench/quic-go code | Pinned source |
|---|---|---|
| Public definition and actual parameter report | `interface.go:DescribeACKPolicy` | Neqo `tracking.rs`; QUICHE received packet manager/constants |
| Per-connection construction | `connection.go` creates `ReceivedPacketHandlerWithPolicy` for each connection | Both references keep receive state on a connection |
| Initial/Handshake immediate ACK | `internal/ackhandler/received_packet_handler.go` | QUIC crypto packet ACK behavior; Paper-v1 deliberately freezes immediate crypto ACKs |
| Neqo threshold/timer/reordering | `internal/ackhandler/received_packet_tracker.go` | [Neqo tracking.rs at e2a2a745](https://github.com/mozilla/neqo/blob/e2a2a7459b8b51778b50209251a61fc5ca020893/neqo-transport/src/tracking.rs) |
| Chrome transition/timer/gap/CE | `internal/ackhandler/received_packet_tracker.go` | [QUICHE manager at 38097a7a](https://github.com/google/quiche/blob/38097a7a48d5f7d0853ec0ece88269c08283c9c7/quiche/quic/core/quic_received_packet_manager.cc), [header](https://github.com/google/quiche/blob/38097a7a48d5f7d0853ec0ece88269c08283c9c7/quiche/quic/core/quic_received_packet_manager.h), [constants](https://github.com/google/quiche/blob/38097a7a48d5f7d0853ec0ece88269c08283c9c7/quiche/quic/core/quic_constants.h) |
| Deterministic transition, timer, reordering, CE and isolation tests | `internal/ackhandler/received_packet_tracker_test.go` | Frozen Paper-v1 interpretation above |
| ACK_FREQUENCY rejection | `connection.go`, `ack_frequency_test.go` | Paper-v1 experiment constraint |

## Required event evidence

Every connection emits exactly one `policy_initialized` event containing flow
ID, connection ID, policy name/version, parameter hash, all effective parameters
and process-start identity. Each transition includes packet number, packet-number
space, old/new state, monotonic time, reason, reference/observed/boundary packet
numbers and transition sequence. Every ACK episode includes ACK ranges, largest
acknowledged, newly acknowledged count, ACK-eliciting batch size, spacing, delay,
effective threshold, timer deadline, state and trigger reason.

The parameter hashes are:

- `neqo-like-ack`: `56f40fb165d89d8f8f2074c5e843c840cdc77e4f1e89f4147a0d7fe970bc2042`
- `chrome-like-ack`: `f52216cf3261e0ae2e119fccc3d54d701574aa86585d264cc76f44cf45a58c43`

## Known non-equivalence

The Neqo-like model lacks Neqo frame-specific immediate-ACK classification at
the decision point, native Firefox preferences/scheduling, and Neqo ACK-range
encoding details. The Chrome-like model freezes one pinned default and excludes
QUICHE option variants, Chrome field trials/process scheduling, and QUICHE's
native crypto-space delayed-ACK details. Wire pcap/qlog validation is therefore
mandatory, and the paper language remains “Neqo-inspired” and
“Chromium-inspired.”
