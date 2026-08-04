# QUICbench experiment semantics

These constraints define the scientific meaning of the main ACK-policy
fairness experiment. Refactors and new server adapters must preserve them.

## Main fairness topology

The main experiment asks whether two QUIC receivers with different ACK
policies receive different bandwidth shares while competing through one
shared bottleneck against the same server instance.

Every main fairness trial therefore uses:

1. one server process;
2. one listening address and port;
3. two independent QUIC connections;
4. two clients with distinct local UDP ports; and
5. identical server configuration and workload for both flows.

`topology_mode: shared-server-shared-port` makes this invariant executable.
The runner must reject a trial before launch if its two flows resolve to
different server stacks or ports, or if their local UDP ports are missing or
equal.

Starting one server per flow, assigning different server ports, or sharing one
QUIC connection between flows changes the experimental question and is not
allowed in the main campaign.

Mechanism controls may explicitly select
`same-implementation-different-ports-control`. Such runs study server/process
scheduling effects and must not be pooled with the main fairness results.

## ACK-policy isolation

All policy flows use the same `quic-go-policy-client` binary. The receiver ACK
policy is selected only through the runtime `-ack-policy` argument. The client
binary hash and selected policy are recorded in each run manifest.

## Workload saturation

Smoke and fairness workloads have different purposes:

- `smoke` is a small transfer for connectivity and adapter validation. It must
  not support performance conclusions.
- `fairness` is a duration-limited, large transfer. Application bytes must
  continue growing throughout the measurement window.

The workload profile controls requested bytes and duration. The generated
target, requested byte count, duration, and workload name are recorded in the
manifest. After a run, the parser checks the second half of the measurement
window in four segments. If any flow lacks cumulative application-byte growth
in a segment, the run is marked invalid. Invalid artifacts remain available
for diagnosis but must be excluded from fairness statistics.

## Server provenance

The manifest records the server implementation, protocol, binary hash,
command, and effective server configuration. Values that are not explicitly
configured are recorded as such rather than inferred from an implementation
name.
