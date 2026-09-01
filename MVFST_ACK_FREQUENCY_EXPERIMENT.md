# P4 mvfst ACK_FREQUENCY mitigation pilot

This experiment is isolated from the HTTP/3 implementation comparison. It
uses one mvfst `tperf` BBR1 server, one listening port, and two synchronized
raw-QUIC connections from the policy client.

The treatment compares:

- `receiver-controlled`: Neqo/Chromium policy remains in control and the
  client does not advertise `min_ack_delay`.
- `sender-requested`: the client advertises mvfst's legacy draft transport
  parameter and applies newer ACK_FREQUENCY requests from the BBR1 sender.

This is a mitigation test, not an assumption that ACK_FREQUENCY improves
fairness. Report whether it changes the mean policy-centered share gap,
role-reversal consistency, and between-trial variance.

## Linux sequence

Build and install the modified mvfst `tperf` and
`quic-go-policy-client` binaries first. Then run:

```bash
cd /home/ioio33/QUICbench
sudo -v

python3 scripts/run_mvfst_ack_frequency_pilot.py preflight
python3 scripts/run_mvfst_ack_frequency_pilot.py canary --qlog-policy all
./scripts/check_mvfst_ack_frequency_pilot.sh
```

Do not start the full pilot unless both canary treatments pass. In particular,
the sender-requested client logs must contain `ack_frequency_applied`, while
the receiver-controlled logs must not contain that event.

Run the 24-run pilot (two treatments, four policy pairs, three repetitions):

```bash
python3 scripts/run_mvfst_ack_frequency_pilot.py full \
  --trials 3 \
  --qlog-policy first-only \
  --pcap-policy none
```

The minimum payload time is eight minutes. Allow approximately 12--20 minutes
including namespace setup, server startup, parsing, and artifact checks.

## Evidence recorded

Each manifest records the treatment, server ACK_FREQUENCY configuration,
client compatibility mode, draft codepoints, commands, binary hashes, topology,
workload, and the normal validity/saturation result. Server qlog is passed to
`tperf`; client stdout records each accepted and applied request.

The mvfst request uses a common steady packet tolerance, but its requested
maximum ACK delay is computed from each connection's SRTT. Analyze and report
the requested values per flow rather than claiming that the two connections
receive an identical ACK trace.
