# ACK feedback mechanism analysis

`scripts/analyze_ack_feedback.py` is a read-only prototype for comparing how
quiche and xquic consume receiver ACK feedback. It does not modify experiment
artifacts or replay ACKs into a sender.

The default selection is intentionally narrow:

- P2 fixed-ratio experiments;
- quiche and xquic;
- CUBIC with pacing enabled;
- `fixed2/fixed10` and its role reversal;
- repetition 1; and
- seconds 5 through 15 after the synchronized client start.

Run it on the Linux result tree with:

```bash
python3 scripts/analyze_ack_feedback.py \
  /home/ioio33/QUIC_project/results
```

Or on a copied result tree with an explicit output directory:

```bash
python3 scripts/analyze_ack_feedback.py \
  /path/to/results \
  --output-dir results/ack-feedback-prototype
```

The script writes:

- `ack_episodes.csv`: one row per received application-space ACK frame;
- `ack_response_summary.csv`: implementation/policy aggregates; and
- `connection_feedback_summary.csv`: one row per QUIC connection, ready for
  ACK-feedback versus cwnd/share scatter plots;
- `feedback_cwnd_association.csv`: descriptive Pearson and Spearman
  associations at connection granularity; and
- `extraction_audit.csv`: selected runs, source-log counts, and parser status.

The common columns cover ACK range size, newly acknowledged packets, cwnd and
inflight changes, and data sent in 1 ms, 5 ms, and one smoothed RTT after the
ACK. Missing implementation-specific telemetry remains blank. In particular,
the retained quiche qlog does not expose an explicit pacing-rate field, while
the xquic CUBIC slog's congestion-controller `pacing_rate` field remains zero
even when the separate transport pacer is enabled, so the analyzer treats it
as unavailable rather than as a measured zero pacing rate.

The cwnd and inflight medians in the summary are sampled at ACK events, not on
a uniform time grid. The short post-ACK send windows are conditional event
descriptors; their windows overlap when ACKs are frequent and therefore must
not be summed into a byte rate.

This analysis supports a narrower claim than ACK-trace replay: it compares
responses to the ACK streams that the experiment actually produced. It cannot
yet claim that the two senders received an identical timestamp-for-timestamp
ACK trace. A replay or differential-feedback harness is a later, separate
experiment.

The fixed2/fixed10 contrast is a stress test, not the deployment-facing main
comparison. In particular, fixed10 applies sparse ACK behavior from connection
startup. Its large quiche window collapse must remain a stress-test observation
until a transition-matched `steady2` versus `late10` experiment repeats the
mechanism with identical ACK-2 startup and otherwise identical timer/reordering
rules.

Association rows deliberately use connections, not ACK episodes, as samples.
They do not report p-values and are labelled descriptive-only: the retained
first-repetition qlogs provide too few independent connections for an
inferential or causal correlation claim.
