"""Application-byte saturation checks shared by experiment parsers."""

import csv
import os


SATURATION_SEGMENTS = 4
SATURATION_END_TOLERANCE_S = 1.0


def validate_saturation(metrics_path, measurement_start_s, measurement_end_s):
    validation_start_s = measurement_start_s + (
        measurement_end_s - measurement_start_s
    ) / 2.0
    result = {
        "valid": False,
        "reason": "",
        "window_start_s": round(validation_start_s, 5),
        "window_end_s": round(measurement_end_s, 5),
        "segments": SATURATION_SEGMENTS,
        "growth_bytes": 0,
        "segment_growth_bytes": [],
    }
    if not metrics_path or not os.path.isfile(metrics_path):
        result["reason"] = "metrics.csv is missing"
        return result

    samples = []
    try:
        with open(metrics_path, newline="") as metrics_file:
            for row in csv.DictReader(metrics_file):
                samples.append(
                    (
                        float(row["elapsed_ms"]) / 1000.0,
                        int(float(row["cumulative_body_bytes"])),
                    )
                )
    except (KeyError, TypeError, ValueError):
        result["reason"] = "metrics.csv has invalid cumulative byte samples"
        return result

    samples.sort(key=lambda sample: sample[0])
    if not samples:
        result["reason"] = "metrics.csv has no cumulative byte samples"
        return result
    if samples[-1][0] < measurement_end_s - SATURATION_END_TOLERANCE_S:
        result["reason"] = "metrics ended before the measurement window"
        return result

    def cumulative_at_or_before(timestamp_s):
        value = None
        for elapsed_s, cumulative_bytes in samples:
            if elapsed_s > timestamp_s:
                break
            value = cumulative_bytes
        return value

    segment_width_s = (measurement_end_s - validation_start_s) / SATURATION_SEGMENTS
    segment_growth = []
    for index in range(SATURATION_SEGMENTS):
        segment_start_s = validation_start_s + index * segment_width_s
        segment_end_s = validation_start_s + (index + 1) * segment_width_s
        start_bytes = cumulative_at_or_before(segment_start_s)
        end_bytes = cumulative_at_or_before(segment_end_s)
        if start_bytes is None or end_bytes is None:
            result["reason"] = "metrics do not cover the saturation validation window"
            return result
        segment_growth.append(max(0, end_bytes - start_bytes))

    result["segment_growth_bytes"] = segment_growth
    result["growth_bytes"] = sum(segment_growth)
    stalled_segments = [index + 1 for index, growth in enumerate(segment_growth) if growth <= 0]
    if stalled_segments:
        result["reason"] = "no byte growth in validation segment(s): {}".format(
            ",".join(str(index) for index in stalled_segments)
        )
        return result

    result["valid"] = True
    result["reason"] = "continuous byte growth observed"
    return result
