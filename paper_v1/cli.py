"""Command line for the single paper-v1 workflow."""

import argparse
import json
import os
import sys

from paper_v1.build_identity import create_build_manifest
from paper_v1.export import export_dataset
from paper_v1.io import atomic_write_json, load_json
from paper_v1.matrix import (
    load_matrix,
    planned_optional_loss_runs,
    planned_runs,
    planned_sensitivity_runs,
)
from paper_v1.preflight import run_preflight
from paper_v1.runner import PaperV1Runner
from paper_v1.validate import validate_run


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MATRIX = os.path.join(ROOT, "configs", "paper-v1", "matrix.json")
DEFAULT_POLICY_SPEC = os.path.join(ROOT, "specs", "receiver_ack_policy_v1.json")


def _parser():
    parser = argparse.ArgumentParser(prog="paper-v1")
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--matrix", default=DEFAULT_MATRIX)
    plan.add_argument("--repetitions", type=int)
    plan.add_argument(
        "--suite",
        choices=("main", "sensitivity", "appendix-loss", "all", "all-with-appendix"),
        default="main",
    )
    plan.add_argument("--path-id")
    plan.add_argument("--run-id")

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--local-config", required=True)
    preflight.add_argument("--matrix", default=DEFAULT_MATRIX)
    preflight.add_argument("--policy-spec", default=DEFAULT_POLICY_SPEC)
    preflight.add_argument("--allow-dirty", action="store_true")

    validate = subparsers.add_parser("validate")
    validate.add_argument("run_dir")
    validate.add_argument("--policy-spec", default=DEFAULT_POLICY_SPEC)

    run = subparsers.add_parser("run")
    run.add_argument("--local-config", required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--attempt-id")
    run.add_argument("--matrix", default=DEFAULT_MATRIX)
    run.add_argument("--policy-spec", default=DEFAULT_POLICY_SPEC)
    run.add_argument("--smoke", action="store_true")

    export = subparsers.add_parser("export")
    export.add_argument("dataset_dir")
    export.add_argument("output_dir")

    build = subparsers.add_parser("build-manifest")
    build.add_argument("--component-id", required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--binary", required=True)
    build.add_argument("--build-command", required=True)
    build.add_argument("--build-flag", action="append", default=[])
    build.add_argument("--supported-cc", action="append", default=[])
    build.add_argument("--pacing-control", action="append", default=[])
    build.add_argument("--expected-effective-pacing", required=True)
    build.add_argument("--workload-protocol", choices=["http3", "raw"], required=True)
    build.add_argument(
        "--metadata-json",
        help="component-specific immutable identity fields (required for mvfst-H3)",
    )
    build.add_argument("--output", required=True)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "plan":
        matrix = load_matrix(args.matrix)
        runs = []
        if args.suite in ("main", "all", "all-with-appendix"):
            runs.extend(planned_runs(matrix, args.repetitions))
        if args.suite in ("sensitivity", "all", "all-with-appendix"):
            runs.extend(planned_sensitivity_runs(matrix, args.repetitions))
        if args.suite in ("appendix-loss", "all-with-appendix"):
            runs.extend(planned_optional_loss_runs(matrix, args.repetitions))
        if args.path_id:
            runs = [run for run in runs if run["path_id"] == args.path_id]
        if args.run_id:
            runs = [run for run in runs if run["run_id"] == args.run_id]
        print(json.dumps({"count": len(runs), "runs": runs}, indent=2))
        return 0
    if args.command == "run":
        runner = PaperV1Runner(args.local_config, args.matrix, args.policy_spec)
        run_dir = runner.run(args.run_id, attempt_id=args.attempt_id, smoke=args.smoke)
        result = validate_run(run_dir, args.policy_spec)
        result["run_dir"] = run_dir
    elif args.command == "preflight":
        result = run_preflight(
            args.local_config,
            args.matrix,
            args.policy_spec,
            allow_dirty=args.allow_dirty,
        )
    elif args.command == "validate":
        result = validate_run(args.run_dir, args.policy_spec)
    elif args.command == "export":
        result = export_dataset(args.dataset_dir, args.output_dir)
    elif args.command == "build-manifest":
        result = create_build_manifest(
            args.component_id,
            args.repository,
            args.binary,
            args.build_command,
            args.build_flag,
            args.supported_cc,
            args.pacing_control,
            args.expected_effective_pacing,
            args.workload_protocol,
            load_json(args.metadata_json) if args.metadata_json else None,
        )
        atomic_write_json(args.output, result)
    else:
        raise AssertionError(args.command)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("paper_eligible", True) else 2


if __name__ == "__main__":
    sys.exit(main())
