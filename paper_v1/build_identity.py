"""Build identity collection and fail-closed verification."""

import datetime
import os
import platform
import shutil
import subprocess

from paper_v1.io import canonical_json_bytes, load_json, sha256_bytes, sha256_file


REQUIRED_FIELDS = {
    "schema",
    "component_id",
    "repository",
    "commit",
    "branch",
    "dirty",
    "dirty_diff_sha256",
    "source_tree_identity",
    "build_command",
    "toolchain",
    "build_flags",
    "build_timestamp",
    "output_path",
    "binary_sha256",
    "supported_cc",
    "pacing_controls",
    "expected_effective_pacing",
    "workload_protocol",
}


class BuildIdentityError(ValueError):
    pass


def _run(repo, *command):
    return subprocess.run(
        list(command), cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def git_identity(repo):
    repo = os.path.abspath(repo)
    commit = _run(repo, "git", "rev-parse", "HEAD")
    branch = _run(repo, "git", "branch", "--show-current")
    status = _run(repo, "git", "status", "--porcelain=v1", "--untracked-files=all")
    diff = subprocess.run(
        ["git", "diff", "--binary"], cwd=repo, check=True, capture_output=True
    ).stdout
    untracked = []
    for line in status.splitlines():
        if line.startswith("?? "):
            path = os.path.join(repo, line[3:])
            if os.path.isfile(path):
                untracked.append((line[3:], sha256_file(path)))
    patch_identity = {
        "tracked_diff_sha256": sha256_bytes(diff),
        "untracked_files": sorted(untracked),
    }


def _toolchain_identity():
    commands = {
        "cc": ("--version",),
        "cmake": ("--version",),
        "go": ("version",),
        "rustc": ("--version",),
        "cargo": ("--version",),
        "openssl": ("version",),
    }
    result = {
        "platform": platform.platform(),
        "python": platform.python_version(),
    }
    for name, arguments in commands.items():
        executable = shutil.which(name)
        if executable is None:
            result[name] = None
            continue
        completed = subprocess.run(
            [executable, *arguments], check=False, capture_output=True, text=True
        )
        output = (completed.stdout or completed.stderr).strip().splitlines()
        result[name] = {
            "path": os.path.realpath(executable),
            "version": output[0] if output else None,
            "exit_code": completed.returncode,
        }
    return result
    dirty_diff_sha256 = sha256_bytes(canonical_json_bytes(patch_identity))
    return {
        "repository": repo,
        "commit": commit,
        "branch": branch,
        "dirty": bool(status),
        "dirty_diff_sha256": dirty_diff_sha256,
        "source_tree_identity": "{}{}".format(
            commit, "+dirty:" + dirty_diff_sha256 if status else ""
        ),
        "status": status.splitlines(),
    }


def create_build_manifest(
    component_id,
    repository,
    binary,
    build_command,
    build_flags,
    supported_cc,
    pacing_controls,
    expected_effective_pacing,
    workload_protocol,
    metadata=None,
):
    identity = git_identity(repository)
    binary = os.path.abspath(binary)
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise BuildIdentityError("binary is not executable: {}".format(binary))
    manifest = {
        "schema": "quicbench-build-v1",
        "component_id": component_id,
        **identity,
        "build_command": build_command,
        "toolchain": _toolchain_identity(),
        "build_flags": build_flags,
        "build_timestamp": datetime.datetime.fromtimestamp(
            os.stat(binary).st_mtime, datetime.timezone.utc
        ).isoformat(),
        "output_path": binary,
        "binary_sha256": sha256_file(binary),
        "supported_cc": sorted(supported_cc),
        "pacing_controls": pacing_controls,
        "expected_effective_pacing": expected_effective_pacing,
        "workload_protocol": workload_protocol,
    }
    metadata = metadata or {}
    collisions = set(metadata).intersection(manifest)
    if collisions:
        raise BuildIdentityError(
            "metadata cannot replace canonical fields: {}".format(sorted(collisions))
        )
    manifest.update(metadata)
    return manifest


def verify_build_manifest(path, allow_dirty=False):
    manifest = load_json(path)
    missing = REQUIRED_FIELDS.difference(manifest)
    if missing:
        raise BuildIdentityError("missing build fields: {}".format(sorted(missing)))
    if manifest["schema"] != "quicbench-build-v1":
        raise BuildIdentityError("unexpected build schema")
    binary = os.path.abspath(manifest["output_path"])
    if sha256_file(binary) != manifest["binary_sha256"]:
        raise BuildIdentityError("binary hash mismatch: {}".format(binary))
    current = git_identity(manifest["repository"])
    for field in ("commit", "dirty", "dirty_diff_sha256", "source_tree_identity"):
        if current[field] != manifest[field]:
            raise BuildIdentityError("source identity mismatch: {}".format(field))
    if manifest["dirty"] and not allow_dirty:
        raise BuildIdentityError("canonical paper build must be clean")
    return manifest
