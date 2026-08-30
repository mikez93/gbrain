#!/usr/bin/env python3
"""Run the pure import guard and publish one exclusive owner-temp receipt."""

import argparse
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=str(repo), text=True).strip()


def verify_temp_parent(path):
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    owner_private = info.st_uid == os.geteuid() and mode & 0o077 == 0
    sticky_system_temp = mode & stat.S_ISVTX and mode & 0o002
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or not (owner_private or sticky_system_temp)
    ):
        raise ValueError("unsafe temporary parent directory")
    return info


def create_owner_temp_run_directory(parent=None, candidate_name=None):
    parent_path = pathlib.Path(parent or tempfile.gettempdir()).resolve()
    verify_temp_parent(parent_path)
    if candidate_name is None:
        path = pathlib.Path(
            tempfile.mkdtemp(prefix="gbrain-exact-target-guard-", dir=str(parent_path))
        )
    else:
        path = parent_path / candidate_name
        os.mkdir(str(path), 0o700)
    os.chmod(str(path), 0o700)
    verify_directory(path)
    return path


def verify_directory(path, expected_uid=None):
    info = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != owner
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_nlink < 2
    ):
        raise ValueError("unsafe owner-temp run directory")
    return info


def publish_exclusive(run_dir, body, after_open_hook=None):
    directory_info = verify_directory(run_dir)
    directory_fd = os.open(str(run_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        receipt_fd = os.open("receipt.json", flags, 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(receipt_fd, 0o600)
            if after_open_hook is not None:
                after_open_hook(run_dir, receipt_fd, directory_fd)
            opened = os.fstat(receipt_fd)
            named = os.stat("receipt.json", dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_dev != named.st_dev
                or opened.st_ino != named.st_ino
            ):
                raise ValueError("unsafe exclusive receipt inode")
            os.write(receipt_fd, body)
            os.fsync(receipt_fd)
        finally:
            os.close(receipt_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return {
        "run_directory_dev": directory_info.st_dev,
        "run_directory_ino": directory_info.st_ino,
        "receipt_dev": named.st_dev,
        "receipt_ino": named.st_ino,
        "run_directory_mode": "0700",
        "receipt_mode": "0600",
    }


def run_guard(repo, scanner_command):
    completed = subprocess.run(
        scanner_command,
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("pure import guard rejected candidate: %s" % completed.stderr.strip())
    guard = json.loads(completed.stdout)
    if not guard.get("pass") or guard.get("forbidden_match_count") != 0:
        raise ValueError("pure import guard did not produce a zero-match result")
    return guard


def expect_rejected(name, operation):
    try:
        operation()
    except Exception as error:
        return {"name": name, "pass": True, "error_class": type(error).__name__}
    return {"name": name, "pass": False, "error_class": None}


def receipt_safety_self_test():
    parent = pathlib.Path(tempfile.mkdtemp(prefix="gbrain-exact-target-selftest-"))
    os.chmod(str(parent), 0o700)
    body = b'{"self_test":true}\n'
    cases = []
    try:
        precreated = create_owner_temp_run_directory(parent)
        (precreated / "receipt.json").write_bytes(b"existing")
        cases.append(
            expect_rejected(
                "precreated_receipt_regular_file",
                lambda: publish_exclusive(precreated, body),
            )
        )

        symlink = create_owner_temp_run_directory(parent)
        symlink_target = parent / "symlink-target"
        symlink_target.write_bytes(b"target")
        os.symlink(str(symlink_target), str(symlink / "receipt.json"))
        cases.append(
            expect_rejected(
                "receipt_symlink",
                lambda: publish_exclusive(symlink, body),
            )
        )

        hardlink = create_owner_temp_run_directory(parent)

        def add_hardlink(run_dir, _receipt_fd, _directory_fd):
            os.link(str(run_dir / "receipt.json"), str(run_dir / "receipt-hardlink"))

        cases.append(
            expect_rejected(
                "receipt_hardlink_nlink_gt_one",
                lambda: publish_exclusive(hardlink, body, add_hardlink),
            )
        )

        stale = create_owner_temp_run_directory(parent)
        publish_exclusive(stale, body)
        cases.append(
            expect_rejected(
                "stale_prior_receipt",
                lambda: publish_exclusive(stale, body),
            )
        )

        collision_name = "gbrain-exact-target-guard-forced-collision"
        create_owner_temp_run_directory(parent, collision_name)
        cases.append(
            expect_rejected(
                "precreated_run_directory_name_collision",
                lambda: create_owner_temp_run_directory(parent, collision_name),
            )
        )

        unsafe = create_owner_temp_run_directory(parent)
        os.chmod(str(unsafe), 0o755)
        cases.append(
            expect_rejected(
                "unsafe_run_directory_mode_or_owner",
                lambda: publish_exclusive(unsafe, body),
            )
        )

        swapped = create_owner_temp_run_directory(parent)

        def swap_named_inode(run_dir, _receipt_fd, _directory_fd):
            os.rename(str(run_dir / "receipt.json"), str(run_dir / "opened-inode"))
            replacement_fd = os.open(
                str(run_dir / "receipt.json"),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(replacement_fd)

        cases.append(
            expect_rejected(
                "named_opened_inode_swap",
                lambda: publish_exclusive(swapped, body, swap_named_inode),
            )
        )

        def concurrent_publish(binding):
            challenge = secrets.token_hex(32)
            receipt = {
                "binding": binding,
                "challenge": challenge,
            }
            receipt_body = (canonical(receipt) + "\n").encode("utf-8")
            run_dir = create_owner_temp_run_directory(parent)
            identity = publish_exclusive(run_dir, receipt_body)
            return {
                "run_directory": str(run_dir),
                "receipt": str(run_dir / "receipt.json"),
                "challenge": challenge,
                "binding": binding,
                "sha256": sha256_bytes(receipt_body),
                "identity": identity,
            }

        with ThreadPoolExecutor(max_workers=2) as executor:
            concurrent = list(executor.map(concurrent_publish, ("left", "right")))
        distinct_fields = [
            "run_directory",
            "receipt",
            "challenge",
            "binding",
            "sha256",
        ]
        concurrency_pass = all(
            concurrent[0][field] != concurrent[1][field] for field in distinct_fields
        ) and concurrent[0]["identity"]["receipt_ino"] != concurrent[1]["identity"]["receipt_ino"]
        cases.append(
            {
                "name": "two_concurrent_runs_distinct_dirs_receipts_challenges_bindings",
                "pass": concurrency_pass,
                "error_class": None,
            }
        )
    finally:
        shutil.rmtree(parent)

    result = {
        "schema": "gbrain.exact-target-receipt-safety-self-test.v1",
        "pass": len(cases) == 8 and all(case["pass"] for case in cases),
        "case_count": len(cases),
        "cases": cases,
    }
    sys.stdout.write(canonical(result) + "\n")
    return 0 if result["pass"] else 1


def main(argv=None):
    effective_argv = sys.argv[1:] if argv is None else argv
    if effective_argv == ["--self-test-receipt-safety"]:
        return receipt_safety_self_test()
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--order", required=True, type=int)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--forbid-profile", required=True)
    parser.add_argument("--output-mode", choices=["owner-temp-exclusive"], required=True)
    parser.add_argument("--stdout-summary", action="store_true", required=True)
    args = parser.parse_args(effective_argv)

    repo = pathlib.Path(args.repo).resolve()
    scanner_command = [
        sys.executable,
        "scripts/check-exact-target-pure-imports.py",
        "--repo",
        ".",
    ]
    for root in args.root:
        scanner_command.extend(["--root", root])
    scanner_command.extend(["--forbid-profile", args.forbid_profile, "--json"])
    guards = [run_guard(repo, scanner_command), run_guard(repo, scanner_command)]
    if canonical(guards[0]) != canonical(guards[1]):
        raise ValueError("pure import graph/evidence changed across repeated scans")
    guard = guards[0]

    command_argv = [sys.executable, *sys.argv]
    command_sha = sha256_bytes(canonical(command_argv).encode("utf-8"))
    receipt = {
        "schema": "gbrain.exact-target-pure-import-guard-receipt.v1",
        "order": args.order,
        "source": {
            "commit": git(repo, "rev-parse", "HEAD"),
            "tree": git(repo, "rev-parse", "HEAD^{tree}"),
        },
        "command_argv_sha256": command_sha,
        "roots": args.root,
        "profile": args.forbid_profile,
        "run_challenge": secrets.token_hex(32),
        "graph_repeat": {
            "runs": 2,
            "identical": True,
            "graph_sha256": guard["graph_sha256"],
        },
        "guard": guard,
        "zero_forbidden_static_runtime_matches": True,
    }
    body = (canonical(receipt) + "\n").encode("utf-8")
    run_dir = create_owner_temp_run_directory()
    identity = publish_exclusive(run_dir, body)
    receipt_path = run_dir / "receipt.json"
    summary = {
        "schema": "gbrain.exact-target-pure-import-guard-summary.v1",
        "pass": True,
        "order": args.order,
        "roots": len(args.root),
        "modules": len(guard["resolved_transitive_modules"]),
        "edges": guard["edge_count"],
        "forbidden_static_runtime_environment_matches": 0,
        "graph_sha256": guard["graph_sha256"],
        "command_argv_sha256": command_sha,
        "source_commit": receipt["source"]["commit"],
        "source_tree": receipt["source"]["tree"],
        "graph_repeat_runs": 2,
        "graph_repeat_identical": True,
        "run_directory_basename": run_dir.name,
        "run_directory_path": str(run_dir),
        "receipt_path": str(receipt_path),
        "receipt_sha256": sha256_bytes(body),
        "receipt_bytes": len(body),
        **identity,
    }
    sys.stdout.write(canonical(summary) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        sys.stderr.write("%s\n" % error)
        raise SystemExit(1)
