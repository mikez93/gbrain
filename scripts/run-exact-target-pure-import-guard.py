#!/usr/bin/env python3
"""Run the pure import guard and publish one exclusive owner-temp receipt."""

import argparse
import hashlib
import json
import os
import pathlib
import secrets
import stat
import subprocess
import sys
import tempfile


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=str(repo), text=True).strip()


def verify_directory(path):
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_nlink < 2
    ):
        raise ValueError("unsafe owner-temp run directory")
    return info


def publish_exclusive(run_dir, body):
    directory_info = verify_directory(run_dir)
    directory_fd = os.open(str(run_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        receipt_fd = os.open("receipt.json", flags, 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(receipt_fd, 0o600)
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


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--order", required=True, type=int)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--forbid-profile", required=True)
    parser.add_argument("--output-mode", choices=["owner-temp-exclusive"], required=True)
    parser.add_argument("--stdout-summary", action="store_true", required=True)
    args = parser.parse_args(argv)

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
        "guard": guard,
        "zero_forbidden_static_runtime_matches": True,
    }
    body = (canonical(receipt) + "\n").encode("utf-8")
    run_dir = pathlib.Path(tempfile.mkdtemp(prefix="gbrain-exact-target-guard-"))
    os.chmod(str(run_dir), 0o700)
    identity = publish_exclusive(run_dir, body)
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
        "run_directory_basename": run_dir.name,
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
