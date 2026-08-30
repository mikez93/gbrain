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
import threading
from concurrent.futures import ThreadPoolExecutor


class ReceiptSafetyError(ValueError):
    """Content-free, cause-bound receipt rejection."""

    def __init__(self, reason, seam):
        self.reason = reason
        self.seam = seam
        super().__init__("%s:%s" % (seam, reason))


PROFILE_MATERIAL = {
    "id": "exact-target-orders-0-2-v2",
    "allowed_bare_imports": ["node:crypto", "node:util"],
    "forbidden_path_fragments": [
        "src/core/ai/",
        "src/core/engine.ts",
        "src/core/postgres-engine.ts",
        "src/core/minions/queue.ts",
        "src/core/minions/worker.ts",
        "src/commands/",
    ],
    "fail_closed": True,
}
EXACT_LOADER_SHA256 = "ddcacb69cd26c07322c51b798a63805fd99c272177c9633a978f3886358ca070"
EXACT_LICENSE_SHA256 = "5f9cf9fb6acb1972b35ae29119ce563bb60ec097656bc4b69b9bac2d04c7a147"
EXACT_RUNTIME_SHA256 = "29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f"
EXACT_GRAMMAR_SHA256 = "8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f"
EXACT_LOCK_INTEGRITY = "sha512-hS87TH71Zd6mGAmYCvlgxeGDjqd9GTeqXNqTT+u0Gs51uIozNIaaq/kUAbV/Zf56jb2ZOyG8BxZs2GG9wbLi6Q=="


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
        try:
            os.mkdir(str(path), 0o700)
        except FileExistsError as error:
            raise ReceiptSafetyError(
                "run_directory_name_collision", "create_run_directory"
            ) from error
    os.chmod(str(path), 0o700)
    verify_directory(path)
    return path


def verify_directory(path, expected_uid=None):
    info = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ReceiptSafetyError("run_directory_not_plain_directory", "verify_run_directory")
    if info.st_uid != owner:
        raise ReceiptSafetyError("run_directory_owner_mismatch", "verify_run_directory")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ReceiptSafetyError("run_directory_mode_mismatch", "verify_run_directory")
    if info.st_nlink < 2:
        raise ReceiptSafetyError("run_directory_link_count", "verify_run_directory")
    return info


def publish_exclusive(run_dir, body, after_open_hook=None, expected_uid=None):
    expected_owner = os.geteuid() if expected_uid is None else expected_uid
    directory_info = verify_directory(run_dir, expected_owner)
    directory_fd = os.open(str(run_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            receipt_fd = os.open("receipt.json", flags, 0o600, dir_fd=directory_fd)
        except FileExistsError as error:
            raise ReceiptSafetyError(
                "receipt_name_exists", "open_exclusive_receipt"
            ) from error
        try:
            os.fchmod(receipt_fd, 0o600)
            if after_open_hook is not None:
                after_open_hook(run_dir, receipt_fd, directory_fd)
            opened = os.fstat(receipt_fd)
            named = os.stat("receipt.json", dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(opened.st_mode):
                raise ReceiptSafetyError("receipt_not_regular", "verify_opened_receipt")
            if opened.st_uid != expected_owner:
                raise ReceiptSafetyError("receipt_owner_mismatch", "verify_opened_receipt")
            if opened.st_nlink != 1:
                raise ReceiptSafetyError("receipt_link_count", "verify_opened_receipt")
            if stat.S_IMODE(opened.st_mode) != 0o600:
                raise ReceiptSafetyError("receipt_mode_mismatch", "verify_opened_receipt")
            if opened.st_dev != named.st_dev or opened.st_ino != named.st_ino:
                raise ReceiptSafetyError(
                    "opened_named_inode_mismatch", "verify_opened_receipt"
                )
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


def deterministic_guard_binding(guard):
    return {
        key: guard[key]
        for key in (
            "schema",
            "profile",
            "profile_sha256",
            "roots",
            "resolved_transitive_modules",
            "module_sha256",
            "edge_count",
            "edges",
            "graph_sha256",
            "scanner_sha256",
            "ast_scanner_sha256",
            "ast_evidence_sha256",
            "forbidden_matches",
            "forbidden_match_count",
            "dynamic_import_matches",
            "environment_access_matches",
            "pass",
        )
    }


def validate_guard_binding(repo, guard, roots, profile):
    if profile != PROFILE_MATERIAL["id"] or guard.get("profile") != profile:
        raise ValueError("guard profile binding mismatch")
    if guard.get("profile_sha256") != sha256_bytes(
        canonical(PROFILE_MATERIAL).encode("utf-8")
    ):
        raise ValueError("guard profile hash mismatch")
    if guard.get("roots") != roots:
        raise ValueError("guard ordered roots mismatch")
    modules = guard.get("resolved_transitive_modules")
    module_hashes = guard.get("module_sha256")
    edges = guard.get("edges")
    if not isinstance(modules, list) or not isinstance(module_hashes, dict):
        raise ValueError("guard module binding missing")
    expected_hashes = {
        module: sha256_bytes((repo / module).read_bytes()) for module in modules
    }
    if module_hashes != dict(sorted(expected_hashes.items())):
        raise ValueError("guard module hash binding mismatch")
    if not isinstance(edges, list) or guard.get("edge_count") != len(edges):
        raise ValueError("guard edge binding mismatch")
    graph_material = {"roots": roots, "modules": expected_hashes, "edges": edges}
    if guard.get("graph_sha256") != sha256_bytes(
        canonical(graph_material).encode("utf-8")
    ):
        raise ValueError("guard graph hash binding mismatch")
    if guard.get("scanner_sha256") != sha256_bytes(
        (repo / "scripts/check-exact-target-pure-imports.py").read_bytes()
    ):
        raise ValueError("guard scanner hash mismatch")
    if guard.get("ast_scanner_sha256") != sha256_bytes(
        (repo / "scripts/exact-target-typescript-ast.ts").read_bytes()
    ):
        raise ValueError("guard AST scanner hash mismatch")
    ast_runs = guard.get("ast_runs")
    if not isinstance(ast_runs, list) or not ast_runs:
        raise ValueError("verified loader-copy evidence missing")
    for ast_run in ast_runs:
        ast_command = ["bun", "scripts/exact-target-typescript-ast.ts", "--json"]
        for module in ast_run.get("module_batch", []):
            ast_command.extend(["--scan-file", module])
        loader = ast_run.get("loader", {})
        owner_copy = loader.get("owner_temp_copy", {})
        if (
            ast_run.get("command_argv_sha256")
            != sha256_bytes(canonical(ast_command).encode("utf-8"))
            or ast_run.get("parser_errors") != 0
            or loader.get("source_sha256") != EXACT_LOADER_SHA256
            or loader.get("license_sha256") != EXACT_LICENSE_SHA256
            or loader.get("runtime_sha256") != EXACT_RUNTIME_SHA256
            or loader.get("grammar_sha256") != EXACT_GRAMMAR_SHA256
            or loader.get("lock_integrity") != EXACT_LOCK_INTEGRITY
            or owner_copy.get("sha256") != EXACT_LOADER_SHA256
            or owner_copy.get("mode") != "0600"
            or owner_copy.get("directory_mode") != "0700"
            or not owner_copy.get("imported")
            or not isinstance(owner_copy.get("dev"), int)
            or owner_copy.get("dev") <= 0
            or not isinstance(owner_copy.get("ino"), int)
            or owner_copy.get("ino") <= 0
        ):
            raise ValueError("verified loader-copy binding mismatch")
    if (
        not guard.get("pass")
        or guard.get("forbidden_match_count") != 0
        or guard.get("dynamic_import_matches") != 0
        or guard.get("environment_access_matches") != 0
    ):
        raise ValueError("guard observed static counts are nonzero")


def run_runtime_tripwire(repo):
    command = [
        "bun",
        "--config=/dev/null",
        "test/helpers/exact-target-effect-tripwire.ts",
        "--suite",
    ]
    completed = subprocess.run(
        command,
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("runtime tripwire suite rejected candidate")
    try:
        receipt = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("runtime tripwire returned invalid JSON") from error
    effect_vector = receipt.get("effect_vector")
    positive = receipt.get("positive_control")
    if (
        not receipt.get("pass")
        or receipt.get("fixture_count") != 30
        or receipt.get("isolated_child_count") != 30
        or receipt.get("distinct_child_pid_count") != 30
        or receipt.get("required_stubs_per_child") != 26
        or receipt.get("total_stub_installs") != 780
        or not receipt.get("all_children_stubbed")
        or receipt.get("rejection_count") != 30
        or receipt.get("executor_invocations") != 0
        or receipt.get("effect_total") != 0
        or not isinstance(effect_vector, dict)
        or len(effect_vector) != 26
        or any(value != 0 for value in effect_vector.values())
        or not isinstance(positive, dict)
        or not positive.get("pass")
        or positive.get("executor_invocations") != 1
        or positive.get("effect_total") != 1
        or positive.get("effect_vector", {}).get("fetch") != 1
    ):
        raise ValueError("runtime tripwire evidence contract mismatch")
    return {
        "command_argv": command,
        "command_argv_sha256": sha256_bytes(canonical(command).encode("utf-8")),
        "helper_sha256": sha256_bytes(
            (repo / "test/helpers/exact-target-effect-tripwire.ts").read_bytes()
        ),
        "fixtures_sha256": sha256_bytes(
            (
                repo
                / "test/fixtures/exact-target-forbidden-effects/cases.ts"
            ).read_bytes()
        ),
        "receipt": receipt,
    }


def execute_full_guard(
    repo,
    order,
    roots,
    profile,
    command_argv,
    parent=None,
    start_barrier=None,
):
    if start_barrier is not None:
        start_barrier.wait(timeout=30)
    scanner_command = [
        sys.executable,
        "scripts/check-exact-target-pure-imports.py",
        "--repo",
        ".",
    ]
    for root in roots:
        scanner_command.extend(["--root", root])
    scanner_command.extend(["--forbid-profile", profile, "--json"])
    guards = [run_guard(repo, scanner_command), run_guard(repo, scanner_command)]
    for guard_run in guards:
        validate_guard_binding(repo, guard_run, roots, profile)
    guard_bindings = [deterministic_guard_binding(guard) for guard in guards]
    if canonical(guard_bindings[0]) != canonical(guard_bindings[1]):
        raise ValueError("pure import graph/evidence changed across repeated scans")
    runtime = run_runtime_tripwire(repo)
    guard = guards[0]
    command_sha = sha256_bytes(canonical(command_argv).encode("utf-8"))
    challenge = secrets.token_hex(32)
    static_matches = guard["forbidden_match_count"]
    runtime_effects = runtime["receipt"]["effect_total"]
    receipt = {
        "schema": "gbrain.exact-target-pure-import-guard-receipt.v1",
        "order": order,
        "source": {
            "commit": git(repo, "rev-parse", "HEAD"),
            "tree": git(repo, "rev-parse", "HEAD^{tree}"),
        },
        "command_argv": command_argv,
        "command_argv_sha256": command_sha,
        "scanner_command_argv": scanner_command,
        "scanner_command_argv_sha256": sha256_bytes(
            canonical(scanner_command).encode("utf-8")
        ),
        "roots": roots,
        "profile": profile,
        "run_challenge": challenge,
        "graph_repeat": {
            "runs": 2,
            "identical": True,
            "graph_sha256": guard["graph_sha256"],
        },
        "guard": guard,
        "guard_runs": guards,
        "runtime_tripwire": runtime,
        "observed_counts": {
            "static_forbidden_matches": static_matches,
            "dynamic_import_matches": guard["dynamic_import_matches"],
            "environment_access_matches": guard["environment_access_matches"],
            "runtime_executor_invocations": runtime["receipt"][
                "executor_invocations"
            ],
            "runtime_effect_total": runtime_effects,
        },
    }
    body = (canonical(receipt) + "\n").encode("utf-8")
    run_dir = create_owner_temp_run_directory(parent)
    identity = publish_exclusive(run_dir, body)
    receipt_path = run_dir / "receipt.json"
    summary = {
        "schema": "gbrain.exact-target-pure-import-guard-summary.v1",
        "pass": static_matches == 0 and runtime_effects == 0,
        "order": order,
        "roots": len(roots),
        "modules": len(guard["resolved_transitive_modules"]),
        "edges": guard["edge_count"],
        "forbidden_static_runtime_environment_matches": static_matches
        + runtime_effects,
        "runtime_fixture_count": runtime["receipt"]["fixture_count"],
        "runtime_executor_invocations": runtime["receipt"]["executor_invocations"],
        "runtime_effect_total": runtime_effects,
        "runtime_all_children_stubbed": runtime["receipt"]["all_children_stubbed"],
        "verified_loader_copy_count": sum(
            len(run.get("ast_runs", [])) for run in guards
        ),
        "graph_sha256": guard["graph_sha256"],
        "command_argv_sha256": command_sha,
        "source_commit": receipt["source"]["commit"],
        "source_tree": receipt["source"]["tree"],
        "graph_repeat_runs": 2,
        "graph_repeat_identical": True,
        "run_challenge_sha256": sha256_bytes(challenge.encode("utf-8")),
        "run_directory_basename": run_dir.name,
        "run_directory_path": str(run_dir),
        "receipt_path": str(receipt_path),
        "receipt_sha256": sha256_bytes(body),
        "receipt_bytes": len(body),
        **identity,
    }
    return summary, receipt


def expect_rejected(name, operation, expected_reason, expected_seam):
    try:
        operation()
    except Exception as error:
        observed_class = type(error).__name__
        observed_reason = getattr(error, "reason", None)
        observed_seam = getattr(error, "seam", None)
        return {
            "name": name,
            "pass": observed_class == "ReceiptSafetyError"
            and observed_reason == expected_reason
            and observed_seam == expected_seam,
            "expected_class": "ReceiptSafetyError",
            "expected_reason": expected_reason,
            "expected_seam": expected_seam,
            "observed_class": observed_class,
            "observed_reason": observed_reason,
            "observed_seam": observed_seam,
        }
    return {
        "name": name,
        "pass": False,
        "expected_class": "ReceiptSafetyError",
        "expected_reason": expected_reason,
        "expected_seam": expected_seam,
        "observed_class": None,
        "observed_reason": None,
        "observed_seam": None,
    }


def receipt_safety_self_test():
    repo = pathlib.Path.cwd().resolve()
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
                "receipt_name_exists",
                "open_exclusive_receipt",
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
                "receipt_name_exists",
                "open_exclusive_receipt",
            )
        )

        hardlink = create_owner_temp_run_directory(parent)

        def add_hardlink(run_dir, _receipt_fd, _directory_fd):
            os.link(str(run_dir / "receipt.json"), str(run_dir / "receipt-hardlink"))

        cases.append(
            expect_rejected(
                "receipt_hardlink_nlink_gt_one",
                lambda: publish_exclusive(hardlink, body, add_hardlink),
                "receipt_link_count",
                "verify_opened_receipt",
            )
        )

        stale = create_owner_temp_run_directory(parent)
        publish_exclusive(stale, body)
        cases.append(
            expect_rejected(
                "stale_prior_receipt",
                lambda: publish_exclusive(stale, body),
                "receipt_name_exists",
                "open_exclusive_receipt",
            )
        )

        collision_name = "gbrain-exact-target-guard-forced-collision"
        create_owner_temp_run_directory(parent, collision_name)
        cases.append(
            expect_rejected(
                "precreated_run_directory_name_collision",
                lambda: create_owner_temp_run_directory(parent, collision_name),
                "run_directory_name_collision",
                "create_run_directory",
            )
        )

        unsafe = create_owner_temp_run_directory(parent)
        os.chmod(str(unsafe), 0o755)
        cases.append(
            expect_rejected(
                "unsafe_run_directory_mode",
                lambda: publish_exclusive(unsafe, body),
                "run_directory_mode_mismatch",
                "verify_run_directory",
            )
        )

        owner_mismatch = create_owner_temp_run_directory(parent)
        cases.append(
            expect_rejected(
                "injected_effective_uid_owner_mismatch",
                lambda: publish_exclusive(
                    owner_mismatch, body, expected_uid=os.geteuid() + 1
                ),
                "run_directory_owner_mismatch",
                "verify_run_directory",
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
                "opened_named_inode_mismatch",
                "verify_opened_receipt",
            )
        )

        roots = [
            "src/core/minions/exact-target-contract.ts",
            "src/core/minions/exact-target-pure-types.ts",
        ]
        profile = "exact-target-orders-0-2-v2"
        full_argv = [
            sys.executable,
            "scripts/run-exact-target-pure-import-guard.py",
            "--repo",
            ".",
            "--order",
            "0",
            "--root",
            roots[0],
            "--root",
            roots[1],
            "--forbid-profile",
            profile,
            "--output-mode",
            "owner-temp-exclusive",
            "--stdout-summary",
        ]
        barrier = threading.Barrier(2)

        def concurrent_full_guard(_slot):
            summary, receipt = execute_full_guard(
                repo,
                0,
                roots,
                profile,
                full_argv,
                parent=parent,
                start_barrier=barrier,
            )
            receipt_body = pathlib.Path(summary["receipt_path"]).read_bytes()
            loaded = json.loads(receipt_body.decode("utf-8"))
            guard = loaded["guard"]
            complete_binding = (
                loaded["command_argv"] == full_argv
                and sha256_bytes(canonical(loaded["command_argv"]).encode("utf-8"))
                == loaded["command_argv_sha256"]
                and loaded["source"]["commit"] == git(repo, "rev-parse", "HEAD")
                and loaded["source"]["tree"] == git(repo, "rev-parse", "HEAD^{tree}")
                and loaded["roots"] == roots
                and guard["roots"] == roots
                and guard["resolved_transitive_modules"] == sorted(roots)
                and len(guard["module_sha256"]) == 2
                and guard["edge_count"] == len(guard["edges"])
                and guard["graph_sha256"] == loaded["graph_repeat"]["graph_sha256"]
                and guard["profile"] == profile
                and len(guard["profile_sha256"]) == 64
                and len(guard["scanner_sha256"]) == 64
                and len(guard["ast_scanner_sha256"]) == 64
                and len(loaded["run_challenge"]) == 64
                and loaded["runtime_tripwire"]["receipt"]["pass"]
                and len(loaded["guard_runs"]) == 2
                and all(
                    ast_run["loader"]["owner_temp_copy"]["imported"]
                    and ast_run["loader"]["owner_temp_copy"]["mode"] == "0600"
                    and ast_run["loader"]["owner_temp_copy"]["ino"] > 0
                    for guard_run in loaded["guard_runs"]
                    for ast_run in guard_run["ast_runs"]
                )
                and summary["receipt_sha256"] == sha256_bytes(receipt_body)
                and summary["receipt_dev"] > 0
                and summary["receipt_ino"] > 0
                and summary["run_directory_dev"] > 0
                and summary["run_directory_ino"] > 0
            )
            return {
                "summary": summary,
                "receipt": receipt,
                "loaded": loaded,
                "complete_binding": complete_binding,
            }

        with ThreadPoolExecutor(max_workers=2) as executor:
            concurrent = list(executor.map(concurrent_full_guard, ("left", "right")))
        left, right = concurrent
        distinct = {
            "run_directory": left["summary"]["run_directory_path"]
            != right["summary"]["run_directory_path"],
            "receipt_path": left["summary"]["receipt_path"]
            != right["summary"]["receipt_path"],
            "challenge": left["loaded"]["run_challenge"]
            != right["loaded"]["run_challenge"],
            "receipt_sha256": left["summary"]["receipt_sha256"]
            != right["summary"]["receipt_sha256"],
            "receipt_inode": left["summary"]["receipt_ino"]
            != right["summary"]["receipt_ino"],
            "run_directory_inode": left["summary"]["run_directory_ino"]
            != right["summary"]["run_directory_ino"],
        }
        no_cross_trust = (
            left["loaded"]["run_challenge"] == left["receipt"]["run_challenge"]
            and right["loaded"]["run_challenge"]
            == right["receipt"]["run_challenge"]
            and left["loaded"]["run_challenge"] != right["receipt"]["run_challenge"]
            and right["loaded"]["run_challenge"] != left["receipt"]["run_challenge"]
        )
        deterministic_bindings_equal = canonical(
            deterministic_guard_binding(left["loaded"]["guard"])
        ) == canonical(deterministic_guard_binding(right["loaded"]["guard"]))
        concurrency_pass = (
            barrier.n_waiting == 0
            and all(run["complete_binding"] for run in concurrent)
            and all(distinct.values())
            and no_cross_trust
            and deterministic_bindings_equal
        )
        cases.append(
            {
                "name": "two_overlapping_full_guard_invocations",
                "pass": concurrency_pass,
                "barrier_parties": barrier.parties,
                "full_guard_invocations": len(concurrent),
                "both_complete_bindings": all(
                    run["complete_binding"] for run in concurrent
                ),
                "distinct": distinct,
                "no_overwrite_or_cross_trust": no_cross_trust,
                "deterministic_bindings_equal": deterministic_bindings_equal,
            }
        )

        def unrelated_error():
            raise RuntimeError("unrelated")

        unrelated = expect_rejected(
            "oracle_unrelated_runtime_error_probe",
            unrelated_error,
            "receipt_name_exists",
            "open_exclusive_receipt",
        )
        oracle_falsifier = {
            "pass": not unrelated["pass"]
            and unrelated["observed_class"] == "RuntimeError"
            and unrelated["observed_reason"] is None
            and unrelated["observed_seam"] is None,
            "probe": unrelated,
        }
    finally:
        shutil.rmtree(parent)

    result = {
        "schema": "gbrain.exact-target-receipt-safety-self-test.v1",
        "pass": len(cases) == 9
        and all(case["pass"] for case in cases)
        and oracle_falsifier["pass"],
        "case_count": len(cases),
        "cases": cases,
        "oracle_falsifier": oracle_falsifier,
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
    command_argv = [sys.executable, *sys.argv]
    summary, _receipt = execute_full_guard(
        repo,
        args.order,
        args.root,
        args.forbid_profile,
        command_argv,
    )
    if not summary["pass"]:
        raise ValueError("full pure import guard evidence did not pass")
    sys.stdout.write(canonical(summary) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        sys.stderr.write("%s\n" % error)
        raise SystemExit(1)
