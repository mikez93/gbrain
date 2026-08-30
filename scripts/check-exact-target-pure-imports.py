#!/usr/bin/env python3
"""AST-backed transitive import/effect guard for exact-target pure roots."""

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys


PROFILE = {
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


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def safe_repo_file(repo, value):
    candidate = (repo / value).resolve() if not pathlib.Path(value).is_absolute() else pathlib.Path(value).resolve()
    try:
        relative = candidate.relative_to(repo)
    except ValueError as error:
        raise ValueError("path escapes repository: %s" % value) from error
    before = candidate.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("unsafe source module: %s" % relative)
    data = candidate.read_bytes()
    after = candidate.stat()
    if before.st_dev != after.st_dev or before.st_ino != after.st_ino:
        raise ValueError("source module changed while reading: %s" % relative)
    return candidate, relative.as_posix(), data


def resolve_relative(repo, importer, specifier):
    base = importer.parent / specifier
    candidates = [base]
    if not base.suffix:
        candidates.extend(
            pathlib.Path(str(base) + suffix)
            for suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs")
        )
        candidates.extend(base / ("index" + suffix) for suffix in (".ts", ".tsx", ".js"))
    existing = [path for path in candidates if path.exists()]
    if len(existing) != 1:
        raise ValueError("unresolved or ambiguous import %s from %s" % (specifier, importer))
    _, relative, _ = safe_repo_file(repo, existing[0])
    return relative


def run_ast_scanner(repo, paths):
    command = ["bun", "scripts/exact-target-typescript-ast.ts", "--json"]
    for path in paths:
        command.extend(["--scan-file", path])
    completed = subprocess.run(
        command,
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("AST scanner failed: %s" % completed.stderr.strip())
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("AST scanner returned invalid JSON") from error
    scans = result.get("scans")
    if not result.get("pass") or not isinstance(scans, list):
        raise ValueError("AST scanner did not return a trusted result")
    return scans, result


def inspect(repo, roots, profile):
    if profile != PROFILE["id"]:
        raise ValueError("unsupported forbid profile: %s" % profile)
    pending = []
    for root in roots:
        _, relative, _ = safe_repo_file(repo, root)
        if relative not in pending:
            pending.append(relative)
    resolved = []
    edges = []
    source_hashes = {}
    violations = []
    ast_binding = None

    while pending:
        batch = sorted(set(pending) - set(resolved))
        pending = []
        if not batch:
            break
        scans, ast_binding = run_ast_scanner(repo, batch)
        by_label = {scan.get("label"): scan for scan in scans}
        for relative in batch:
            path, _, data = safe_repo_file(repo, relative)
            scan = by_label.get(relative)
            if not isinstance(scan, dict):
                raise ValueError("AST result missing source: %s" % relative)
            if scan.get("has_error"):
                violations.append({"kind": "parse_error", "path": relative})
            for violation in scan.get("violations", []):
                violations.append(
                    {
                        "kind": violation.get("kind", "ast_violation"),
                        "path": relative,
                        "start": violation.get("start"),
                        "end": violation.get("end"),
                    }
                )
            source_hashes[relative] = sha256_bytes(data)
            resolved.append(relative)
            for fragment in PROFILE["forbidden_path_fragments"]:
                if fragment in relative:
                    violations.append({"kind": "forbidden_resolved_path", "path": relative})
            for specifier in scan.get("imports", []):
                if specifier.startswith("."):
                    target = resolve_relative(repo, path, specifier)
                    edges.append([relative, target])
                    if target not in resolved:
                        pending.append(target)
                elif specifier in PROFILE["allowed_bare_imports"]:
                    edges.append([relative, specifier])
                else:
                    violations.append(
                        {
                            "kind": "unapproved_bare_import",
                            "path": relative,
                            "specifier": specifier,
                        }
                    )

    resolved = sorted(set(resolved))
    edges = sorted({tuple(edge) for edge in edges})
    edge_lists = [list(edge) for edge in edges]
    graph_material = {"roots": roots, "modules": source_hashes, "edges": edge_lists}
    result = {
        "schema": "gbrain.exact-target-pure-import-guard.v1",
        "profile": profile,
        "profile_sha256": sha256_bytes(canonical(PROFILE).encode("utf-8")),
        "roots": roots,
        "resolved_transitive_modules": resolved,
        "module_sha256": dict(sorted(source_hashes.items())),
        "edge_count": len(edge_lists),
        "edges": edge_lists,
        "graph_sha256": sha256_bytes(canonical(graph_material).encode("utf-8")),
        "scanner_sha256": sha256_bytes(
            (repo / "scripts/check-exact-target-pure-imports.py").read_bytes()
        ),
        "ast_scanner_sha256": sha256_bytes(
            (repo / "scripts/exact-target-typescript-ast.ts").read_bytes()
        ),
        "ast_evidence_sha256": ast_binding.get("evidence_sha256") if ast_binding else None,
        "forbidden_matches": sorted(
            violations,
            key=lambda item: canonical(item),
        ),
        "forbidden_match_count": len(violations),
        "dynamic_import_matches": sum(
            1 for item in violations if item.get("kind") == "dynamic_import"
        ),
        "environment_access_matches": sum(
            1
            for item in violations
            if item.get("kind") in ("forbidden_global_access", "forbidden_global_call")
        ),
    }
    result["pass"] = result["forbidden_match_count"] == 0
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--forbid-profile", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    repo = pathlib.Path(args.repo).resolve()
    result = inspect(repo, args.root, args.forbid_profile)
    sys.stdout.write(canonical(result) + "\n")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        sys.stderr.write("%s\n" % error)
        raise SystemExit(1)
