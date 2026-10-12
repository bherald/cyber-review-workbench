"""Run a tiny owned-local-fixture demo or inspect existing evidence offline."""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

from .evidence import summarize
from .fixture import CASES, HEADERS, digest, local_fixture, make_grant, make_scope, observe, source_digest
from .ledger import Ledger, Refused, status


def save(path, value):
    """Create a new private demo artifact; never replace an existing evidence file."""
    content = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    with path.open("x", encoding="utf-8") as handle:
        path.chmod(0o600)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    if json.loads(path.read_text()) != value:
        raise Refused("Artifact readback failed.")


def check_case(case, observation, artifact_hash):
    failed = []
    if not observation.get("complete"):
        failed.append("observation_incomplete")
    elif case == "header_presence":
        failed = [header for header in HEADERS if not observation["security_headers_present"].get(header)]
        if observation["http_status"] != 200:
            failed.append("unexpected_response_status")
    elif observation["http_status"] not in (401, 403):
        failed.append("anonymous_request_not_denied")
    coverage = len(HEADERS) + 1 if case == "header_presence" else 1
    return {"case_id": case, "status": "complete_clean" if not failed else "checks_failed",
            "coverage": coverage, "failed_checks": failed, "source_sha256": artifact_hash}


def run_demo(workspace, approved, negative=False):
    if approved is not True:
        raise Refused("Use --approve-local-fixture to authorize only the included local synthetic fixture.")
    workspace = Path(workspace)
    if workspace.is_symlink() or (workspace.exists() and (not workspace.is_dir() or any(workspace.iterdir()))):
        raise Refused("Use a new or empty local evidence directory; existing evidence is preserved.")
    workspace.mkdir(parents=True, exist_ok=True)
    workspace.chmod(0o700)
    policy_path = Path(__file__).resolve().parents[1] / "fixtures/local-fixture.json"
    policy = json.loads(policy_path.read_text())
    if negative:
        policy["candidate"]["security_headers"] = False
    ledger = Ledger(workspace / "receipts.sqlite")
    try:
        with local_fixture(policy) as origin:
            now = int(time.time())
            scope = make_scope(origin, policy, now)
            grant = make_grant(scope, approved, now)
            scope_hash = digest(scope)
            save(workspace / "scope.json", scope)
            save(workspace / "authorization.json", grant)
            observations = {}
            for role in ("candidate", "clean_control"):
                for case, suffix in CASES.items():
                    observations[(role, case)] = observe(scope, grant, scope_hash, policy, f"/{role}/{suffix}", ledger)
                    if not observations[(role, case)]["complete"]:
                        raise Refused("Observation incomplete. Inspect original receipts; do not replay.")
            hashes = {role: digest({"fixture_source_sha256": source_digest(), "profile": policy[role], "role": role})
                      for role in ("candidate", "clean_control")}
            report = {"schema": "cyber-review.report.v1", "scope_sha256": scope_hash, "error": None, "results": {"candidate_hashes": {}, "clean_control_hashes": {}, "retests": {}}}
            contract = {}
            for case in CASES:
                retest = check_case(case, observations[("candidate", case)], hashes["candidate"])
                retest["clean_holdout"] = check_case(case, observations[("clean_control", case)], hashes["clean_control"])
                action_id = "retest:" + case
                ledger.claim(action_id, scope_hash, {"name": "retest_candidate", "arguments": {"case_id": case}})
                success = retest["status"] == retest["clean_holdout"]["status"] == "complete_clean"
                ledger.complete(action_id, retest, success=success)
                report["results"]["candidate_hashes"][case] = hashes["candidate"]
                report["results"]["clean_control_hashes"][case] = hashes["clean_control"]
                report["results"]["retests"][case] = retest
                contract[case] = retest["coverage"]
            receipts = ledger.receipts()
            summary = summarize(report, receipts, contract)
            save(workspace / "report.json", report)
            save(workspace / "coverage.json", contract)
            save(workspace / "receipts.json", receipts)
            save(workspace / "summary.json", summary)
            return summary
    finally:
        ledger.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Run only the included synthetic loopback fixture")
    demo.add_argument("--workspace", type=Path, required=True)
    demo.add_argument("--approve-local-fixture", action="store_true", help="Explicitly authorize the included loopback HEAD cases")
    demo.add_argument("--simulate-missing-header", action="store_true", help="Show a deliberately incomplete synthetic check")
    view = commands.add_parser("status", help="Read saved receipt states without network access")
    view.add_argument("--workspace", type=Path, required=True)
    verify = commands.add_parser("verify", help="Check stored report/receipt/coverage JSON offline")
    verify.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            result = run_demo(args.workspace, args.approve_local_fixture, args.simulate_missing_header)
        elif args.command == "status":
            result = status(args.workspace / "receipts.sqlite")
        else:
            result = summarize(*(json.loads((args.workspace / name).read_text()) for name in ("report.json", "receipts.json", "coverage.json")))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("status", "recorded_synthetic_checks_passed") == "recorded_synthetic_checks_passed" else 1
    except (Refused, OSError, ValueError, sqlite3.Error):
        print(json.dumps({"status": "refused_or_incomplete", "operator_review_required": True,
                          "automatic_replay_allowed": False, "operator_closed": False}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
