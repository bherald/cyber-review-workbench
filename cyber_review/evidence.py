"""Recorded synthetic evidence summary, adapted from MIT-licensed PLOS logic.

Copyright (c) 2026 PLOS Contributors. See LICENSE and NOTICE.md.
"""

import json
import math
import re

SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def same_evidence(left, right):
    """Ignore object-key order and integer/whole-float serialization differences."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if type(left) in (int, float) and type(right) in (int, float):
        return (type(left) is int or math.isfinite(left)) and (type(right) is int or math.isfinite(right)) and left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_evidence(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same_evidence(a, b) for a, b in zip(left, right))
    return left == right


def summarize(report, receipts, expected_coverage):
    """Recorded checks remain separate from prose, human closure and certification."""
    problems, completed = [], []
    if not isinstance(report, dict) or not isinstance(receipts, list) or not isinstance(expected_coverage, dict):
        return _summary([], [], ["invalid_evidence_document"])
    scope_hash = report.get("scope_sha256")
    if report.get("schema") != "cyber-review.report.v1" or not isinstance(scope_hash, str) or not SHA256.fullmatch(scope_hash):
        problems.append("invalid_report_scope")
    results = report.get("results", {})
    if not isinstance(results, dict):
        return _summary([], list(expected_coverage), ["invalid_evidence_document"])
    retests = results.get("retests", {})
    hashes = results.get("candidate_hashes", {})
    control_hashes = results.get("clean_control_hashes", {})
    if not isinstance(retests, dict) or not isinstance(hashes, dict) or not isinstance(control_hashes, dict):
        return _summary([], list(expected_coverage), ["invalid_evidence_document"])
    if report.get("error") is not None or not expected_coverage:
        problems.append("run_error_or_missing_coverage_contract")
    if any(not isinstance(receipt, dict) or receipt.get("state") != "completed" for receipt in receipts):
        problems.append("unfinished_action_receipt")
    for receipt in receipts:
        document = receipt.get("document", {}) if isinstance(receipt, dict) else {}
        if not isinstance(document, dict) or document.get("scope_sha256") != scope_hash:
            problems.append("receipt_scope_mismatch")
    for case, coverage in expected_coverage.items():
        retest = retests.get(case, {})
        candidate_hash = hashes.get(case)
        control_hash = control_hashes.get(case)
        valid = type(coverage) is int and coverage > 0 and isinstance(candidate_hash, str) and SHA256.fullmatch(candidate_hash)
        valid = bool(valid and isinstance(control_hash, str) and SHA256.fullmatch(control_hash)
                     and isinstance(retest, dict) and retest.get("source_sha256") == candidate_hash
                     and isinstance(retest.get("clean_holdout"), dict)
                     and retest["clean_holdout"].get("source_sha256") == control_hash)
        for check in (retest, retest.get("clean_holdout", {}) if isinstance(retest, dict) else {}):
            valid = bool(valid and isinstance(check, dict) and check.get("case_id") == case
                         and check.get("status") == "complete_clean" and type(check.get("coverage")) is int
                         and check.get("coverage") == coverage and check.get("failed_checks") == [])
        attempts, matches = 0, 0
        for receipt in receipts:
            if not isinstance(receipt, dict):
                continue
            document = receipt.get("document", {})
            if not isinstance(document, dict):
                continue
            action = document.get("action", {})
            if not isinstance(action, dict):
                continue
            arguments = action.get("arguments", {})
            if action.get("name") != "retest_candidate" or not isinstance(arguments, dict) or arguments.get("case_id") != case:
                continue
            attempts += 1
            result = document.get("result", {})
            if not isinstance(result, dict):
                continue
            recorded = result.get("evidence")
            if isinstance(recorded, dict) and recorded.get("operator_closed") is False:
                recorded = {key: value for key, value in recorded.items() if key != "operator_closed"}
            if receipt.get("state") == "completed" and document.get("outcome") == "succeeded" and result.get("success") is True and same_evidence(recorded, retest):
                matches += 1
        if valid and attempts == matches == 1:
            completed.append(case)
        else:
            problems.append("unverified_retest:" + str(case))
    if set(retests) - set(expected_coverage):
        problems.append("unexpected_retest_cases")
    return _summary(completed, list(expected_coverage), list(dict.fromkeys(problems)))


def _summary(completed, expected, problems):
    passed = not problems
    return {"schema": "cyber-review.summary.v1",
            "status": "recorded_synthetic_checks_passed" if passed else "review_incomplete_evidence",
            "text": (f"{len(completed)} synthetic cases passed recorded candidate and clean-control checks. Human review remains open."
                     if passed else "Recorded evidence is incomplete or inconsistent. Human review remains open."),
            "completed_cases": sorted(completed), "expected_cases": sorted(expected), "problems": problems,
            "operator_closed": False, "security_certification": False, "model_commentary_authoritative": False}
