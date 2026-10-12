import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cyber_review.__main__ import run_demo
from cyber_review.evidence import same_evidence, summarize
from cyber_review.fixture import PATHS, digest, make_grant, make_scope, observe
from cyber_review.ledger import Ledger, Refused, status

POLICY = {"schema": "cyber-review.fixture.v1", "candidate": {"security_headers": True, "unauthenticated_status": 403},
          "clean_control": {"security_headers": True, "unauthenticated_status": 403}}


def recorded_evidence():
    check = {"case_id": "fixture", "status": "complete_clean", "coverage": 2, "failed_checks": [], "source_sha256": "a" * 64}
    retest = dict(check, clean_holdout=dict(check, source_sha256="b" * 64))
    report = {"schema": "cyber-review.report.v1", "scope_sha256": "c" * 64, "error": None, "results": {"candidate_hashes": {"fixture": "a" * 64}, "clean_control_hashes": {"fixture": "b" * 64}, "retests": {"fixture": retest}}}
    receipt = {"state": "completed", "document": {"scope_sha256": "c" * 64, "action": {"name": "retest_candidate", "arguments": {"case_id": "fixture"}},
               "outcome": "succeeded", "result": {"success": True, "evidence": copy.deepcopy(retest)}}}
    return report, [receipt], {"fixture": 2}


class EvidenceTest(unittest.TestCase):
    def test_narrative_and_closed_flags_cannot_certify_or_close(self):
        report, receipts, coverage = recorded_evidence()
        report.update(passed=True, operator_closed=True, commentary="Every system is secure.")
        result = summarize(report, receipts, coverage)
        self.assertEqual("recorded_synthetic_checks_passed", result["status"])
        for key in ("operator_closed", "security_certification", "model_commentary_authoritative"):
            self.assertIs(False, result[key])
        self.assertNotIn("Every system", result["text"])

    def test_missing_duplicate_conflicting_and_unfinished_receipts_require_review(self):
        report, receipts, coverage = recorded_evidence()
        failed = copy.deepcopy(receipts[0])
        failed["document"]["result"]["success"] = False
        for variant in ([], receipts * 2, [failed], receipts + [failed], receipts + [{"state": "started"}]):
            with self.subTest(variant=variant):
                self.assertEqual("review_incomplete_evidence", summarize(report, variant, coverage)["status"])

    def test_changed_source_coverage_or_control_invalidates_pass(self):
        report, receipts, coverage = recorded_evidence()
        variants = []
        changed = copy.deepcopy(report)
        changed["results"]["candidate_hashes"]["fixture"] = "c" * 64
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["results"]["retests"]["fixture"]["clean_holdout"]["failed_checks"] = ["control_failed"]
        variants.append(changed)
        for changed in variants:
            self.assertEqual("review_incomplete_evidence", summarize(changed, receipts, coverage)["status"])
        self.assertEqual("review_incomplete_evidence", summarize(report, receipts, {"fixture": 3})["status"])
        self.assertEqual("review_incomplete_evidence", summarize(report, receipts, {"fixture": True})["status"])

    def test_mismatched_receipt_scope_or_control_source_requires_review(self):
        report, receipts, coverage = recorded_evidence()
        changed = copy.deepcopy(receipts)
        changed[0]["document"]["scope_sha256"] = "d" * 64
        self.assertIn("receipt_scope_mismatch", summarize(report, changed, coverage)["problems"])
        report["results"]["clean_control_hashes"]["fixture"] = "d" * 64
        self.assertEqual("review_incomplete_evidence", summarize(report, receipts, coverage)["status"])

    def test_json_object_order_is_irrelevant_but_types_and_list_order_match(self):
        self.assertTrue(same_evidence({"a": 331.0, "b": [1, 2]}, {"b": [1, 2], "a": 331}))
        for changed in ("331", 331.25, True, None):
            self.assertFalse(same_evidence(331.0, changed))
        self.assertFalse(same_evidence([1, 2], [2, 1]))
        self.assertFalse(same_evidence(float("nan"), float("nan")))
        self.assertTrue(same_evidence(10 ** 1000, 10 ** 1000))

    def test_extra_retest_invalidates_coverage(self):
        report, receipts, coverage = recorded_evidence()
        report["results"]["retests"]["unreviewed"] = {}
        self.assertIn("unexpected_retest_cases", summarize(report, receipts, coverage)["problems"])

    def test_malformed_receipt_and_report_do_not_pass(self):
        report, receipts, coverage = recorded_evidence()
        receipts[0]["document"]["action"]["arguments"] = None
        self.assertEqual("review_incomplete_evidence", summarize(report, receipts, coverage)["status"])
        self.assertEqual("review_incomplete_evidence", summarize(None, None, None)["status"])


class PublicExampleTest(unittest.TestCase):
    def test_committed_synthetic_bundle_is_consistent_with_saved_summary(self):
        root = Path(__file__).resolve().parents[1]
        bundle = json.loads((root / "fixtures/synthetic-review-bundle.json").read_text())
        self.assertEqual(bundle["summary"], summarize(bundle["report"], bundle["receipts"], bundle["coverage"]))
        self.assertEqual(6, len(bundle["receipts"]))
        self.assertFalse(bundle["summary"]["operator_closed"])
        for schema in (root / "schemas").glob("*.json"):
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", json.loads(schema.read_text())["$schema"])


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = Ledger(Path(self.tmp.name) / "receipts.sqlite")
        self.addCleanup(self.ledger.close)
        self.scope = make_scope("http://127.0.0.1:12345", POLICY, 100)
        self.grant = make_grant(self.scope, True, 100)
        self.hash = digest(self.scope)

    def refused_without_contact(self, scope=None, grant=None, path=PATHS[0], now=101):
        with patch("cyber_review.fixture.http.client.HTTPConnection") as connection:
            with self.assertRaises(Refused):
                observe(scope if scope is not None else self.scope, grant if grant is not None else self.grant,
                        self.hash, POLICY, path, self.ledger, now)
            connection.assert_not_called()

    def test_expired_or_absent_authorization_is_refused_before_network(self):
        self.refused_without_contact(now=700)
        self.refused_without_contact(grant={})
        with self.assertRaises(Refused):
            make_grant(self.scope, False, 100)

    def test_external_origin_dns_alias_query_and_path_are_refused(self):
        for origin in ("https://example.org:443", "http://localhost:12345", "http://127.0.0.1:12345?x=1", "http://127.0.0.1:65536"):
            scope = dict(self.scope, origin=origin)
            self.refused_without_contact(scope=scope)
        self.refused_without_contact(path="/candidate/headers?x=1")
        self.refused_without_contact(path="/new-target")

    def test_changed_scope_source_profile_and_credentials_are_refused(self):
        for changes in ({"method": "POST"}, {"request_credentials": True}, {"fixture_source_sha256": "f" * 64}, {"profile_sha256": "f" * 64}):
            self.refused_without_contact(scope=dict(self.scope, **changes))

    def test_duplicate_action_cannot_replay_request(self):
        self.ledger.claim("head:" + PATHS[0], self.hash, {"name": "observe_local_fixture"})
        self.refused_without_contact()
        self.assertEqual("started", self.ledger.receipt("head:" + PATHS[0])["state"])

    def test_transport_failure_retains_unknown_receipt_without_retry(self):
        with patch("cyber_review.fixture.http.client.HTTPConnection") as connection:
            connection.return_value.getresponse.side_effect = OSError("synthetic transport failure")
            result = observe(self.scope, self.grant, self.hash, POLICY, PATHS[0], self.ledger, 101)
            self.assertFalse(result["complete"])
            self.assertEqual(1, connection.return_value.request.call_count)
            self.assertEqual("outcome_unknown", self.ledger.receipt("head:" + PATHS[0])["state"])
            self.assertNotIn("synthetic transport", json.dumps(result))
        self.refused_without_contact()

    def test_status_is_read_only_and_makes_no_network_request(self):
        self.ledger.claim("original", self.hash, {"name": "synthetic"})
        with patch("cyber_review.fixture.http.client.HTTPConnection") as connection:
            result = status(self.ledger.path)
            connection.assert_not_called()
        self.assertFalse(result["network_contacted"])
        self.assertFalse(result["automatic_replay_allowed"])


class LocalDemoTest(unittest.TestCase):
    def test_no_approval_has_no_workspace_or_server_effect(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "unapproved"
            with patch("cyber_review.__main__.local_fixture") as server:
                with self.assertRaises(Refused):
                    run_demo(directory, False)
                server.assert_not_called()
            self.assertFalse(directory.exists())

    def test_approved_local_demo_and_saved_evidence_are_verifiable(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "positive"
            result = run_demo(directory, True)
            self.assertEqual("recorded_synthetic_checks_passed", result["status"])
            self.assertEqual(2, len(result["completed_cases"]))
            self.assertFalse(result["operator_closed"])
            self.assertFalse(result["security_certification"])
            receipts = json.loads((directory / "receipts.json").read_text())
            self.assertEqual(6, len(receipts))
            scope = json.loads((directory / "scope.json").read_text())
            self.assertTrue(scope["origin"].startswith("http://127.0.0.1:"))
            self.assertEqual(4, len(scope["paths"]))
            for receipt in receipts:
                evidence = receipt["document"]["result"]["evidence"]
                self.assertNotIn("body", evidence)
                self.assertNotIn("cookies", evidence)
                self.assertNotIn("header_values", evidence)
            with self.assertRaises(Refused):
                run_demo(directory, True)

    def test_missing_candidate_headers_fail_while_clean_control_passes(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "negative"
            result = run_demo(directory, True, negative=True)
            self.assertEqual("review_incomplete_evidence", result["status"])
            report = json.loads((directory / "report.json").read_text())
            retest = report["results"]["retests"]["header_presence"]
            self.assertEqual(3, len(retest["failed_checks"]))
            self.assertEqual("complete_clean", retest["clean_holdout"]["status"])
            self.assertFalse(result["operator_closed"])


if __name__ == "__main__":
    unittest.main()
