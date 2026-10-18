# Cyber Review Workbench

When a security check says it passed, I want to see what ran and what supports that result.

Cyber Review Workbench is a small working example of that review. It runs fixed checks against a local test fixture, compares the results with a known-good control, saves the evidence and leaves the final decision to a person. It uses Python's standard library; no account, model, API key, database server or extra packages are required.

## Try it

Requires Python 3.11 or newer. Run from the repository root:

```bash
python3 -m cyber_review demo --workspace /tmp/cyber-review-demo --approve-local-fixture
python3 -m cyber_review status --workspace /tmp/cyber-review-demo
python3 -m cyber_review verify --workspace /tmp/cyber-review-demo
```

The approval flag permits only the fixture started by this command. It listens on `127.0.0.1` at an assigned port and stops when the command finishes. Four fixed HEAD requests check example headers and an anonymous denial response. Six action receipts, including two retests, are saved and read back.

A passing demo reports `recorded_synthetic_checks_passed`, with `operator_closed: false` and `security_certification: false`. The checks passed; the human review is still open.

To see a failed check, use a new evidence directory:

```bash
python3 -m cyber_review demo --workspace /tmp/cyber-review-negative --approve-local-fixture --simulate-missing-header
```

This removes three example headers from the candidate. The control passes, the result requires review, and the command exits with code 1. Existing nonempty evidence directories are preserved. Without the approval flag, the demo refuses before starting a server or creating evidence.

## What you can reuse

- `cyber_review/evidence.py` checks fixture hashes, coverage, results and retest receipts. Missing, duplicated, unfinished or conflicting evidence prevents a passing summary.
- `cyber_review/ledger.py` records an action before it runs and verifies the saved result. An action with an unknown outcome stays held and cannot replay.
- `cyber_review/fixture.py` demonstrates limited local permission, expiry, fixed request paths and bounded headers.
- The [review process](docs/review-process.md), [contracts](docs/contracts.md), [synthetic bundle](fixtures/synthetic-review-bundle.json) and JSON schemas explain the details.

## What the example proves

This release covers two synthetic cases. A header's presence does not prove its policy is correct, and an example 403 response does not prove real access controls. The control shares the fixture implementation; it is a regression check, not an independent security audit. Hashes check consistency, not authenticity, so protect the evidence store.

The demo accepts no external target URL, credentials, arbitrary commands or scan parameters. It follows no redirects, keeps no response bodies or raw header values, and does not retry automatically. `status` and `verify` read local evidence without contacting a worker. It does not scan or certify a system, and model commentary cannot make an incomplete record pass.

## Check the reference

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_release.py
```

Tests use temporary SQLite files and two small loopback fixtures. They cover passing and failed checks, scope refusal, expiry, duplicates, unknown outcomes and conflicting evidence.

Version **0.1.0**. Code: [MIT](LICENSE). The adapted method retains PLOS copyright and license notices; see [NOTICE.md](NOTICE.md) and [provenance](docs/provenance.md).

## Help keep it going

Thanks for taking a look. If you try the example, I would appreciate your feedback.

If this example helps you check your own work, an [optional one-time tip](https://github.com/sponsors/bherald?frequency=one-time) helps me keep testing. It does not buy support, access, priority or a deliverable.
