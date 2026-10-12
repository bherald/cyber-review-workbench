# Cyber Review Workbench

A security result should come with evidence you can check.

Cyber Review Workbench is a small, runnable reference for reviewing security
checks: bind the check to a specific fixture, record what actually ran, compare
it with a known-good control, and keep the human decision separate from the
machine's summary.

The first release includes a deterministic evidence verifier and a synthetic
HTTP fixture. It uses Python's standard library. No account, model, API key,
database server or dependency installation is required.

## Try it

Requires Python 3.11 or newer. Run these commands from the repository root:

```bash
python3 -m cyber_review demo --workspace /tmp/cyber-review-demo --approve-local-fixture
python3 -m cyber_review status --workspace /tmp/cyber-review-demo
python3 -m cyber_review verify --workspace /tmp/cyber-review-demo
```

The approval flag authorizes only the fixture started by this command. The
fixture listens on `127.0.0.1` at an automatically assigned port and stops when
the command finishes. Four fixed HEAD requests check header presence and an
anonymous denial response for the candidate and clean control. Six original
action receipts are saved and read back, including the two case retests.

A clean demo reports `recorded_synthetic_checks_passed`. It also reports
`operator_closed: false` and `security_certification: false`. The recorded
checks passed; the human review remains open.

See a failed check with a new evidence directory:

```bash
python3 -m cyber_review demo --workspace /tmp/cyber-review-negative --approve-local-fixture --simulate-missing-header
```

This deliberately removes the candidate's three example headers. The control
passes; the summary requires review and the command exits with code 1.
An existing nonempty evidence directory is preserved and cannot be reused
by the demo. Without the explicit approval flag, the command refuses before
starting a server or creating evidence.

## What you can reuse

- `cyber_review/evidence.py`: compare the coverage contract, fixture hashes,
  candidate/control results and the exact saved retest receipt. Missing,
  duplicated, unfinished or conflicting receipts prevent a passing summary.
- `cyber_review/ledger.py`: claim an action identity before its effect, save
  its result, and verify the saved readback. An unknown outcome stays held;
  the original action cannot replay.
- `cyber_review/fixture.py`: demonstrate exact local scope, expiring explicit
  authorization, fixed HEAD paths, bounded response headers and minimal
  evidence retention.
- [Review process](docs/review-process.md), [contracts](docs/contracts.md),
  [synthetic bundle](fixtures/synthetic-review-bundle.json) and JSON schemas:
  make the method inspectable before connecting another tool.

## Scope and limits

This release exercises two synthetic cases. It accepts no external target URL,
credentials, arbitrary commands or scan parameters. It follows no redirects,
retains no response body or raw header values, and performs no automatic retry.
`status` and `verify` read local evidence without contacting a worker.

A header's presence does not establish that its policy is correct. A synthetic
403 response does not prove real authentication or authorization. The control
shares the fixture implementation; it is a regression control, not an
independent security audit. Hashes and receipt equality establish consistency,
not cryptographic authenticity. Protect the local evidence store.

The workbench does not certify a system, close findings, perform vulnerability
scanning or provide complete product coverage. Model commentary, if supplied
in a report, cannot turn an incomplete record into a pass.

## Verify the reference

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_release.py
```

The tests use temporary SQLite files and two tiny owned loopback fixtures.
They cover both passing and failed checks, scope refusal, expiry, duplicate
execution, unknown outcomes and conflicting evidence.

Version: **0.1.0**. License: **MIT**. The adapted evidence method retains
PLOS copyright and license notices; see [NOTICE.md](NOTICE.md) and
[provenance](docs/provenance.md).
