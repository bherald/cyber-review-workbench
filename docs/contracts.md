# Reference contracts

The JSON schemas describe version 1 reference documents. The code applies
its own strict local execution-scope validation; it does not require a JSON
Schema package. A consumer can use a separate schema validator.

| Document | Meaning |
| --- | --- |
| Scope | Exact loopback origin, HEAD method, four fixed paths, source/profile hashes, ten-minute expiry and disabled credentials/body retention/replay |
| Authorization | Explicit operator local-fixture intent bound to that exact scope hash and approval time |
| Observation | Fixed path, status, boolean header presence, duration and body/credential/redirect retention limits |
| Retest | Case ID, expected check count, failed checks, source fingerprint and clean-control evidence |
| Action receipt | Original action, scope hash, started/completed/unknown state and saved result |
| Summary | Recorded case completion, problems and human-owned decision boundaries |

Each hash is SHA-256. Structured values use sorted-key compact JSON. Candidate
and control hashes bind the fixture module bytes, profile and role. They do not
represent a deployed application's source, a container image or a third-party
scanner. The public synthetic review bundle uses this reference format.

`header_presence` declares four checks: status 200 and presence of the three
example headers. `anonymous_denial` declares one check: status 401 or 403.
The supplied control uses status 403 and all three example headers. An observed
200 on the restricted fixture would fail the anonymous-denial case.

The verifier treats JSON object-key order as irrelevant. Integer and exact
whole-number floating representations can match their JSON round trip; boolean
values, numeric strings and reordered lists do not match.

A local receipt database is ordinary SQLite. Its action key prevents an
accidental duplicate dispatch through this implementation. The table schema is
in `schemas/receipt-ledger.sql`. It is not append-only storage, a signed audit
log or a multi-tenant authorization system. Someone able to rewrite all trusted
inputs can fabricate a consistent record; a deployment needs its own protected
storage and independent provenance.

The saved JSON snapshots support offline review. `verify` checks their mutual
consistency, while `status` reads the original SQLite action states. Neither
performs an independent audit or checks a live target. Exit codes are 0 for
recorded synthetic checks passing or a status read, 1 for incomplete evidence,
and 2 for refusal, invalid input or an operational failure.
