# A reviewable check has a chain of evidence

Start with the decision you need to make. Write a bounded coverage contract and
name the source or fixture the check applies to. A title such as “security
review passed” loses that scope; a record of two specific synthetic cases
preserves it.

## Before an action

1. Define the target, method, paths, source/profile fingerprints, expiry and
   retained evidence. Keep target selection outside model-generated arguments.
2. Obtain explicit authorization for those actions. In this reference, the
   operator chooses the included local fixture with `--approve-local-fixture`.
   The resulting scope records its exact loopback origin and four HEAD paths.
3. Recheck the scope, authorization, expiry and current fixture bytes before
   each request. Claim the original action identity durably before sending it.

This local CLI flag is a demonstration of an action gate. It is not a remote
permission system, a proof of customer consent or an authentication credential.
Connecting a real target requires a separate implementation and review of
ownership, authorization, transport, retention and operational limits.

## After an action

Persist the result under the original action identity. Read it back and compare
it with what the check produced. A received response and a saved receipt are
separate facts. If the request or persistence outcome is unknown, keep that
original receipt and require review. Inspect saved status instead of replaying
an action to find out whether it happened.

The reference saves only status, booleans for example header presence, timing
and fixed case labels. It does not retain bodies, cookies, banners, raw header
values or exception messages. The server handles only synthetic data.

## Before presenting a result

Match the retest to the candidate fingerprint, the declared coverage, a clean
control and exactly one successful saved receipt for that case. Reject missing
coverage, changed source hashes, failed controls, unexpected cases, unfinished
receipts or a conflicting second attempt.

The reference summary accepts these recorded checks as evidence of their own
bounded result. It deliberately ignores narrative claims and closure flags in
the input report. A summary always leaves human finding closure and security
certification false.

## Maintain the record

Keep the coverage contract with the source revision and receipts. Changes to a
fixture or its expected checks require a newly reviewed scope. Retain prior
results as history; do not silently overwrite them. Keep runtime evidence out
of source releases and use synthetic examples for demonstrations.

Separate these states in a real implementation: action authorized, action
claimed, request observed, result saved/read back, bounded checks complete,
finding reviewed and finding closed. This reference implements the action and
recorded-check stages only. It has no finding-closing or remediation command.
