# A security result should come with evidence you can check

By Bill Herald

A report says a problem was found. Another says it was fixed. Before accepting either statement, I want to know what was checked, which version was checked and what the recorded result actually showed. A useful explanation can help someone understand the work, but it should not replace the evidence.

I am preparing Cyber Review Workbench as a small public reference project around that idea. Its purpose is to make a bounded check inspectable, keep uncertain outcomes visible and leave the final finding with a human reviewer. It is a way to organize and verify evidence from a defined check. It is not a claim that a whole application or network is secure.

Consider a fictional example. A demonstration service is supposed to return a particular HTTP response to a HEAD request. We save the expected result, make one permitted request and record what came back. Later, the example changes. A new check should be tied to the new candidate and its expected result. Reusing an older successful receipt would tell us something about the old example, but nothing conclusive about the changed one.

That is why the connection between the candidate and the receipt matters. The workbench method binds the reviewed candidate to its source hash and compares the saved result with the exact expectation. A retest is its own recorded attempt. The reviewer should be able to see whether it matches the candidate being reviewed, rather than finding a reassuring result from some other version.

The control case matters too. If a check is supposed to distinguish a problem from an ordinary response, show the clean case as well. Keep the required coverage visible. An incomplete set of cases should remain incomplete; a good result in one case should not quietly stand in for every case that was planned.

The public demonstration uses a local fixture and synthetic records. Its HTTP boundary is deliberately narrow: a HEAD-only check against the loopback fixture, with no credentials, redirects or retained response body. There is no customer system, private target or production finding in the examples. The fixture helps demonstrate the evidence contract without requiring somebody to scan another person's services.

The prepared demonstration makes four fixed requests for candidate and control cases, checking header presence and an anonymous-denial response. Missing required headers leave the candidate review incomplete while the clean control can pass. Header presence is not policy correctness, and a denial status is not proof of a complete authentication system.

The implementation uses the Python standard library so the evidence example can be inspected without installing a model or a large tool stack. I want the input records, result checks and failure conditions to be understandable. A failed verification should identify the mismatch or missing coverage, not produce a broader assurance than the check supports.

One attempt per case is part of the method. If an action's outcome is uncertain, repeating it automatically can hide the uncertainty or perform the action twice. Retain the original attempt and inspect its recorded state. Decide explicitly whether a new attempt is appropriate, and label that new attempt so it cannot be mistaken for the old result.

AI can help explain a result, organize a report or suggest what a reviewer should examine. Its commentary is a different artifact from the recorded check. A confident paragraph does not repair a missing receipt, change the source version or establish that an untested case passed. The useful role is to make the evidence easier to review while retaining the facts, contradictions and limits of what was actually observed.

Human review also needs a clear ending. Verifying a receipt does not automatically close a security finding. The reviewer still has to decide whether the check addresses the concern, whether the expected result was appropriate and what remains outside its scope. A machine-generated summary should keep that decision open rather than announce that the whole system has passed.

The same distinction applies to hashes. A hash can help show that the reviewed file changed or that a receipt corresponds to a particular artifact. It does not, by itself, establish who created the record or whether the check was a good test. Keep the source, the expected result and the recorded outcome available so someone can inspect the relationship.

I see this as useful for developers reviewing a small correction, teams comparing a candidate with a control and people who need to explain why a finding is still open. The public project is intentionally a reference workbench with synthetic examples. It does not publish private security findings, enable an observer on somebody's network or certify a completed security assessment.

My next step is to use the small example to make the review process easy to follow: inspect the candidate, inspect the expected result, verify the saved receipt and decide what the evidence supports. A result worth sharing should come with enough context for another person to check it. That is the purpose of Cyber Review Workbench.
