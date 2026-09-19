# Annotation trust boundary

Email headers, subject, body, URLs and attachments are untrusted. MIME parsing never
executes attachment content or loads an external resource. Streamlit displays email
and model prose with plain text; URLs are defanged. Uploaded HTML is never injected
into the browser. The stored public-suffix snapshot avoids implicit network fetches.

The trusted path is the fitted model artifact, its embedded blend and policy, and
versioned deterministic rules. The engine computes the score and tier first, then
passes a frozen tier to enrichment. The annotation schema has no score or tier field
and rejects unknown fields. Adding an instruction to an email can legitimately alter
the upstream ML score; the claim is that the LLM cannot alter the completed decision.

Enrichment normalizes NFKC, strips Unicode controls including zero-width characters,
limits text length, serializes evidence as JSON and places the body between freshly
randomized delimiters. The system prompt forbids following email instructions. Ollama
has no tools and is constrained to loopback HTTP, with proxy inheritance disabled,
redirects refused, a read timeout, a context limit and a generation-token cap.
The read timeout is an idle-read timeout, not a hard whole-process deadline. A hostile
local service is outside this prototype's trust boundary. Triage has already completed
before an analyst requests enrichment, and failures return a visible fallback.

Schema validation checks shape, action enumeration, length and numeric confidence.
Exact instruction fragments, a test sentinel and active URL/markup patterns are
rejected. These controls are defense in depth, not a reliable detector of all injected
instructions. The LLM may still make an unsupported recommendation. No actual secret
should be placed in the system prompt. Self-reported confidence is not calibrated.

The generated red-team report distinguishes invariant checks from live model results.
When Ollama is absent, `make redteam` checks fallback behavior and structural separation;
`make redteam-live` exits nonzero rather than report live coverage. A report does not
claim that a mitigation fixed a failure that was never observed.

Local files are not encrypted by this application. FileVault and workstation access
controls are operator responsibilities. Audit excludes message content; explicitly
retained feedback examples and optional observation records contain email data.
No real email is added to version control by the supplied ignore rules. Historical
corpora remain subject to publisher terms, even when publicly downloadable.
