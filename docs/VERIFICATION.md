# Verification record

Verified on the local Apple Silicon host using Python 3.11.15, NumPy 1.26.4 and
scikit-learn 1.6.1. This is not an 8 GB MacBook Air memory benchmark.

| Actual workflow | Observed result |
|---|---|
| Public corpus acquisition and build | 3,979 source messages; 3,623 deduplicated; 2,536 / 543 / 544 train, validation and test records |
| Full three-model nested comparison | Completed in 395.85 seconds; calibrated logistic regression selected by five-fold PR-AUC |
| Exact installed CLI | `triageai analyze tests/fixtures/reported.eml --json` returned a schema-valid decision and appended its audit |
| Batch CLI replay | 240 alerts; 204 benign / 36 malicious; complete report and per-decision audit |
| Offline red-team command | 30/30 invariant/schema checks passed; five held-out ML evasion transformations measured |
| Real Streamlit queue | 240 alerts visibly sorted by descending risk; risk, tier, red flags, defanged URLs and ATT&CK hypotheses displayed |
| Real explanation panel | Opened and displayed signed feature contributions from the fitted model |
| Real enrichment button | Accepted CPU-model summary displayed for “24 Hours Deadline”; audit records llm_used=true, 5.37 s. Score stayed 87.2% and tier ANALYST-REVIEW. Also observed timeout, malformed-output and guard-rejection fallbacks. |
| Real feedback form | Saved an unadjudicated test review; success message appeared and the matching JSONL record was read from disk |
| Real email upload | Uploaded the 0.5 KB MIME fixture; the console showed its subject, sender, risk, rules and defanged links. The final upload control displayed a 2 MB limit. |
| Metrics dashboard | Displayed 0% automation, N/A empty-tier error rates and zero estimated hours saved |
| Real corrected drift comparison | Recomputed in the browser: maximum PSI 0.08073, below 0.2; zero-heavy features now have distinct values |
| Weekly drift command | With no retained observations, reported insufficient data rather than stable |
| Retraining CLI, isolated synthetic data | Trained all candidates, versioned, gated, promoted, backed up the incumbent and appended a changelog; real project model was untouched |
| Final local checks | Ruff passed; 135 pytest tests passed in 1.79 seconds |

## Coverage limits

Ollama 0.33.0 and phi3:mini (model ID `4f2222927938`, 2.2 GB download) were
installed after authorization. `ollama ps` confirmed 100% CPU inference with a
4,096-token context. An initial eight-second request timed out. A subsequent
response used confidence 95 and only two sentences; strict validation rejected it.
Explicit decimal-confidence and sentence instructions produced an accepted fixture
annotation in 15.65 seconds. A queue message then exhausted the output cap by
repeating emoji; a repetition penalty and more specific sentence instructions
stopped that observed loop. The same short queue email produced both rejected
and accepted responses. A long HTML email exceeded the 30-second read limit.
Usable summaries are not guaranteed, even with the model warm. The final wire
format now requires three sentence strings, joined and validated again for display.
An accepted diagnostic response mislabeled ATT&CK technique T1036 as a “spam
score.” Shape and leakage checks cannot establish factual correctness; analyst
review of the prose remains necessary. The read timeout is now 30 seconds, still bounded.
The live 30-payload suite completed with 30/30 invariant/schema passes: 27 model
annotations accepted and three rejected to deterministic fallback (ROT13, forged
JSON, and a forged assistant turn). No request used transport fallback. All five
ML evasion measurements were rerun on 37 held-out malicious emails. These checks
do not establish factual correctness of every summary or paraphrase-leakage immunity.

The project is published in the public [devansh2604/TriageAI repository](https://github.com/devansh2604/TriageAI)
through [PR #1](https://github.com/devansh2604/TriageAI/pull/1). Main contains only an
empty bootstrap commit; implementation remains on `feature/triageai` pending review.
[GitHub Actions run 35441340709](https://github.com/devansh2604/TriageAI/actions/runs/35441340709)
passed Ruff and all 131 tests on Ubuntu in 3.75 seconds of pytest execution for commit
`8d04d8e`. The corresponding pull-request run also passed. No live SOC deployment,
analyst labor study, real-world false-positive reduction or production feedback
promotion was tested.
The retained UI test feedback has no corrected label and cannot train a candidate.

The exact `make setup` target was not rerun into a second virtual environment; its
pinned dependency installation and editable CLI installation were executed in the
workspace virtual environment used for all verification.

## Findings fixed during verification

- NumPy 2.2.6 emitted floating-point errors even for a dot product of arrays of ones
  on this host. NumPy 1.26.4 passed that reproduction and the complete training run.
- The original Linear SVM configuration produced convergence warnings. The final
  primal configuration completed the comparison without those warnings.
- Unfitted-transformer warnings were resolved by marking stateless transformers fitted.
- PSI quantile edges could merge zero and positive values in zero-heavy features.
  The final implementation moves each boundary to the next representable float;
  a zero-to-one distribution-shift regression test passes.
- The upload control initially advertised Streamlit's 200 MB default despite the
  parser's 2 MB limit. Project configuration now enforces and displays 2 MB.

The remaining test warning is sandbox-specific CPU discovery from joblib. It falls
back to logical-core counting; training explicitly limits math threads to two.
The public replay achieved perfect classification on this small source-confounded
split. That result does not demonstrate robustness to contemporary user reports.

See `test-output.txt`, `BATCH_REPORT.json`, `MODEL_CARD.md` and `REDTEAM_REPORT.md`
for recorded evidence. The timings above describe this host, not an 8 GB benchmark.
