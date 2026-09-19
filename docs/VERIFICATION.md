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
| Real enrichment button | Ollama connection failure displayed a visible warning and deterministic summary; the tier stayed ANALYST-REVIEW |
| Real feedback form | Saved an unadjudicated test review; success message appeared and the matching JSONL record was read from disk |
| Real email upload | Uploaded the 0.5 KB MIME fixture; the console showed its subject, sender, risk, rules and defanged links. The final upload control displayed a 2 MB limit. |
| Metrics dashboard | Displayed 0% automation, N/A empty-tier error rates and zero estimated hours saved |
| Real corrected drift comparison | Recomputed in the browser: maximum PSI 0.08073, below 0.2; zero-heavy features now have distinct values |
| Weekly drift command | With no retained observations, reported insufficient data rather than stable |
| Retraining CLI, isolated synthetic data | Trained all candidates, versioned, gated, promoted, backed up the incumbent and appended a changelog; real project model was untouched |
| Final local checks | Ruff passed; 131 pytest tests passed in 3.98 seconds |

## Coverage limits

No Ollama installation or model was present. Live model generation, live prompt-injection
resistance and the human/rewrite AI-style classifier remain untested and untrained.
The thirty fallback passes must not be described as thirty successful live-LLM defenses.
No global installation was performed while permission was pending.

The GitHub Actions workflow is supplied but was not run on GitHub. No remote repository
was provided, so no PR was created or published. No live SOC deployment, analyst labor
study, real-world false-positive reduction or production feedback promotion was tested.
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
for recorded evidence. Cold-start and CPU-only LLM timings remain estimates.
