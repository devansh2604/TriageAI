# File-by-file guide

Each source module contains working code in the repository. A complete source listing,
with path and two-line notes, is delivered beside the repository as `TriageAI-source.md`.

| Area | Responsibility |
|---|---|
| `src/data/` | Acquisition, bounded MIME parsing, exact/MinHash deduplication and fixed splits |
| `src/features/` | Offline URL/header/content indicators, sparse TF-IDF and character-LM signals |
| `src/model/` | Fold-local transforms, calibrated comparison, threshold policy and SOC metrics |
| `src/triage/` | ATT&CK hypotheses, risk blending, frozen decisions, explanations and audit |
| `src/llm/` | Loopback Ollama, strict annotations, fallback and paired style experiment |
| `src/redteam/` | Thirty injection fixtures, five ML evasions and coverage-aware reports |
| `src/ops/` | Feedback storage, holdout-safe retraining, promotion gate and PSI |
| `src/cli.py` | Single-email analysis and batch reporting |
| `src/app.py` | Local queue, details, enrichment, explanations, feedback and metrics |
| `tests/` | Parser, feature, policy, persistence, enrichment and integration checks |
