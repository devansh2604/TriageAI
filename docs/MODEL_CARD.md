# TriageAI model card

Version: triageai_v1. Trained: 2026-09-18T14:20:46.958176+00:00.
Training input hash: `234c5364cc8e5905391a46e5d5cd16cd5d78371850a879c32c9945af81295b1f`. Winner: logistic.

## Intended use
Local analyst assistance for user-reported email alert triage. No sender blocking,
account reset, message deletion, or external action is executed. Automation tiers
are recommendations until a SOC owner approves deployment.

## Data and evaluation
Public Nazario phishing and Enron ham; optional manually acquired Kaggle CSV.
Exact and approximate MinHash/Jaccard deduplication precedes a seeded 70/15/15 split.
TF-IDF, character LM, scaling, SVD and calibration fit inside training folds.
Five-fold outer CV selects the model by mean PR-AUC; sigmoid calibration uses
three inner folds. Thresholds use only the 85:15 validation stream. Test metrics
are retrospective, never used to choose thresholds. The 85:15 test stream is a
subset of the test split, so the two reported evaluations are not independent.

## Policy
Policy is applied to the blended score, not raw ML probability. One-sided 95%
Wilson bounds must meet the 1% auto-close error / 95% escalation precision policy.
Support must be >= 30. Bounds do not account for
search over thresholds or dataset shift and are not a deployment guarantee.
Disabled thresholds (-1 or 2) mean insufficient evidence to automate that tier.

```json
{
  "max_close_error": 0.01,
  "min_escalation_precision": 0.95,
  "min_support": 30,
  "auto_close": -1.0,
  "auto_escalate": 2.0,
  "analyst_minutes_per_alert": 5
}
```

## Held-out metrics
```json
{
  "validation_stream": {
    "n": 240,
    "accuracy": 1.0,
    "precision": 1.0,
    "recall": 1.0,
    "f1": 1.0,
    "roc_auc": 1.0,
    "pr_auc": 1.0,
    "fpr_at_95_recall": 0.0,
    "fpr_at_99_recall": 0.0,
    "auto_close_fraction": 0.0,
    "auto_close_n": 0,
    "auto_close_fn": 0,
    "auto_close_error_rate": null,
    "auto_close_fn_rate_all_malicious": 0.0,
    "auto_close_error_upper95": 1.0,
    "auto_escalate_fraction": 0.0,
    "auto_escalate_n": 0,
    "auto_escalate_precision": null,
    "escalation_false_discovery_rate": null,
    "escalation_fpr_all_benign": 0.0,
    "estimated_hours_saved_per_1000": 0.0,
    "median_time_to_triage_seconds": null
  },
  "test": {
    "n": 544,
    "accuracy": 1.0,
    "precision": 1.0,
    "recall": 1.0,
    "f1": 1.0,
    "roc_auc": 1.0,
    "pr_auc": 1.0,
    "fpr_at_95_recall": 0.0,
    "fpr_at_99_recall": 0.0,
    "auto_close_fraction": 0.0,
    "auto_close_n": 0,
    "auto_close_fn": 0,
    "auto_close_error_rate": null,
    "auto_close_fn_rate_all_malicious": 0.0,
    "auto_close_error_upper95": 1.0,
    "auto_escalate_fraction": 0.0,
    "auto_escalate_n": 0,
    "auto_escalate_precision": null,
    "escalation_false_discovery_rate": null,
    "escalation_fpr_all_benign": 0.0,
    "estimated_hours_saved_per_1000": 0.0,
    "median_time_to_triage_seconds": null
  },
  "eval_stream": {
    "n": 240,
    "accuracy": 1.0,
    "precision": 1.0,
    "recall": 1.0,
    "f1": 1.0,
    "roc_auc": 1.0,
    "pr_auc": 1.0,
    "fpr_at_95_recall": 0.0,
    "fpr_at_99_recall": 0.0,
    "auto_close_fraction": 0.0,
    "auto_close_n": 0,
    "auto_close_fn": 0,
    "auto_close_error_rate": null,
    "auto_close_fn_rate_all_malicious": 0.0,
    "auto_close_error_upper95": 1.0,
    "auto_escalate_fraction": 0.0,
    "auto_escalate_n": 0,
    "auto_escalate_precision": null,
    "escalation_false_discovery_rate": null,
    "escalation_fpr_all_benign": 0.0,
    "estimated_hours_saved_per_1000": 0.0,
    "median_time_to_triage_seconds": null
  }
}
```

## Limitations
Historic English corporate mail is not a live user-report distribution. Source,
formatting and age can predict labels; missing headers in preprocessed ham make
header comparisons especially biased. Public labels are not independently verified.
No attachments are executed, links resolved, QR codes read, or reputation feeds
queried. Near-duplicate LSH can miss pairs. AI style is not authorship proof.
Perplexity uses a character trigram model, not GPT-2. Human review remains necessary.
Subgroup results are in the batch report; language proxies are not language labels.
