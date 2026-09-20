"""SOC metrics include explicit denominators; undefined rates remain null."""
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score, roc_curve
from src.model.policy import tier, CLOSE, ESCALATE, wilson_upper

def rate(numerator, denominator):
    return float(numerator / denominator) if denominator else None

def measure(y, probabilities, scores, policy, timings=None):
    y, p, s = np.asarray(y), np.asarray(probabilities), np.asarray(scores)
    prediction = p >= .5
    tiers = np.array([tier(score, policy) for score in s])
    closed, escalated = tiers == CLOSE, tiers == ESCALATE
    fn = int(y[closed].sum())
    fp = int((1-y[escalated]).sum())
    fpr, tpr, _ = roc_curve(y, p)
    result = {"n": len(y), "accuracy": accuracy_score(y, prediction),
              "precision": precision_score(y, prediction, zero_division=0),
              "recall": recall_score(y, prediction, zero_division=0),
              "f1": f1_score(y, prediction, zero_division=0),
              "roc_auc": roc_auc_score(y, p), "pr_auc": average_precision_score(y, p),
              "fpr_at_95_recall": float(fpr[tpr >= .95].min()),
              "fpr_at_99_recall": float(fpr[tpr >= .99].min()),
              "auto_close_fraction": float(closed.mean()), "auto_close_n": int(closed.sum()),
              "auto_close_fn": fn, "auto_close_error_rate": rate(fn, closed.sum()),
              "auto_close_fn_rate_all_malicious": rate(fn, y.sum()),
              "auto_close_error_upper95": wilson_upper(fn, int(closed.sum())),
              "auto_escalate_fraction": float(escalated.mean()), "auto_escalate_n": int(escalated.sum()),
              "auto_escalate_precision": rate(int(y[escalated].sum()), escalated.sum()),
              "escalation_false_discovery_rate": rate(fp, escalated.sum()),
              "escalation_fpr_all_benign": rate(fp, (1-y).sum()),
              "estimated_hours_saved_per_1000": float(closed.mean()*1000*policy["analyst_minutes_per_alert"]/60),
              "median_time_to_triage_seconds": float(np.median(timings)) if timings else None}
    return result
