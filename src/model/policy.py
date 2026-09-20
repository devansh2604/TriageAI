"""Validation-only tier policy, with one-sided 95% Wilson uncertainty bounds."""
import numpy as np

CLOSE, REVIEW, ESCALATE = "AUTO-CLOSE", "ANALYST-REVIEW", "AUTO-ESCALATE"

def tier(score, policy):
    if score <= policy["auto_close"]:
        return CLOSE
    if score >= policy["auto_escalate"]:
        return ESCALATE
    return REVIEW

def wilson_upper(errors, n, z=1.645):
    if n == 0:
        return 1.
    p = errors/n
    return float((p + z*z/(2*n) + z*np.sqrt(p*(1-p)/n + z*z/(4*n*n))) / (1+z*z/n))

def select_thresholds(y, scores, policy):
    y, scores = np.asarray(y), np.asarray(scores)
    selected = dict(policy, auto_close=-1., auto_escalate=2.)
    for threshold in np.unique(scores):
        mask = scores <= threshold
        if mask.sum() >= policy["min_support"] and wilson_upper(int(y[mask].sum()), int(mask.sum())) <= policy["max_close_error"]:
            selected["auto_close"] = float(threshold)
    for threshold in np.unique(scores):
        mask = scores >= threshold
        if (threshold > selected["auto_close"] and mask.sum() >= policy["min_support"]
                and wilson_upper(int((1-y[mask]).sum()), int(mask.sum())) <= 1-policy["min_escalation_precision"]):
            selected["auto_escalate"] = float(threshold)
            break
    return selected
