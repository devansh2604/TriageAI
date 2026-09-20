"""Durable analyst feedback tied to an audited decision; never implicit ground truth."""
from datetime import datetime, timezone
import json
from src.common import ROOT, append_jsonl

def submit(decision, agree, reason, corrected_label=None, path=None, alert=None):
    reason = reason.strip()
    if not reason or len(reason) > 2000:
        raise ValueError("A reason between 1 and 2000 characters is required")
    if corrected_label is not None and corrected_label not in (0, 1):
        raise ValueError("Corrected label must be 0 or 1")
    if not agree and corrected_label is None:
        raise ValueError("A disagreement needs an adjudicated label")
    record = {"decision_id": decision["decision_id"], "alert_id": decision["alert_id"],
              "model_version": decision["model_version"], "agree": bool(agree), "reason": reason,
              "corrected_label": corrected_label, "timestamp": datetime.now(timezone.utc).isoformat()}
    if alert is not None:
        # Explicitly saved adjudicated examples; holdout protection is enforced again at retraining.
        record["alert"] = {**alert, "urls": list(alert["urls"]), "attachments": list(alert["attachments"])}
    append_jsonl(path or ROOT / "data/feedback.jsonl", record)
    return record

def read(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
