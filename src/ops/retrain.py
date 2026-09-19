"""Versioned retraining with quarantined holdouts and a validation promotion gate."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import json
import shutil
import joblib
import pandas as pd
import yaml
from src.common import ROOT, config, append_jsonl
from src.model.train import fit, scores_for, write_reports
from src.model.metrics import measure
from src.ops.feedback import read
from src.data.build import shingles, deduplicate
from src.data.parse import make_alert

def promotion_allowed(old, new):
    # Disabling close is safe but carries zero automation benefit. Enabling a new
    # close tier requires its own uncertainty bound, not a comparison to null.
    if new["auto_close_n"] == 0:
        close_ok = True
    elif new["auto_close_error_upper95"] > .01:
        close_ok = False
    elif old["auto_close_n"] == 0:
        close_ok = True
    else:
        close_ok = new["auto_close_error_rate"] <= old["auto_close_error_rate"]
    escalation_ok = (new["auto_escalate_n"] == 0 or new["auto_escalate_precision"] >= .95)
    return close_ok and escalation_ok

def merge_feedback(train, feedback, protected_ids, protected_rows=None):
    result = train.copy().set_index("alert_id", drop=False)
    protected_sets = [shingles(row) for row in (protected_rows or [])]
    accepted, ignored = 0, 0
    for record in feedback:
        key, label = record["alert_id"], record.get("corrected_label")
        if key in protected_ids or label not in (0, 1):
            ignored += 1
            continue
        if key not in result.index:
            alert = record.get("alert")
            if not alert:
                ignored += 1
                continue
            example = make_alert(subject=alert.get("subject", ""), body_text=alert.get("body_text", ""),
                                 body_html=alert.get("body_html", ""), from_addr=alert.get("from_addr", ""),
                                 reply_to=alert.get("reply_to", ""), headers=json.loads(alert.get("headers_json", "{}")),
                                 attachments=alert.get("attachments", []), label=label, source="analyst_feedback")
            candidate_set = shingles(example)
            if any(len(candidate_set & held)/max(1, len(candidate_set | held)) >= .85 for held in protected_sets):
                ignored += 1
                continue
            example["alert_id"] = key
            result = pd.concat([result, pd.DataFrame([example]).set_index("alert_id", drop=False)])
        else:
            result.loc[key, "label"] = label
        accepted += 1
    # Deduplication also checks conflicts among newly submitted examples.
    merged = result.reset_index(drop=True)
    if {"subject", "body_text"} <= set(merged.columns):
        merged = deduplicate(merged)
    return merged, accepted, ignored

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--promote", action="store_true", help="Atomically replace active model only after gate passes")
    args = parser.parse_args()
    lock = (ROOT / "models/retrain.lock").open("w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    def frame(name):
        return pd.read_parquet(ROOT / f"data/{name}.parquet")
    validation, test, stream = frame("validation_stream"), frame("test"), frame("eval_stream")
    protected = set(frame("validation").alert_id) | set(test.alert_id)
    train, accepted, ignored = merge_feedback(frame("train"), read(ROOT / "data/feedback.jsonl"), protected,
                                                pd.concat([frame("validation"), test]).to_dict("records"))
    if not accepted:
        raise ValueError("No eligible adjudicated training feedback; holdout/upload records are quarantined")
    current = joblib.load(ROOT / "models/triageai_v1.joblib")
    settings = deepcopy(config())
    settings["model_version"] = "triageai_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    candidate_path = ROOT / "models" / (settings["model_version"] + ".joblib")
    proposed = fit(train, validation, test, stream, settings, candidate_path)
    p, s = scores_for(current["model"], validation, current)
    incumbent_metrics = measure(validation.label, p, s, current["policy"])
    allowed = promotion_allowed(incumbent_metrics, proposed["metrics"]["validation_stream"])
    promoted = allowed and args.promote
    if promoted:
        active = ROOT / "models/triageai_v1.joblib"
        backup = ROOT / "models" / (current["version"] + "_backup.joblib")
        if not backup.exists():
            shutil.copyfile(active, backup)
        temp = active.with_suffix(".promote")
        shutil.copyfile(candidate_path, temp)
        temp.replace(active)
        settings["policy"] = proposed["policy"]
        (ROOT / "config.yaml").write_text(yaml.safe_dump(settings, sort_keys=False))
        write_reports(proposed)
    event = {"version": settings["model_version"], "accepted": accepted, "ignored": ignored,
             "gate_passed": allowed, "promoted": promoted, "timestamp": datetime.now(timezone.utc).isoformat()}
    append_jsonl(ROOT / "models/changelog.jsonl", event)
    with (ROOT / "docs/RETRAIN_CHANGELOG.md").open("a") as out:
        out.write("\n- " + json.dumps(event) + "\n")
    print(json.dumps(event, indent=2))
    if not allowed:
        raise SystemExit("Promotion refused: validation safety gate failed")

if __name__ == "__main__":
    main()
