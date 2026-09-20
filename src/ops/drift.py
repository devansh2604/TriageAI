"""Weekly PSI on fixed baseline bins; empty populations are not zero drift."""
import argparse
from datetime import datetime, timezone, timedelta
import json
import joblib
import numpy as np
import pandas as pd
from src.common import ROOT, atomic_json
from src.features.pipeline import AlertRows
from src.model.train import scores_for

TOP_FEATURES = ["url_count", "lookalike", "credential_request", "urgency", "text_length", "reply_mismatch", "score"]

def psi(reference, current):
    reference, current = np.asarray(reference, float), np.asarray(current, float)
    reference, current = reference[np.isfinite(reference)], current[np.isfinite(current)]
    if not len(reference) or not len(current):
        return None
    inner = np.unique(np.quantile(reference, np.linspace(.1, .9, 9)))
    # Put a repeated mass (especially zero counts) below its boundary, so
    # newly nonzero observations cannot disappear into the same histogram bin.
    inner = np.nextafter(inner, np.inf)
    bins = np.r_[-np.inf, inner, np.inf]
    expected = np.histogram(reference, bins=bins)[0].astype(float) + .5
    observed = np.histogram(current, bins=bins)[0].astype(float) + .5
    expected /= expected.sum()
    observed /= observed.sum()
    return float(np.sum((observed-expected)*np.log(observed/expected)))

def monitor(bundle, frame):
    if frame.empty:
        return {"status": "insufficient data", "n": 0, "psi": {}}
    facts = AlertRows().transform(frame).drop(columns="text")
    _, scores = scores_for(bundle["model"], frame, bundle)
    facts["score"] = scores
    values = {name: psi(bundle["baseline"][name], facts[name]) for name in TOP_FEATURES}
    return {"status": "alert" if any(v is not None and v > .2 for v in values.values()) else "stable",
            "n": len(frame), "psi": values, "threshold": .2,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "warning": "PSI estimates are unstable below 100 observations" if len(frame) < 100 else None}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(ROOT / "data/observations.jsonl"))
    parser.add_argument("--all", action="store_true", help="Evaluate all rows; for historic replay only")
    args = parser.parse_args()
    path = __import__("pathlib").Path(args.input)
    frame = pd.read_parquet(path) if path.suffix == ".parquet" else (
        pd.read_json(path, lines=True) if path.exists() else pd.DataFrame())
    if not args.all and not frame.empty:
        dates = pd.to_datetime(frame.get("observed_at"), errors="coerce", utc=True)
        if dates is None:
            frame = frame.iloc[:0]
        else:
            frame = frame[dates >= datetime.now(timezone.utc)-timedelta(days=7)]
    report = monitor(joblib.load(ROOT / "models/triageai_v1.joblib"), frame)
    atomic_json(ROOT / "docs/DRIFT_REPORT.json", report)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
