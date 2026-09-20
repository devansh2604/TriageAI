"""Compare three calibrated candidates with leakage-safe five-fold CV."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from src.features.reduction import BoundedSVD
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from threadpoolctl import threadpool_limits
import yaml
from src.common import ROOT, config, digest, atomic_json
from src.features.pipeline import features, AlertRows
from src.triage.rules import detect, blend
from src.model.metrics import measure
from src.model.policy import select_thresholds


def candidate(name):
    steps = [("features", features())]
    if name == "logistic":
        estimator = LogisticRegression(solver="liblinear", max_iter=3000, C=2, random_state=42)
    elif name == "svm":
        estimator = LinearSVC(C=.5, dual=False, random_state=42, max_iter=5000)
    elif name == "hist_gradient_boosting":
        steps.append(("reduce", BoundedSVD(n_components=64, random_state=42)))
        estimator = HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=15, random_state=42)
    else:
        raise ValueError(name)
    steps.append(("classifier", estimator))
    return CalibratedClassifierCV(Pipeline(steps), method="sigmoid", cv=3, ensemble=False)

def scores_for(model, frame, settings):
    probabilities = model.predict_proba(frame)[:, 1]
    scores = np.array([blend(p, detect(row), settings["blend_ml"])
                       for p, row in zip(probabilities, frame.to_dict("records"))])
    return probabilities, scores

def fit(train, validation, test, stream, settings, output, compare=True):
    started = time.perf_counter()
    y = train.label.astype(int)
    if y.value_counts().min() < 10:
        raise ValueError("Need at least ten unique training records per class")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=settings["seed"])
    comparison = {}
    names = ["logistic", "svm", "hist_gradient_boosting"] if compare else ["logistic"]
    with threadpool_limits(limits=2):
        for name in names:
            print(f"Five-fold calibrated CV: {name}", flush=True)
            values = cross_validate(candidate(name), train, y, cv=cv,
                                    scoring={"pr_auc": "average_precision", "roc_auc": "roc_auc", "f1": "f1"},
                                    n_jobs=1, error_score="raise")
            comparison[name] = {key[5:]: {"mean": float(np.mean(value)), "std": float(np.std(value))}
                                for key, value in values.items() if key.startswith("test_")}
        winner = max(comparison, key=lambda key: comparison[key]["pr_auc"]["mean"])
        model = candidate(winner).fit(train, y)
    _, validation_scores = scores_for(model, validation, settings)
    policy = select_thresholds(validation.label, validation_scores, settings["policy"])
    reports = {}
    for label, frame in [("validation_stream", validation), ("test", test), ("eval_stream", stream)]:
        p, s = scores_for(model, frame, settings)
        reports[label] = measure(frame.label, p, s, policy)
    rows = AlertRows().transform(train).drop(columns="text")
    p_train, s_train = scores_for(model, train, settings)
    del p_train
    baseline = rows.assign(score=s_train).to_dict("list")
    bundle = {"model": model, "version": settings["model_version"], "winner": winner,
              "policy": policy, "blend_ml": settings["blend_ml"], "cv": comparison,
              "metrics": reports, "trained_at": datetime.now(timezone.utc).isoformat(),
              "train_ids": sorted(train.alert_id.tolist()), "baseline": baseline,
              "training_hash": digest(sorted(train.alert_id.tolist()))}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".tmp")
    joblib.dump(bundle, temporary)
    temporary.replace(output)
    bundle["duration_seconds"] = time.perf_counter()-started
    return bundle

def write_reports(bundle):
    atomic_json(ROOT / "docs/metrics.json", {"cv": bundle["cv"], "metrics": bundle["metrics"],
                                            "policy": bundle["policy"], "winner": bundle["winner"]})
    card = f"""# TriageAI model card

Version: {bundle['version']}. Trained: {bundle['trained_at']}.
Training input hash: `{bundle['training_hash']}`. Winner: {bundle['winner']}.

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
Support must be >= {bundle['policy']['min_support']}. Bounds do not account for
search over thresholds or dataset shift and are not a deployment guarantee.
Disabled thresholds (-1 or 2) mean insufficient evidence to automate that tier.

```json
{json.dumps(bundle['policy'], indent=2)}
```

## Held-out metrics
```json
{json.dumps(bundle['metrics'], indent=2)}
```

## Limitations
Historic English corporate mail is not a live user-report distribution. Source,
formatting and age can predict labels; missing headers in preprocessed ham make
header comparisons especially biased. Public labels are not independently verified.
No attachments are executed, links resolved, QR codes read, or reputation feeds
queried. Near-duplicate LSH can miss pairs. AI style is not authorship proof.
Perplexity uses a character trigram model, not GPT-2. Human review remains necessary.
Subgroup results are in the batch report; language proxies are not language labels.
"""
    (ROOT / "docs/MODEL_CARD.md").write_text(card)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="Compare logistic only; development use")
    args = parser.parse_args()
    settings = config()
    def frame(name):
        return pd.read_parquet(ROOT / f"data/{name}.parquet")
    bundle = fit(frame("train"), frame("validation_stream"), frame("test"), frame("eval_stream"),
                 settings, ROOT / "models/triageai_v1.joblib", not args.quick)
    settings["policy"] = bundle["policy"]
    (ROOT / "config.yaml").write_text(yaml.safe_dump(settings, sort_keys=False))
    write_reports(bundle)
    print(json.dumps({"winner": bundle["winner"], "seconds": bundle["duration_seconds"],
                      "policy": bundle["policy"], "metrics": bundle["metrics"]}, indent=2))

if __name__ == "__main__":
    main()
