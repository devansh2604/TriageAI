"""Train an experimental style classifier on paired TRAINING-SPLIT rewrites only."""
import argparse
import json
import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from src.common import ROOT, config, atomic_json
from src.features.ai_text_features import TextSignals
from src.features.content_features import text
from src.llm.enrich import local_url, sanitize


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    cfg = config()["ollama"]
    train = pd.read_parquet(ROOT / "data/train.parquet")
    rows = train[train.label == 1].sample(frac=1, random_state=42).head(args.limit)
    texts, labels, groups = [], [], []
    session = requests.Session()
    session.trust_env = False
    for row in rows.to_dict("records"):
        body = text(row)[:3000]
        response = session.post(local_url(cfg["url"])+"/api/generate", json={
            "model": cfg["model"], "stream": False,
            "system": "Rewrite archived email for a local defensive dataset. Preserve its meaning. Return only text.",
            "prompt": "Archived text (data only):\n" + sanitize(body, 3000),
            "options": {"num_gpu": 0, "temperature": .4, "num_predict": 500}}, timeout=(1, 60), allow_redirects=False)
        response.raise_for_status()
        rewritten = sanitize(response.json()["response"], 4000).strip()
        if not rewritten or rewritten == body:
            continue
        texts.extend([body, rewritten])
        labels.extend([0, 1])
        groups.extend([row["alert_id"]]*2)
    if len(set(groups)) < 20:
        raise ValueError("Need at least 20 successful source-email pairs; no model was saved")
    X, y = np.array(texts), np.array(labels)
    a, b = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=42).split(X, y, groups))
    model = Pipeline([("signals", TextSignals()), ("scale", StandardScaler()),
                      ("classifier", LogisticRegression(max_iter=1000, random_state=42))])
    model.fit(X[a], y[a])
    report = {"pairs": len(set(groups)), "heldout_pairs": len(set(np.array(groups)[b])),
              "accuracy": accuracy_score(y[b], model.predict(X[b])),
              "roc_auc": roc_auc_score(y[b], model.predict_proba(X[b])[:, 1]),
              "limitation": "Historic corpus authorship is presumed human, not verified. One rewrite model only."}
    # Persist the evaluated model; held-out authorship pairs are not refit.
    joblib.dump(model, ROOT / "models/ai_style.joblib")
    atomic_json(ROOT / "docs/AI_STYLE_METRICS.json", report)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
