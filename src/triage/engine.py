"""Freeze the decision before enrichment and append a content-minimized audit."""
from datetime import datetime, timezone
import json
import time
import uuid
import joblib
import pandas as pd
from jsonschema import validate
from src.common import ROOT, config, digest, append_jsonl
from src.features.content_features import text
from src.llm.enrich import enrich
from src.model.policy import tier
from src.triage.rules import detect, blend

class Engine:
    def __init__(self, model_path=None, audit_path=None, llm_enabled=None):
        self.bundle = joblib.load(model_path or ROOT / "models/triageai_v1.joblib")
        self.settings = config()
        if llm_enabled is not None:
            self.settings["ollama"]["enabled"] = llm_enabled
        self.audit_path = audit_path or ROOT / "data/audit.jsonl"
        self.schema = json.loads((ROOT / "docs/report.schema.json").read_text())
        self.authorship = None
        author_path = ROOT / "models/ai_style.joblib"
        if author_path.exists():
            self.authorship = joblib.load(author_path)

    def score(self, row):
        probability = float(self.bundle["model"].predict_proba(pd.DataFrame([row]))[0, 1])
        ai_probability = float(self.authorship.predict_proba([text(row)])[0, 1]) if self.authorship else None
        flags = detect(row, ai_probability)
        score = blend(probability, flags, self.bundle["blend_ml"])
        return probability, flags, score, tier(score, self.bundle["policy"])

    def analyze(self, row, annotation=True):
        started = time.perf_counter()
        p, flags, score, decision = self.score(row)
        llm_settings = dict(self.settings["ollama"])
        if not annotation:
            llm_settings["enabled"] = False
        result = {"decision_id": str(uuid.uuid4()), "alert_id": row["alert_id"],
                  "timestamp": datetime.now(timezone.utc).isoformat(), "inputs_hash": digest(row),
                  "model_version": self.bundle["version"], "ml_probability": p, "score": score,
                  "tier": decision, "flags": flags,
                  "attack_techniques": sorted({f["attack_technique"] for f in flags if f["attack_technique"]}),
                  "enrichment": enrich(row, flags, decision, llm_settings)}
        result["elapsed_seconds"] = time.perf_counter()-started
        validate(result, self.schema)
        # No email body, URLs, sender address or LLM prose in the append-only audit.
        audit = {k: result[k] for k in ["decision_id", "alert_id", "timestamp", "inputs_hash", "model_version",
                                        "ml_probability", "score", "tier", "elapsed_seconds"]}
        audit.update(rules_fired=[f["flag_id"] for f in flags], llm_used=result["enrichment"]["llm_used"])
        append_jsonl(self.audit_path, audit)
        return result

    def explain(self, row, limit=10):
        fitted = self.bundle["model"].calibrated_classifiers_[0].estimator
        transformed = fitted.named_steps["features"].transform(pd.DataFrame([row]))
        classifier = fitted.named_steps["classifier"]
        if hasattr(classifier, "coef_"):
            names = fitted.named_steps["features"].named_steps["columns"].get_feature_names_out()
            contributions = transformed.multiply(classifier.coef_[0]).toarray()[0]
            order = abs(contributions).argsort()[-limit:][::-1]
            return [{"feature": str(names[i]), "contribution": float(contributions[i]),
                     "meaning": "pre-calibration margin contribution"} for i in order]
        # Bounded feature-group ablations are faithful local probability changes for HGB.
        baseline = self.score(row)[0]
        variants = {"message text": dict(row, subject="", body_text="", body_html=""),
                    "URLs": dict(row, urls=[]), "headers": dict(row, headers_json="{}", from_addr="", reply_to=""),
                    "attachments": dict(row, attachments=[])}
        return [{"feature": name, "contribution": baseline-self.score(changed)[0],
                 "meaning": "local ablation probability delta; correlated features remain"}
                for name, changed in variants.items()]
