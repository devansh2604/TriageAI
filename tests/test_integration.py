"""Exercise training, serialization, inference, and durable audit together."""
import json
import joblib
import pandas as pd
import pytest
from threadpoolctl import threadpool_limits
from src.common import config
from src.data.parse import make_alert
from src.model.train import candidate
from src.triage.engine import Engine


@pytest.mark.parametrize("name", ["logistic", "svm", "hist_gradient_boosting"])
def test_actual_pipeline_to_audit(tmp_path, name):
    rows = [make_alert(body_text=f"Team calendar meeting notes agenda {i}",label=0) for i in range(12)]
    rows += [make_alert(body_text=f"Urgent verify your account password http://evil.example/{i}",label=1) for i in range(12)]
    frame = pd.DataFrame(rows)
    with threadpool_limits(limits=2):
        model = candidate(name).fit(frame, frame.label)
    bundle = {"model":model,"version":"test-v1","blend_ml":.85,"policy":config()["policy"]}
    path = tmp_path/"model.joblib"
    joblib.dump(bundle,path)
    engine = Engine(path,tmp_path/"audit.jsonl",llm_enabled=False)
    result = engine.analyze(rows[-1])
    audit = json.loads((tmp_path/"audit.jsonl").read_text())
    assert audit["decision_id"] == result["decision_id"]
    assert audit["score"] == result["score"]
    assert "body_text" not in audit and audit["llm_used"] is False
    assert engine.explain(rows[-1])
