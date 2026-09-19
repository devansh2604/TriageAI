import json
import numpy as np
import pandas as pd
import pytest
from src.common import append_jsonl, digest
from src.model.policy import tier, select_thresholds, wilson_upper
from src.model.metrics import measure
from src.ops.drift import psi
from src.ops.feedback import submit
from src.ops.retrain import merge_feedback, promotion_allowed
from src.triage.rules import detect, blend

POLICY = {"auto_close": .1, "auto_escalate": .9, "min_support": 30,
          "max_close_error": .01, "min_escalation_precision": .95, "analyst_minutes_per_alert": 5}

@pytest.mark.parametrize("score,expected",[(.1,"AUTO-CLOSE"),(.5,"ANALYST-REVIEW"),(.9,"AUTO-ESCALATE")])
def test_tier_boundaries(score, expected):
    assert tier(score, POLICY) == expected

def test_no_support_disables_automation():
    selected = select_thresholds([0, 1], [.01, .99], POLICY)
    assert selected["auto_close"] == -1 and selected["auto_escalate"] == 2

def test_supported_safe_tiers():
    selected = select_thresholds([0]*400+[1]*100, [.01]*400+[.99]*100, POLICY)
    assert selected["auto_close"] == .01 and selected["auto_escalate"] == .99

def test_small_zero_error_not_guarantee():
    assert wilson_upper(0, 10) > .01

def test_metrics_denominators():
    metrics = measure([0,1,0,1],[.01,.02,.99,.99],[.01,.02,.99,.99],POLICY)
    assert metrics["auto_close_error_rate"] == .5
    assert metrics["escalation_false_discovery_rate"] == .5
    assert metrics["auto_close_fn_rate_all_malicious"] == .5

def test_empty_tier_metrics_are_null():
    metrics = measure([0,1],[.4,.6],[.4,.6],POLICY)
    assert metrics["auto_close_error_rate"] is None

def test_rules_and_blend(alert):
    flags = detect(alert)
    assert all(1 <= f["severity"] <= 5 for f in flags)
    assert 0 <= blend(.5, flags) <= 1
    assert any(f["attack_technique"] == "T1036" for f in flags)

def test_ai_style_not_risk(alert):
    assert blend(.2, detect(alert,.99)) == blend(.2, detect(alert))

def test_invalid_blend():
    with pytest.raises(ValueError):
        blend(.5, [], 2)

def test_audit_append(tmp_path):
    path = tmp_path/"audit.jsonl"
    append_jsonl(path, {"score": .5})
    append_jsonl(path, {"score": .9})
    assert len(path.read_text().splitlines()) == 2

def test_hash_order_independent():
    assert digest({"x":1,"y":2}) == digest({"y":2,"x":1})

def test_feedback_persistence(tmp_path):
    record = submit({"decision_id":"d","alert_id":"a","model_version":"v"},False,"Confirmed malicious",1,tmp_path/"f")
    assert json.loads((tmp_path/"f").read_text()) == record

def test_feedback_needs_reason():
    with pytest.raises(ValueError):
        submit({}, True, "")

def test_feedback_disagree_needs_label():
    with pytest.raises(ValueError):
        submit({}, False, "Disagree")

def test_feedback_cannot_train_on_holdout():
    train = pd.DataFrame({"alert_id":["train","held"],"label":[0,0]})
    rows = [{"alert_id":"train","corrected_label":1},{"alert_id":"held","corrected_label":1}]
    merged, accepted, ignored = merge_feedback(train, rows, {"held"})
    assert merged.label.tolist() == [1,0] and accepted == ignored == 1

def test_drift_identical():
    assert psi(np.arange(100), np.arange(100)) == 0

def test_drift_shift():
    assert psi(np.arange(100), np.arange(100)+1000) > .2

def test_drift_empty():
    assert psi([], [1]) is None

def test_retrain_gate_regression():
    old = {"auto_close_n":400,"auto_close_error_rate":0}
    new = {"auto_close_n":400,"auto_close_error_rate":.002,"auto_close_error_upper95":.008,
           "auto_escalate_n":100,"auto_escalate_precision":1}
    assert not promotion_allowed(old,new)

def test_retrain_gate_disabling_close():
    assert promotion_allowed({"auto_close_n":0},{"auto_close_n":0,"auto_escalate_n":0})


def test_new_feedback_admission_and_near_holdout_rejection():
    from src.data.parse import make_alert
    train = pd.DataFrame([make_alert(body_text="Team project calendar notes", label=0)])
    held = make_alert(body_text="Secret heldout identical message", label=1)
    new = make_alert(body_text="Distinct new payroll message", label=None)
    records = [{"alert_id": "new", "corrected_label": 1, "alert": new},
               {"alert_id": "different-id", "corrected_label": 0, "alert": held}]
    merged, accepted, ignored = merge_feedback(train, records, {held["alert_id"]}, [held])
    assert accepted == ignored == 1 and len(merged) == 2
    assert merged.loc[merged.alert_id == "new", "label"].iloc[0] == 1


def test_drift_detects_departure_from_constant_zero():
    assert psi(np.zeros(100), np.ones(100)) > .2
