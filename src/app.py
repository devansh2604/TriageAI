"""Local analyst console for user-reported email alert triage."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pandas as pd
import streamlit as st
from src.common import ROOT
from src.data.parse import parse_eml
from src.ops.feedback import submit
from src.ops.drift import monitor
from src.triage.engine import Engine

st.set_page_config(page_title="TriageAI · SOC alert triage", page_icon="🛡", layout="wide")
st.title("TriageAI")
st.caption("AI-assisted SOC triage · user-reported suspicious email · local analyst console")

@st.cache_resource
def load_engine(model_mtime):
    return Engine()

@st.cache_data
def load_queue(path, mtime):
    return pd.read_parquet(path)

model_path = ROOT / "models/triageai_v1.joblib"
if not model_path.exists():
    st.info("No trained model yet. Run make data and make train from the project directory.")
    st.stop()
engine = load_engine(model_path.stat().st_mtime_ns)
st.sidebar.markdown("### Analyst workspace")
st.sidebar.caption(f"Model: {engine.bundle['version']}")
llm_enabled = st.sidebar.toggle("Use local Ollama enrichment", value=True)
st.sidebar.caption("Email stays on this device. LLM suggestions never change the tier.")
page = st.sidebar.radio("View", ["Alert queue", "Metrics & drift"])
path = ROOT / "data/eval_stream.parquet"
if not path.exists():
    st.warning("Build the evaluation queue with make data.")
    st.stop()
frame = load_queue(str(path), path.stat().st_mtime_ns)

@st.cache_data
def score_queue(_engine, version, data_mtime):
    records = []
    for row in frame.to_dict("records"):
        p, flags, score, tier = _engine.score(row)
        records.append({"alert_id": row["alert_id"], "subject": row["subject"], "risk": score,
                        "tier": tier, "flags": len(flags)})
    return pd.DataFrame(records).sort_values("risk", ascending=False)

if page == "Metrics & drift":
    report_path = ROOT / "docs/BATCH_REPORT.json"
    metrics = json.loads(report_path.read_text())["metrics"] if report_path.exists() else engine.bundle["metrics"]["eval_stream"]
    cols = st.columns(4)
    cols[0].metric("Auto-close", f"{metrics['auto_close_fraction']:.1%}")
    close_rate = metrics["auto_close_error_rate"]
    cols[1].metric("Malicious inside auto-close", "N/A" if close_rate is None else f"{close_rate:.1%}")
    fp = metrics["escalation_false_discovery_rate"]
    cols[2].metric("Benign inside escalation", "N/A" if fp is None else f"{fp:.1%}")
    cols[3].metric("Estimated hours saved / 1,000", f"{metrics['estimated_hours_saved_per_1000']:.1f}")
    st.caption("Historic public-corpus replay at 85:15. Hours saved assumes five minutes per auto-closed alert; not measured labor savings.")
    st.json(metrics)
    drift_path = ROOT / "docs/DRIFT_REPORT.json"
    if drift_path.exists():
        st.subheader("Latest drift run")
        st.json(json.loads(drift_path.read_text()))
    else:
        st.info("No weekly production observations yet. Run python -m src.ops.drift after collecting observations.")
    if st.button("Compare historic replay to training baseline"):
        st.json(monitor(engine.bundle, frame))
        st.caption("Historic replay comparison; not a weekly production drift measurement.")
    st.stop()

upload = st.file_uploader("Analyze a reported email (.eml, maximum 2 MB)", type=["eml"])
queue = score_queue(engine, engine.bundle["version"] + engine.bundle["training_hash"], path.stat().st_mtime_ns)
st.subheader("Reported email queue")
st.caption(f"{len(queue)} alerts · highest risk first · queue scores are previews; opening a decision writes an audit record")
st.dataframe(queue, hide_index=True, use_container_width=True,
             column_config={"risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=1, format="%.2f")})
if upload:
    try:
        row = parse_eml(upload.getvalue())
    except ValueError as error:
        st.error(str(error))
        st.stop()
else:
    selected = st.selectbox("Open alert", queue.alert_id.tolist(),
                           format_func=lambda value: f"{queue.loc[queue.alert_id == value, 'subject'].iloc[0][:100]} · {value[:8]}")
    row = frame[frame.alert_id == selected].iloc[0].to_dict()
key = engine.bundle["version"] + ":" + row["alert_id"]
if key not in st.session_state:
    st.session_state[key] = engine.analyze(row, annotation=False)
result = st.session_state[key]
colors = {"AUTO-CLOSE": "green", "ANALYST-REVIEW": "orange", "AUTO-ESCALATE": "red"}
st.subheader("Alert detail")
st.markdown(f":{colors[result['tier']]}-background[{result['tier']}]")
st.text(row["subject"])
left, right = st.columns([1, 2])
with left:
    st.metric("Blended risk score", f"{result['score']:.1%}")
    st.progress(result["score"])
    st.caption(f"Calibrated ML probability: {result['ml_probability']:.1%}")
    st.text("Sender: " + row["from_addr"])
    st.text("Reply to: " + row["reply_to"])
    st.caption("ATT&CK hypotheses")
    st.write(" · ".join(result["attack_techniques"]) or "None")
with right:
    st.markdown("**Red flags and evidence**")
    st.dataframe(pd.DataFrame(result["flags"]), hide_index=True, use_container_width=True)
    st.markdown("**Reported URLs (defanged; never opened)**")
    for url in row["urls"]:
        st.code(str(url).replace("http", "hxxp").replace(".", "[.]"), language=None)
with st.expander("Email body · untrusted text"):
    st.text(row["body_text"][:12000])
with st.expander("Why this score"):
    st.dataframe(engine.explain(row), hide_index=True)
    st.caption("Contributions explain the model, not causality. Rule severities are blended separately.")
st.markdown("### Analyst enrichment")
if st.button("Enrich with local Ollama", disabled=not llm_enabled):
    with st.spinner("Requesting bounded local annotation…"):
        st.session_state[key] = engine.analyze(row)
    result = st.session_state[key]
st.text(result["enrichment"]["summary"])
st.write("Recommended action: " + result["enrichment"]["recommended_action"])
if result["enrichment"]["warning"]:
    st.warning(result["enrichment"]["warning"])
else:
    st.caption(f"LLM self-reported confidence: {result['enrichment']['confidence']:.0%}; not calibrated")
st.caption("Recommendations need analyst judgment. This console does not block senders or reset credentials.")
with st.form("feedback"):
    st.markdown("**Analyst review**")
    agreement = st.radio("Decision", ["Agree", "Disagree"], horizontal=True)
    label = st.selectbox("Adjudicated label", ["Not adjudicated", "Benign", "Malicious"])
    reason = st.text_area("Reason")
    retain = st.checkbox("Save this email locally as an adjudicated training example", value=False)
    if st.form_submit_button("Save feedback"):
        try:
            record = submit(result, agreement == "Agree", reason,
                            {"Not adjudicated": None, "Benign": 0, "Malicious": 1}[label],
                            alert=row if retain and label != "Not adjudicated" else None)
            st.success("Feedback saved to data/feedback.jsonl.")
        except ValueError as error:
            st.error(str(error))
