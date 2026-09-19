"""Local single-alert triage, batch replay, and reproducible SOC reports."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import pandas as pd
from src.common import ROOT, append_jsonl, atomic_json
from src.data.parse import parse_eml
from src.features.url_features import domain
from src.model.metrics import measure
from src.triage.engine import Engine


def observe(row):
    append_jsonl(ROOT / "data/observations.jsonl", {**row, "observed_at": datetime.now(timezone.utc).isoformat()})

def batch(frame, engine, annotate=False, output=None):
    results = []
    for row in frame.to_dict("records"):
        results.append(engine.analyze(row, annotation=annotate))
    if output:
        with Path(output).open("w") as stream:
            for record in results:
                stream.write(json.dumps(record) + "\n")
    metrics = measure(frame.label.astype(int), [r["ml_probability"] for r in results],
                      [r["score"] for r in results], engine.bundle["policy"],
                      [r["elapsed_seconds"] for r in results])
    metrics["llm_used_n"] = sum(r["enrichment"]["llm_used"] for r in results)
    metrics["timing_mode"] = "end-to-end including enrichment and audit" if annotate else "scoring, fallback, schema and audit; LLM disabled"
    groups = []
    for row, result in zip(frame.to_dict("records"), results):
        text = row["body_text"]
        proxy = "non-ASCII" if sum(ord(c)>127 for c in text)/max(1, len(text)) > .05 else "mostly ASCII"
        sender = row["from_addr"].split("@")[-1].strip("> ") if "@" in row["from_addr"] else "missing"
        groups.append({"source": row["source"], "language_proxy": proxy, "sender_domain": domain(sender),
                       "label": row["label"], "predicted": int(result["ml_probability"] >= .5)})
    group_frame = pd.DataFrame(groups)
    subgroups = []
    for dimension in ["source", "language_proxy", "sender_domain"]:
        for group, values in group_frame.groupby(dimension):
            if len(values) < 10:
                continue
            malignant = values[values.label == 1]
            benign = values[values.label == 0]
            subgroups.append({"dimension": dimension, "group": group, "n": len(values),
                              "recall": float(malignant.predicted.mean()) if len(malignant) else None,
                              "fpr": float(benign.predicted.mean()) if len(benign) else None})
    return {"metrics": metrics, "subgroups": subgroups,
            "subgroup_caution": "ASCII is not a language label. Groups below 10 records are omitted."}

def main():
    parser = argparse.ArgumentParser(prog="triageai", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze")
    analyze.add_argument("email", type=Path)
    analyze.add_argument("--json", action="store_true")
    analyze.add_argument("--no-llm", action="store_true")
    analyze.add_argument("--record-observation", action="store_true", help="Store email locally for weekly drift")
    batch_parser = sub.add_parser("batch")
    batch_parser.add_argument("input", type=Path)
    batch_parser.add_argument("--report", action="store_true")
    batch_parser.add_argument("--llm", action="store_true", help="Enrich every alert; potentially slow")
    args = parser.parse_args()
    engine = Engine()
    if args.command == "analyze":
        row = parse_eml(args.email.read_bytes())
        result = engine.analyze(row, annotation=not args.no_llm)
        if args.record_observation:
            observe(row)
        print(json.dumps(result, indent=2) if args.json else
              f"{result['tier']} · {result['score']:.1%}\n{result['enrichment']['summary']}\n"
              f"{result['enrichment']['warning'] or ''}")
    else:
        frame = pd.read_parquet(args.input)
        report = batch(frame, engine, args.llm, ROOT / "data/batch_results.jsonl" if args.report else None)
        if args.report:
            atomic_json(ROOT / "docs/BATCH_REPORT.json", report)
            (ROOT / "docs/BATCH_REPORT.md").write_text("# SOC replay report\n\n```json\n"+
                                                        json.dumps(report, indent=2)+"\n```\n")
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
