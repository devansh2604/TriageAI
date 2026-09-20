"""Normalize public corpora; MinHash deduplicate before stratified partitioning."""
import argparse
from collections import defaultdict
import hashlib
import json
import mailbox
import re
import tarfile
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from src.common import ROOT, normalize
from src.data.parse import make_alert, parse_eml

SEED = 42

def tokens(row):
    text = normalize(row["subject"] + " " + row["body_text"]).lower()
    return re.findall(r"\w+", text)

def shingles(row):
    words = tokens(row)
    return {" ".join(words[i:i+5]) for i in range(max(1, len(words)-4))}

def deduplicate(frame, threshold=0.85):
    """64-permutation MinHash / 16-band LSH with exact Jaccard confirmation.

    Candidate conflicts discard the whole cluster. Approximate candidate search
    can miss near duplicates; no claim of exhaustive pairwise equivalence.
    """
    rng = np.random.default_rng(SEED)
    prime = np.uint64(4294967311)
    a = rng.integers(1, int(prime), 64, dtype=np.uint64)
    b = rng.integers(0, int(prime), 64, dtype=np.uint64)
    buckets, exact, sets, kept, conflicts = defaultdict(list), {}, {}, {}, set()
    for index, row in frame.iterrows():
        content = " ".join(tokens(row))
        key = hashlib.sha256(content.encode()).hexdigest()
        subset = shingles(row)
        hashes = np.array([int.from_bytes(hashlib.blake2b(s.encode(), digest_size=4).digest(), "little")
                           for s in subset], dtype=np.uint64)
        signature = np.min((hashes[:, None] * a + b) % prime, axis=0)
        keys = [(band, tuple(signature[band*4:(band+1)*4])) for band in range(16)]
        candidates = set([exact[key]]) if key in exact else set()
        for bandkey in keys:
            candidates.update(buckets[bandkey])
        match = next((j for j in sorted(candidates)
                      if len(subset & sets[j]) / max(1, len(subset | sets[j])) >= threshold), None)
        if match is not None:
            if kept[match]["label"] != row["label"]:
                conflicts.add(match)
            continue
        exact[key] = index
        sets[index] = subset
        kept[index] = row
        for bandkey in keys:
            buckets[bandkey].append(index)
    return pd.DataFrame([row for i, row in kept.items() if i not in conflicts]).reset_index(drop=True)

def queue_sample(frame, seed=SEED):
    benign, malicious = frame[frame.label == 0], frame[frame.label == 1]
    units = min(len(benign)//17, len(malicious)//3)
    if units < 1:
        raise ValueError("Need at least 17 benign and 3 malicious records for 85:15 evaluation")
    return pd.concat([benign.sample(17*units, random_state=seed),
                      malicious.sample(3*units, random_state=seed)]).sample(frac=1, random_state=seed)

def read_corpora(raw):
    rows = []
    mbox_path = raw / "nazario.mbox"
    if mbox_path.exists():
        box = mailbox.mbox(mbox_path, create=False)
        for key in box.iterkeys():
            rows.append(parse_eml(box.get_bytes(key), 1, "nazario"))
        box.close()
    archive = raw / "enron1.tar.gz"
    if archive.exists():
        with tarfile.open(archive) as tar:
            for member in tar:
                if member.isfile() and "/ham/" in member.name and member.size <= 2_000_000:
                    with tar.extractfile(member) as stream:
                        rows.append(parse_eml(stream.read(), 0, "enron"))
    csv_path = raw / "kaggle.csv"
    if csv_path.exists():
        frame = pd.read_csv(csv_path).fillna("")
        for row in frame.to_dict("records"):
            label = row.get("label", row.get("Email Type"))
            mapping = {"Safe Email": 0, "Phishing Email": 1, "0": 0, "1": 1, 0: 0, 1: 1}
            if label not in mapping:
                raise ValueError(f"Unsupported Kaggle label: {label!r}")
            rows.append(make_alert(subject=row.get("subject", ""),
                                   body_text=row.get("body", row.get("Email Text", "")),
                                   label=mapping[label], source="kaggle"))
    if not rows:
        raise FileNotFoundError("No public corpora. Run make download or follow python -m src.data.download")
    return pd.DataFrame(rows)

def build(raw, destination):
    original = read_corpora(raw)
    if original.label.nunique() < 2:
        raise ValueError("Both benign and malicious corpora are required; check data/raw and download logs")
    frame = deduplicate(original)
    train, held = train_test_split(frame, test_size=.30, stratify=frame.label, random_state=SEED)
    validation, test = train_test_split(held, test_size=.5, stratify=held.label, random_state=SEED)
    destination.mkdir(parents=True, exist_ok=True)
    parts = {"alerts": frame, "train": train, "validation": validation, "test": test,
             "validation_stream": queue_sample(validation), "eval_stream": queue_sample(test)}
    for name, part in parts.items():
        part.to_parquet(destination / f"{name}.parquet", index=False)
    manifest = {"raw_rows": len(original), "unique_rows": len(frame), "seed": SEED,
                "splits": {name: {"rows": len(p), "malicious": int(p.label.sum()),
                                   "benign": int((p.label == 0).sum())} for name, p in parts.items()}}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    return manifest

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=__import__("pathlib").Path, default=ROOT / "data/raw")
    args = parser.parse_args()
    build(args.raw, ROOT / "data")

if __name__ == "__main__":
    main()
