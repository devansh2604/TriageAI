"""Shared local storage, hashing, and Unicode handling."""
import hashlib
import json
import os
from pathlib import Path
import unicodedata
import fcntl
import yaml

ROOT = Path(os.environ.get("TRIAGEAI_HOME", Path(__file__).resolve().parents[1]))

def normalize(text):
    return "".join(c for c in unicodedata.normalize("NFKC", str(text))
                   if not unicodedata.category(c).startswith("C") or c in "\n\t")

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     default=str).encode()).hexdigest()

def config():
    return yaml.safe_load((ROOT / "config.yaml").read_text())

def append_jsonl(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(json.dumps(record, ensure_ascii=True, allow_nan=False, default=str) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        fcntl.flock(stream, fcntl.LOCK_UN)

def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False, default=str))
    temporary.replace(path)
