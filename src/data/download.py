"""Explicit one-time public corpus acquisition; runtime never calls this module."""
import argparse
import hashlib
import json
import subprocess
import requests
from src.common import ROOT

SOURCES = {
    "nazario": ("https://monkey.org/~jose/phishing/phishing-2015", "nazario.mbox"),
    "enron": ("https://www2.aueb.gr/users/ion/data/enron-spam/preprocessed/enron1.tar.gz", "enron1.tar.gz"),
}
MANUAL = """Optional Kaggle: download 'Phishing Email' CSV using your own browser/account.
Place it at data/raw/kaggle.csv. Supported columns: Email Text + Email Type
(Safe Email / Phishing Email), or body + label (0 / 1). Never label generic spam
as confirmed phishing. Source labels are inherited, not independently adjudicated.
Nazario: https://monkey.org/~jose/phishing/
Enron: https://www2.aueb.gr/users/ion/data/enron-spam/
Respect each publisher's terms; public availability is not a redistribution license.
"""

def acquire(name, destination):
    url, filename = SOURCES[name]
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / filename
    if target.exists():
        print(f"Using existing {target}")
        return
    temp = target.with_suffix(target.suffix + ".part")
    try:
        with requests.get(url, timeout=(10, 60), stream=True) as response:
            response.raise_for_status()
            count = 0
            with temp.open("wb") as output:
                for chunk in response.iter_content(65536):
                    count += len(chunk)
                    if count > 100_000_000:
                        raise ValueError("Corpus exceeds 100 MB download cap")
                    output.write(chunk)
        temp.replace(target)
        checksum = hashlib.sha256(target.read_bytes()).hexdigest()
        target.with_suffix(target.suffix + ".provenance.json").write_text(
            json.dumps({"url": url, "sha256": checksum}, indent=2))
        print(f"Downloaded {target}: {count:,} bytes")
    except requests.exceptions.SSLError:
        # macOS curl uses the system trust store. TLS verification stays enabled.
        subprocess.run(["curl", "--fail", "--location", "--proto", "=https",
                        "--proto-redir", "=https", "--max-time", "120",
                        "--max-filesize", "100000000", "--output", str(temp), url], check=True)
        temp.replace(target)
        checksum = hashlib.sha256(target.read_bytes()).hexdigest()
        target.with_suffix(target.suffix + ".provenance.json").write_text(
            json.dumps({"url": url, "sha256": checksum, "transport": "system curl; TLS verified"}, indent=2))
        print(f"Downloaded {target} with system TLS trust store")
    finally:
        temp.unlink(missing_ok=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="Explicitly allow corpus network downloads")
    args = parser.parse_args()
    print(MANUAL)
    if args.fetch:
        for name in SOURCES:
            acquire(name, ROOT / "data/raw")

if __name__ == "__main__":
    main()
