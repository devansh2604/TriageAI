"""Header facts are evidence, not trusted authentication verdicts on uploaded MIME."""
import json
import re
from email.utils import parseaddr
from src.features.url_features import BRANDS, domain

def headers(row):
    try:
        values = json.loads(row.get("headers_json", "{}"))
        return {k.lower(): v if isinstance(v, list) else [str(v)] for k, v in values.items()}
    except (ValueError, AttributeError):
        return {}

def extract(row):
    h = headers(row)
    name, sender = parseaddr(row.get("from_addr", ""))
    reply = parseaddr(row.get("reply_to", ""))[1]
    sender_domain = domain(sender.rsplit("@", 1)[-1]) if "@" in sender else ""
    auth = " ".join(h.get("authentication-results", [])).lower()
    result = {"display_mismatch": int(any(b in name.lower() and sender_domain != d
                                          for b, d in BRANDS.items())),
              "reply_mismatch": int(bool(reply) and reply.lower() != sender.lower()),
              "received_hops": len(h.get("received", [])),
              "missing_message_id": int(not h.get("message-id")),
              "x_mailer_anomaly": int(bool(re.search(r"php|mass.?mail|bulk|sendblaster",
                                                     " ".join(h.get("x-mailer", [])), re.I)))}
    for mechanism in ("spf", "dkim", "dmarc"):
        statuses = re.findall(r"\b" + mechanism + r"\s*=\s*([a-z]+)", auth)
        result[mechanism + "_fail"] = int(any(v in {"fail", "softfail", "permerror"} for v in statuses))
        result[mechanism + "_pass"] = int("pass" in statuses)
        result[mechanism + "_missing"] = int(not statuses)
    return result
