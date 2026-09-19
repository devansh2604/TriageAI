"""Bounded MIME ingestion; never fetch URLs or execute attachments."""
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import PurePath
import json
import re
from bs4 import BeautifulSoup
from src.common import digest, normalize

MAX_EMAIL_BYTES = 2_000_000
URL_RE = re.compile(r"(?:https?|hxxps?)://[^\s<>\"']+", re.I)

def extract_urls(text, html=""):
    soup = BeautifulSoup(html[:500_000], "html.parser")
    values = URL_RE.findall(normalize(text))
    values += [str(a.get("href", "")) for a in soup.find_all("a")]
    return sorted({normalize(u).replace("hxxps://", "https://").replace("hxxp://", "http://")
                   .replace("[.]", ".").rstrip(".,;)") for u in values
                   if u.lower().startswith(("http://", "https://", "hxxp://", "hxxps://"))})[:500]

def make_alert(subject="", body_text="", body_html="", from_addr="", reply_to="",
               headers=None, attachments=None, label=None, source="user", received_at=None):
    html = str(body_html or "")[:500_000]
    text = str(body_text or "")[:500_000]
    if not text:
        text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
    item = dict(subject=str(subject or "")[:2000], body_text=text, body_html=html,
                from_addr=str(from_addr or "")[:2000], reply_to=str(reply_to or "")[:2000],
                headers_json=json.dumps(headers or {}, sort_keys=True),
                urls=extract_urls(text, html), attachments=attachments or [], label=label, source=source)
    item["alert_id"] = digest(item)[:24]
    item["reporter_id"] = "synthetic-" + item["alert_id"][:8]
    item["received_at"] = received_at
    return item

def parse_eml(raw, label=None, source="user"):
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Email exceeds 2 MB ingestion limit")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    texts, htmls, attachments = [], [], []
    for part in message.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if name or part.get_content_disposition() == "attachment":
            name = str(name or "unnamed")[:255]
            attachments.append({"name": name, "ext": PurePath(name).suffix.lower()})
        elif part.get_content_type() in ("text/plain", "text/html"):
            raw_part = part.get_payload(decode=True) or b""
            try:
                value = raw_part.decode(part.get_content_charset() or "utf-8", errors="replace")
            except LookupError:
                value = raw_part.decode("utf-8", errors="replace")
            (htmls if part.get_content_type() == "text/html" else texts).append(value)
    received = None
    try:
        received = parsedate_to_datetime(str(message.get("Date"))).isoformat()
    except (TypeError, ValueError, OverflowError):
        pass
    headers = {key.lower(): [str(v) for v in message.get_all(key)] for key in message.keys()}
    return make_alert(str(message.get("Subject", "")), "\n".join(texts), "\n".join(htmls),
                      str(message.get("From", "")), str(message.get("Reply-To", "")),
                      headers, attachments, label, source, received)
