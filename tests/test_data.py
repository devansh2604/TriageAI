import json
import pandas as pd
import pytest
from src.common import normalize
from src.data.parse import parse_eml, make_alert, extract_urls
from src.data.build import deduplicate, queue_sample


def test_mime_and_attachment():
    from email.message import EmailMessage
    mail = EmailMessage()
    mail["Subject"] = "Invoice"
    mail.set_content("Plain text")
    mail.add_alternative('<a href="https://example.com">link</a>', subtype="html")
    mail.add_attachment(b"never execute", maintype="application", subtype="octet-stream", filename="bill.exe")
    row = parse_eml(mail.as_bytes())
    assert "Plain text" in row["body_text"]
    assert row["attachments"] == [{"name": "bill.exe", "ext": ".exe"}]
    assert row["urls"] == ["https://example.com"]

def test_repeated_headers():
    row = parse_eml(b"Received: one\nReceived: two\nSubject: x\n\nbody")
    assert len(json.loads(row["headers_json"])["received"]) == 2

def test_oversized_rejected():
    with pytest.raises(ValueError, match="2 MB"):
        parse_eml(b"x"*2_000_001)

def test_invalid_charset():
    assert "hello" in parse_eml(b"Content-Type: text/plain; charset=madeup\n\nhello")["body_text"]

def test_bad_date_is_missing():
    assert parse_eml(b"Date: nonsense\n\nx")["received_at"] is None

def test_normalization():
    assert normalize("ｐａｙ\u200bpal\x00") == "paypal"

def test_obfuscated_url():
    assert extract_urls("hxxps://evil[.]com/login") == ["https://evil.com/login"]

def test_exact_duplicates_removed():
    row = make_alert(body_text="Repeated body", label=0)
    assert len(deduplicate(pd.DataFrame([row, row]))) == 1

def test_conflicting_labels_removed():
    assert deduplicate(pd.DataFrame([make_alert(body_text="same", label=0),
                                     make_alert(body_text="same", label=1)])).empty

def test_near_duplicates_removed():
    body = " ".join(f"word{i}" for i in range(200))
    rows = [make_alert(body_text=body, label=0), make_alert(body_text=body+" extra", label=0)]
    assert len(deduplicate(pd.DataFrame(rows))) == 1

def test_queue_prevalence_no_replacement():
    frame = pd.DataFrame({"label": [0]*170+[1]*100, "alert_id": range(270)})
    queue = queue_sample(frame)
    assert queue.label.mean() == .15
    assert queue.alert_id.is_unique

def test_queue_small_fails():
    with pytest.raises(ValueError):
        queue_sample(pd.DataFrame({"label": [0, 1]}))
