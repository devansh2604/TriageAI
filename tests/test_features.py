import numpy as np
from scipy.sparse import issparse
import pytest
from src.features import url_features as urls, header_features as headers, content_features as content
from src.features.ai_text_features import TextSignals
from src.features.pipeline import features
from src.data.parse import make_alert

@pytest.mark.parametrize("url,key", [
    ("http://127.0.0.1/a", "ip_urls"), ("http://[::1]/a", "ip_urls"),
    ("https://bit.ly/a", "shorteners"), ("https://paypal-login.example/a", "lookalike"),
    ("https://pаypal.com/a", "lookalike"), ("https://x.zip/a", "risky_tld"),
    ("https://good.com@evil.com/a", "at_in_url"), ("https://xn--pple-43d.com", "punycode")])
def test_url_indicators(url, key):
    assert urls.extract(make_alert(body_text=url))[key] == 1

def test_real_brand_not_lookalike():
    assert urls.lookalike("login.paypal.com") == 0

def test_anchor_mismatch(alert):
    assert urls.extract(alert)["anchor_mismatch"] == 1

def test_subdomains():
    assert urls.extract(make_alert(body_text="http://a.b.example.com"))["subdomain_depth"] == 2

def test_header_mismatch(alert):
    result = headers.extract(alert)
    assert result["reply_mismatch"] == result["display_mismatch"] == 1

def test_auth_results():
    row = make_alert(headers={"Authentication-Results": ["mx; spf=fail; dkim=pass; dmarc=fail"]})
    result = headers.extract(row)
    assert result["spf_fail"] == result["dkim_pass"] == result["dmarc_fail"] == 1
    assert result["spf_missing"] == 0

def test_missing_auth_is_not_fail():
    result = headers.extract(make_alert())
    assert result["spf_missing"] == 1 and result["spf_fail"] == 0

def test_xmailer_and_hops():
    row = make_alert(headers={"X-Mailer": ["PHP bulk mail"], "Received": ["one", "two"]})
    assert headers.extract(row)["received_hops"] == 2
    assert headers.extract(row)["x_mailer_anomaly"] == 1

def test_bad_headers():
    assert headers.headers({"headers_json": "not JSON"}) == {}

def test_forms_hidden_attachments():
    row = make_alert(body_html='<form><span style="display:none">x</span></form>',
                     attachments=[{"name": "a.docm", "ext": ".docm"}])
    result = content.extract(row)
    assert result["html_forms"] == result["hidden_text"] == result["risky_attachments"] == 1

def test_content_keywords(alert):
    result = content.extract(alert)
    assert result["urgency"] >= 1 and result["credential_request"] >= 1

def test_text_signals_finite():
    model = TextSignals().fit(["Human email. More text."])
    result = model.transform(["", "Hello. Hello!", "teh acount"])
    assert result.shape == (3, 5) and np.isfinite(result).all()
    assert result[-1, -1] == 0

def test_sparse_pipeline(alert):
    pipeline = features()
    result = pipeline.fit_transform([alert, make_alert(body_text="Team meeting notes")])
    assert issparse(result) and result.shape[0] == 2
    assert len(pipeline.named_steps["columns"].get_feature_names_out()) == result.shape[1]

def test_no_header_source_label_leakage(alert):
    model = features().fit([alert])
    other = dict(alert, label=0, source="different", alert_id="changed")
    assert (model.transform([alert]) != model.transform([other])).nnz == 0
