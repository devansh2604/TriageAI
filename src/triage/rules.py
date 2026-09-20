"""Explainable triage indicators; ATT&CK mappings are hypotheses, not attribution."""
from src.features import url_features, header_features, content_features

# Key, flag id, severity, ATT&CK technique, analyst evidence label.
SPECS = [
    ("ip_urls", "URL_IP", 4, "T1566.002", "IP-literal link"),
    ("lookalike", "LOOKALIKE", 4, "T1036", "Brand-like unofficial domain"),
    ("shorteners", "SHORT_LINK", 2, "T1566.002", "Shortened link; destination unresolved"),
    ("anchor_mismatch", "ANCHOR_MISMATCH", 4, "T1566.002", "Visible domain differs from destination"),
    ("at_in_url", "URL_USERINFO", 3, "T1566.002", "URL contains @"),
    ("punycode", "IDN", 2, "T1036", "Punycode domain; may be legitimate"),
    ("display_mismatch", "DISPLAY_MISMATCH", 3, "T1036", "Brand display name differs from sender domain"),
    ("reply_mismatch", "REPLY_MISMATCH", 2, "T1036", "Reply address differs from sender"),
    ("dmarc_fail", "DMARC_FAIL", 3, "T1036", "Unverified uploaded header reports DMARC failure"),
    ("credential_request", "CREDENTIALS", 3, "T1598", "Credential or sensitive-information request"),
    ("risky_attachments", "RISKY_ATTACHMENT", 5, "T1566.001", "Executable or macro-capable attachment"),
    ("html_forms", "HTML_FORM", 4, "T1598", "Embedded HTML form"),
    ("hidden_text", "HIDDEN_TEXT", 2, "T1036", "Hidden or tiny markup text"),
    ("urgency", "URGENCY", 1, "T1598", "Urgency or threat wording"),
]

def detect(row, ai_probability=None):
    facts = {**url_features.extract(row), **header_features.extract(row), **content_features.extract(row)}
    result = [{"flag_id": flag, "severity": severity, "evidence": f"{label}: {facts[key]}",
               "attack_technique": technique} for key, flag, severity, technique, label in SPECS if facts[key]]
    services = {"docs.google.com", "forms.office.com", "sharepoint.com", "dropbox.com"}
    if facts["credential_request"] and any(any(url_features.host(u) == service or
            url_features.host(u).endswith("." + service) for service in services) for u in row.get("urls", [])):
        result.append({"flag_id": "SERVICE_LURE", "severity": 3,
                       "evidence": "Sensitive-information request includes a hosted-service link",
                       "attack_technique": "T1566.003"})
    if ai_probability is not None and ai_probability >= .8:
        result.append({"flag_id": "AI_STYLE", "severity": 1,
                       "evidence": f"Likely AI-generated style (experimental): {ai_probability:.2f}; not proof",
                       "attack_technique": None})
    return result

def rule_score(flags):
    # AI authorship is descriptive only: it never increases the triage score.
    return min(1., sum(flag["severity"] for flag in flags if flag["flag_id"] != "AI_STYLE") / 20.)

def blend(probability, flags, weight=.85):
    if not 0 <= weight <= 1:
        raise ValueError("blend_ml must be between zero and one")
    return float(weight * probability + (1-weight) * rule_score(flags))
