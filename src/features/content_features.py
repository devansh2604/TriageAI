"""Text and markup indicators for SOC alert triage."""
import re
from bs4 import BeautifulSoup
from src.common import normalize

RISKY = {".exe", ".scr", ".js", ".vbs", ".hta", ".iso", ".lnk", ".docm", ".xlsm", ".ps1"}

def text(row):
    html = BeautifulSoup(row.get("body_html", ""), "html.parser")
    for tag in html(["script", "style"]):
        tag.decompose()
    # Preserve hidden text as evidence; do not render or load external content.
    return normalize(row.get("subject", "") + " " + row.get("body_text", "") + " " +
                     html.get_text(" ", strip=True)).lower().replace("hxxp", "http").replace("[.]", ".")

def extract(row):
    value = text(row)
    soup = BeautifulSoup(row.get("body_html", ""), "html.parser")
    hidden = 0
    for tag in soup.find_all(True):
        style = str(tag.get("style", "")).replace(" ", "").lower()
        hidden += int(tag.has_attr("hidden") or bool(re.search(
            r"display:none|visibility:hidden|opacity:0(?:;|$)|font-size:(?:0|1|2)(?:px|pt)", style)))
    return {"urgency": len(re.findall(r"\b(urgent|immediately|asap|expires?|suspended|terminated|final warning)\b", value)),
            "credential_request": len(re.findall(r"verify (?:your )?account|reset (?:your )?password|"
                                                   r"confirm (?:your )?(?:password|identity)|sign in|log in|"
                                                   r"credit card|social security", value)),
            "generic_greeting": len(re.findall(r"dear (?:user|customer|member)|valued customer", value)),
            "html_forms": len(soup.find_all("form")), "hidden_text": hidden,
            "risky_attachments": sum(str(a.get("ext", "")).lower() in RISKY
                                     for a in row.get("attachments", [])),
            "text_length": len(value)}
