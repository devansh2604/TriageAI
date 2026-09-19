"""Offline URL indicators using the bundled public-suffix snapshot."""
import ipaddress
import re
from urllib.parse import urlsplit
from difflib import SequenceMatcher
from bs4 import BeautifulSoup
import tldextract
from src.common import normalize

EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
BRANDS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
          "google": "google.com", "chase": "chase.com", "hsbc": "hsbc.com",
          "bankofamerica": "bankofamerica.com", "wellsfargo": "wellsfargo.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "rb.gy"}
CONFUSABLES = str.maketrans("аесорхуіӏο", "aecopxyilo")

def host(url):
    try:
        return (urlsplit(normalize(url).replace("[.]", ".")).hostname or "").lower()
    except ValueError:
        return ""

def domain(value):
    h = host(value) if "://" in value else value.lower().rstrip(".")
    ext = EXTRACT(h)
    return ext.top_domain_under_public_suffix or h

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def lookalike(value):
    try:
        decoded = value.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        decoded = value
    skeleton = normalize(decoded).translate(CONFUSABLES).lower()
    registered = domain(skeleton)
    stem = EXTRACT(registered).domain
    for brand, official in BRANDS.items():
        if domain(value) == official:
            continue
        if brand in skeleton or (len(stem) >= 4 and SequenceMatcher(None, stem, brand).ratio() >= .8):
            return 1
    return 0

def extract(row):
    urls = list(row.get("urls", []))
    hosts = [host(u) for u in urls]
    soup = BeautifulSoup(row.get("body_html", ""), "html.parser")
    mismatch = 0
    for anchor in soup.find_all("a", href=True):
        text = anchor.get_text(" ", strip=True)
        visible = re.search(r"(?:https?://)?([\w.-]+\.[a-z]{2,})(?:/|$)", text, re.I)
        if visible and domain(visible.group(1)) != domain(host(anchor["href"])):
            mismatch += 1
    return {"url_count": len(urls), "ip_urls": sum(is_ip(h) for h in hosts),
            "shorteners": sum(domain(h) in SHORTENERS for h in hosts),
            "lookalike": sum(lookalike(h) for h in hosts),
            "risky_tld": sum(EXTRACT(h).suffix in {"zip", "mov", "top", "click", "xyz"} for h in hosts),
            "subdomain_depth": max([len(EXTRACT(h).subdomain.split("."))
                                     if EXTRACT(h).subdomain else 0 for h in hosts] or [0]),
            "at_in_url": sum("@" in u for u in urls), "anchor_mismatch": mismatch,
            "punycode": sum("xn--" in h for h in hosts)}
