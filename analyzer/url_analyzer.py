import ipaddress
import re
from urllib.parse import urlsplit

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "account", "password",
    "signin", "secure", "update", "wallet",
    "confirm", "banking", "payment"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly"
}


def is_valid_hostname(hostname):
    """Validate that hostname is either a valid IP or a conforming domain name."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    labels = hostname.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", label):
            return False
    return True


def analyze_url(raw_url):
    """Analyze URL characteristics without visiting the website."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Please enter a URL.")

    raw_url = raw_url.strip()

    if len(raw_url) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")

    # Reject whitespace and control characters.
    if re.search(r"\s", raw_url) or any(
        ord(char) < 32 or ord(char) == 127 for char in raw_url
    ):
        raise ValueError("The URL contains invalid whitespace or control characters.")

    # Accept example.com by assuming HTTPS.
    working_url = raw_url
    has_explicit_scheme = "://" in raw_url
    if not has_explicit_scheme:
        working_url = f"https://{raw_url}"

    try:
        parsed = urlsplit(working_url)
    except Exception as exc:
        raise ValueError(f"Unable to parse the URL: {exc}")

    # Validate scheme
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: '{parsed.scheme}'. Only HTTP and HTTPS are supported.")

    # Validate port
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid URL port: {exc}")

    # Reject embedded credentials
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise ValueError("URLs containing embedded credentials are not allowed.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname or not is_valid_hostname(hostname):
        raise ValueError("The URL contains an invalid hostname.")

    indicators = []

    # 1. Check if the hostname is an IP address
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        indicators.append({
            "name": "IP address used as hostname",
            "points": 30,
            "explanation": "The URL uses a raw IP address instead of a domain name, a common technique to evade domain-based reputation filters."
        })
    except ValueError:
        is_ip = False

    # 2. Check for URL shorteners
    if hostname in SHORTENER_DOMAINS or any(hostname.endswith(f".{domain}") for domain in SHORTENER_DOMAINS):
        indicators.append({
            "name": "URL Shortener Service",
            "points": 20,
            "explanation": "The link points to a URL shortening service, which obscures the ultimate destination of the website."
        })

    # 3. Check for suspicious keywords in hostname, path, and query
    search_target = f"{hostname}{parsed.path}{parsed.query}".lower()
    matched_keywords = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in search_target})
    if matched_keywords:
        indicators.append({
            "name": "Security-sensitive keywords",
            "points": 20,
            "explanation": f"The URL includes sensitive keywords ({', '.join(matched_keywords)}) frequently used in credential-harvesting phishing campaigns."
        })

    # 4. Check for unusual URL length (> 75 characters)
    if len(raw_url) > 75:
        indicators.append({
            "name": "Long URL",
            "points": 10,
            "explanation": "The URL exceeds 75 characters, which attackers often use to disguise malicious parameters or push suspicious parts off-screen."
        })

    # 5. Check for excessive subdomains
    if not is_ip:
        dots_count = hostname.count(".")
        if dots_count >= 3:
            indicators.append({
                "name": "Excessive Subdomains",
                "points": 15,
                "explanation": f"The domain has {dots_count} dot separators, suggesting deep subdomain nesting often employed to impersonate trusted services."
            })

    # 6. Check for hyphens in domain name
    if not is_ip and "-" in hostname:
        indicators.append({
            "name": "Hyphenated Domain",
            "points": 10,
            "explanation": "The hostname contains hyphens, a pattern common in typosquatting and brand spoofing domains."
        })

    # 7. Check for unencrypted HTTP
    if has_explicit_scheme and parsed.scheme.lower() == "http":
        indicators.append({
            "name": "Unencrypted HTTP",
            "points": 10,
            "explanation": "The URL uses unencrypted HTTP instead of HTTPS, lacking transport security and modern certificate verification."
        })

    # 8. Check for percent-encoded characters
    if re.search(r"%[0-9a-fA-F]{2}", raw_url):
        indicators.append({
            "name": "Percent-encoded characters",
            "points": 10,
            "explanation": "The URL contains percent-encoded characters, often used to conceal malicious strings or evade detection filters."
        })

    # Calculate total risk score
    total_score = sum(ind["points"] for ind in indicators)
    risk_score = max(0, min(total_score, 100))

    # Determine risk level and analyst note
    if risk_score >= 80:
        risk_level = "CRITICAL"
        message = "Critical risk indicators detected. This link strongly exhibits phishing or malicious traits."
    elif risk_score >= 60:
        risk_level = "HIGH"
        message = "Multiple high-risk indicators detected. This link displays characteristics strongly aligned with phishing or deceptive sites."
    elif risk_score >= 25:
        risk_level = "MEDIUM"
        message = "Suspicious indicators detected. Proceed with caution and verify the source before providing any credentials or personal data."
    else:
        risk_level = "LOW"
        message = "No high-risk structural characteristics were detected by current heuristic checks. Always practice caution with unexpected links."

    return {
        "submitted_url": raw_url,
        "hostname": hostname,
        "scheme": parsed.scheme.lower(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "message": message,
    }
