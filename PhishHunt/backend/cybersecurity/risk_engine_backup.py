from urllib.parse import urlparse
import ipaddress


# Known legitimate domains for our project demo.
# Matching is exact, so evil.com/google.com will NOT be trusted.
TRUSTED_DOMAINS = {
    "google.com",
    "www.google.com",

    "microsoft.com",
    "www.microsoft.com",

    "wikipedia.org",
    "www.wikipedia.org",

    "github.com",
    "www.github.com",

    "amazon.com",
    "www.amazon.com",

    "apple.com",
    "www.apple.com",

    "python.org",
    "www.python.org",

    "cloudflare.com",
    "www.cloudflare.com",

    "mozilla.org",
    "www.mozilla.org",

    "ibm.com",
    "www.ibm.com"
}


def is_ip(hostname):
    """Check whether hostname is an IP address."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_security_rules(url):
    """
    Analyze a URL using cybersecurity rules.
    This does NOT visit the URL.
    """

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()

    indicators = []
    risk_score = 0

    # ------------------------------------------------
    # Rule 1: Trusted exact domain
    # ------------------------------------------------

    if hostname in TRUSTED_DOMAINS:

        return {
            "decision": "LEGITIMATE",
            "risk_score": 0,
            "reason": "Known trusted domain",
            "indicators": [
                "Exact hostname matched trusted-domain list"
            ]
        }

    # ------------------------------------------------
    # Rule 2: IP address instead of domain
    # ------------------------------------------------

    if is_ip(hostname):
        risk_score += 30
        indicators.append("IP address used instead of domain name")

    # ------------------------------------------------
    # Rule 3: HTTP instead of HTTPS
    # ------------------------------------------------

    if parsed.scheme == "http":
        risk_score += 10
        indicators.append("Connection does not use HTTPS")

    # ------------------------------------------------
    # Rule 4: @ symbol
    # ------------------------------------------------

    if "@" in url:
        risk_score += 25
        indicators.append("@ symbol detected")

    # ------------------------------------------------
    # Rule 5: Very long URL
    # ------------------------------------------------

    if len(url) > 100:
        risk_score += 10
        indicators.append("Very long URL")

    # ------------------------------------------------
    # Rule 6: Suspicious words
    # ------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "update",
        "password",
        "payment",
        "bank",
        "signin",
        "confirm",
        "wallet"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url:
            found_words.append(word)

    if found_words:
        risk_score += min(len(found_words) * 5, 25)
        indicators.append(
            "Suspicious keywords: " + ", ".join(found_words)
        )

    # ------------------------------------------------
    # Rule 7: Punycode
    # ------------------------------------------------

    if "xn--" in hostname:
        risk_score += 25
        indicators.append("Punycode domain detected")

    # ------------------------------------------------
    # Rule 8: Excessive subdomains
    # ------------------------------------------------

    subdomain_count = max(0, hostname.count(".") - 1)

    if subdomain_count >= 3:
        risk_score += 15
        indicators.append("Multiple subdomains detected")

    # ------------------------------------------------
    # Limit score
    # ------------------------------------------------

    risk_score = min(risk_score, 100)

    # ------------------------------------------------
    # Final decision
    # ------------------------------------------------

    if risk_score >= 60:
        decision = "HIGH RISK"

    elif risk_score >= 30:
        decision = "SUSPICIOUS"

    else:
        decision = "LOW RISK"

    return {
        "decision": decision,
        "risk_score": risk_score,
        "reason": "Cybersecurity rules analyzed the URL",
        "indicators": indicators
    }