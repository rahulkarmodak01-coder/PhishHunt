from urllib.parse import urlparse
import ipaddress
import re


# ============================================================
# KNOWN LEGITIMATE DOMAINS
# ============================================================

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


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_WORDS = [
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "passwd",
    "payment",
    "bank",
    "wallet",
    "confirm",
    "authentication",
    "authorize",
    "billing",
    "recover",
    "suspended",
    "unlock"
]


# ============================================================
# SUSPICIOUS TLDs
# ============================================================

SUSPICIOUS_TLDS = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".click",
    ".work",
    ".zip",
    ".mov"
}


# ============================================================
# BRANDS OFTEN IMPERSONATED
# ============================================================

BRAND_NAMES = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "github",
    "bank"
]


# ============================================================
# IP ADDRESS CHECK
# ============================================================

def is_ip(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# ============================================================
# SUSPICIOUS KEYWORD CHECK
# ============================================================

def find_suspicious_words(url):
    url_lower = url.lower()

    found = []

    for word in SUSPICIOUS_WORDS:
        if word in url_lower:
            found.append(word)

    return found


# ============================================================
# BRAND IMPERSONATION CHECK
# ============================================================

def find_brand_impersonation(hostname):
    hostname_lower = hostname.lower()

    found_brands = []

    for brand in BRAND_NAMES:
        if brand in hostname_lower:
            found_brands.append(brand)

    return found_brands


# ============================================================
# MAIN SECURITY ANALYZER
# ============================================================

def analyze_security_rules(url):

    url = str(url).strip()

    if not url:
        return {
            "decision": "HIGH RISK",
            "risk_score": 100,
            "reason": "Empty URL",
            "indicators": ["No URL was provided"]
        }

    # Normalize scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    indicators = []
    risk_score = 0

    # Exact hostname check
    is_trusted_domain = hostname in TRUSTED_DOMAINS

    # --------------------------------------------------------
    # Invalid hostname
    # --------------------------------------------------------

    if not hostname:
        return {
            "decision": "HIGH RISK",
            "risk_score": 100,
            "reason": "Invalid URL structure",
            "indicators": [
                "Hostname could not be identified"
            ]
        }

    # --------------------------------------------------------
    # Trusted-domain indicator
    # --------------------------------------------------------

    if is_trusted_domain:
        indicators.append(
            "Exact hostname matched trusted-domain list"
        )

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    if is_ip(hostname):
        risk_score += 30
        indicators.append(
            "IP address used instead of domain name"
        )

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if parsed.scheme == "http":
        risk_score += 10
        indicators.append(
            "Connection does not use HTTPS"
        )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if "@" in url:
        risk_score += 25
        indicators.append(
            "@ symbol detected in URL"
        )

    # --------------------------------------------------------
    # URL length
    # --------------------------------------------------------

    if len(url) > 100:
        risk_score += 10
        indicators.append("Very long URL")

    if len(url) > 200:
        risk_score += 10
        indicators.append("Extremely long URL")

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    found_words = find_suspicious_words(full_url)

    if found_words:
        keyword_score = min(
            len(found_words) * 5,
            25
        )

        risk_score += keyword_score

        indicators.append(
            "Suspicious keywords: "
            + ", ".join(found_words)
        )

    # --------------------------------------------------------
    # Punycode
    # --------------------------------------------------------

    if "xn--" in hostname:
        risk_score += 25
        indicators.append(
            "Punycode domain detected"
        )

    # --------------------------------------------------------
    # Subdomains
    # --------------------------------------------------------

    subdomain_count = max(
        0,
        hostname.count(".") - 1
    )

    if subdomain_count >= 3:
        risk_score += 15
        indicators.append(
            "Multiple subdomains detected"
        )

    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    matched_tld = None

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            matched_tld = tld
            break

    if matched_tld:
        risk_score += 15
        indicators.append(
            "Suspicious top-level domain: "
            + matched_tld
        )

    # --------------------------------------------------------
    # Encoded characters
    # --------------------------------------------------------

    encoded_characters = re.findall(
        r"%[0-9a-fA-F]{2}",
        full_url
    )

    if len(encoded_characters) >= 3:
        risk_score += 10
        indicators.append(
            "Multiple URL-encoded characters detected"
        )

    # --------------------------------------------------------
    # Digits in hostname
    # --------------------------------------------------------

    hostname_digits = sum(
        character.isdigit()
        for character in hostname
    )

    if hostname:
        digit_ratio = (
            hostname_digits / len(hostname)
        )

        if digit_ratio > 0.30:
            risk_score += 10
            indicators.append(
                "High number of digits in hostname"
            )

    # --------------------------------------------------------
    # Hyphens
    # --------------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 3:
        risk_score += 10
        indicators.append(
            "Multiple hyphens in hostname"
        )

    # --------------------------------------------------------
    # Brand impersonation
    # --------------------------------------------------------

    found_brands = find_brand_impersonation(hostname)

    if found_brands and not is_trusted_domain:
        risk_score += 20

        indicators.append(
            "Possible brand impersonation: "
            + ", ".join(found_brands)
        )

    # --------------------------------------------------------
    # Brand + suspicious keyword
    # --------------------------------------------------------

    if found_brands and found_words and not is_trusted_domain:
        risk_score += 15

        indicators.append(
            "Brand name combined with suspicious keyword"
        )

    # --------------------------------------------------------
    # Double slash in path
    # --------------------------------------------------------

    if "//" in path:
        risk_score += 10

        indicators.append(
            "Double slash detected inside URL path"
        )

    # --------------------------------------------------------
    # Deep path
    # --------------------------------------------------------

    path_parts = [
        part
        for part in path.split("/")
        if part
    ]

    if len(path_parts) >= 6:
        risk_score += 10

        indicators.append(
            "Deep URL path structure detected"
        )

    # --------------------------------------------------------
    # Suspicious query parameters
    # --------------------------------------------------------

    suspicious_query_words = [
        "password",
        "passwd",
        "token",
        "verify",
        "login",
        "account",
        "payment"
    ]

    found_query_words = []

    for word in suspicious_query_words:
        if word in query:
            found_query_words.append(word)

    if found_query_words:
        risk_score += min(
            len(found_query_words) * 5,
            15
        )

        indicators.append(
            "Sensitive words found in query: "
            + ", ".join(found_query_words)
        )

    # --------------------------------------------------------
    # Special characters
    # --------------------------------------------------------

    special_characters = sum(
        1
        for character in full_url
        if character in "@?=&_%"
    )

    if special_characters >= 8:
        risk_score += 10

        indicators.append(
            "High number of special characters"
        )

    # --------------------------------------------------------
    # Limit score
    # --------------------------------------------------------

    risk_score = min(
        risk_score,
        100
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # Exact clean trusted domains are legitimate.
    #
    # The ML model should NOT be allowed to override this
    # through the final decision engine.
    # --------------------------------------------------------

    if is_trusted_domain and risk_score == 0:

        return {
            "decision": "LEGITIMATE",
            "risk_score": 0,
            "reason": (
                "Known trusted domain with no "
                "additional risk indicators"
            ),
            "indicators": [
                "Exact hostname matched trusted-domain list"
            ]
        }

    # --------------------------------------------------------
    # General security decision
    # --------------------------------------------------------

    if risk_score >= 60:
        decision = "HIGH RISK"

    elif risk_score >= 20:
        decision = "SUSPICIOUS"

    else:
        decision = "LOW RISK"

    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    if not indicators:
        reason = (
            "No major URL-based security indicators detected"
        )
    else:
        reason = (
            f"{len(indicators)} security indicator(s) detected"
        )

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return {
        "decision": decision,
        "risk_score": risk_score,
        "reason": reason,
        "indicators": indicators
    }