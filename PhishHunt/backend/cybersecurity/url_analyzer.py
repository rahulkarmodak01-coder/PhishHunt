from urllib.parse import urlparse
import ipaddress
import re


def is_ip_address(hostname):
    """Check whether the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url):
    """
    Analyze a URL without visiting it.
    Returns extracted security features and a basic risk score.
    """

    # Add a scheme if the user enters something like example.com
    original_url = url.strip()

    if not original_url:
        return {"error": "URL cannot be empty."}

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original_url):
        url = "http://" + original_url
    else:
        url = original_url

    try:
        parsed = urlparse(url)
    except Exception:
        return {"error": "Invalid URL."}

    hostname = parsed.hostname

    if not hostname:
        return {"error": "Could not identify the domain."}

    hostname = hostname.lower()

    # -----------------------------
    # Feature extraction
    # -----------------------------

    features = {
        "url_length": len(original_url),
        "hostname_length": len(hostname),
        "https": parsed.scheme.lower() == "https",
        "has_ip_address": is_ip_address(hostname),
        "has_at_symbol": "@" in original_url,
        "has_double_slash_redirect": "//" in parsed.path,
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "digit_count": sum(c.isdigit() for c in hostname),
        "special_character_count": len(
            re.findall(r"[^a-zA-Z0-9.\-]", hostname)
        ),
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "has_punycode": hostname.startswith("xn--") or ".xn--" in hostname,
    }

    # -----------------------------
    # Suspicious indicators
    # -----------------------------

    indicators = []
    risk_score = 0

    if features["has_ip_address"]:
        risk_score += 25
        indicators.append("Hostname is an IP address")

    if features["has_at_symbol"]:
        risk_score += 20
        indicators.append("URL contains @ symbol")

    if features["url_length"] > 100:
        risk_score += 10
        indicators.append("Very long URL")

    if features["hostname_length"] > 50:
        risk_score += 10
        indicators.append("Very long hostname")

    if features["subdomain_count"] >= 3:
        risk_score += 10
        indicators.append("Excessive subdomains")

    if features["hyphen_count"] >= 3:
        risk_score += 5
        indicators.append("Many hyphens in hostname")

    if features["has_punycode"]:
        risk_score += 15
        indicators.append("Punycode domain detected")

    if not features["https"]:
        risk_score += 10
        indicators.append("Connection does not use HTTPS")

    if features["has_double_slash_redirect"]:
        risk_score += 10
        indicators.append("Possible redirect pattern in path")

    # Keep score between 0 and 100
    risk_score = min(risk_score, 100)

    # -----------------------------
    # Classification
    # -----------------------------

    if risk_score >= 60:
        classification = "HIGH RISK"
    elif risk_score >= 30:
        classification = "SUSPICIOUS"
    else:
        classification = "LOW RISK"

    return {
        "url": original_url,
        "hostname": hostname,
        "features": features,
        "risk_score": risk_score,
        "classification": classification,
        "indicators": indicators,
    }


# -----------------------------------------
# Test the analyzer directly
# -----------------------------------------

if __name__ == "__main__":

    test_urls = [
        "https://www.google.com",
        "http://example.com/login",
        "http://192.168.1.10/login",
        "http://example.com@evil.example/login",
    ]

    for test_url in test_urls:

        print("\n" + "=" * 60)
        print("URL:", test_url)
        print("=" * 60)

        result = analyze_url(test_url)

        if "error" in result:
            print("ERROR:", result["error"])
            continue

        print("Hostname:", result["hostname"])
        print("Risk Score:", result["risk_score"], "/ 100")
        print("Classification:", result["classification"])

        print("\nIndicators:")

        if result["indicators"]:
            for indicator in result["indicators"]:
                print(" -", indicator)
        else:
            print(" - No obvious suspicious indicators")