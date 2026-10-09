from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import math
import re


# ============================================================
# PHISHHUNT ML PREDICTION FEATURE EXTRACTOR
# ============================================================


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "question_count",
    "equal_count",
    "at_count",
    "digit_count",
    "has_ip",
    "has_at_symbol",
    "has_double_slash",
    "subdomain_count",
    "has_punycode",
    "has_suspicious_word",
    "query_length",
    "fragment_length",
    "digit_ratio",
    "letter_ratio",
    "special_ratio",
    "url_entropy",
    "suspicious_word_count",
    "brand_count",
    "suspicious_tld",
    "path_depth",
    "encoded_character_count",
    "repeated_character",
    "hostname_has_digit",
    "hostname_has_hyphen",
    "hostname_has_underscore",
]


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
    "unlock",
]


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
    "whatsapp",
    "wikipedia",
    "bank",
]


SUSPICIOUS_TLDS = [
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
    ".mov",
]


def is_ip_address(hostname):
    """
    Check whether hostname is an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.
    """

    if not text:
        return 0.0

    length = len(text)

    frequencies = {
        char: text.count(char)
        for char in set(text)
    }

    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_features(url):
    """
    Extract the 31 URL-based features used by PhishHunt ML.

    Important:
    - No webpage is visited.
    - No external request is made.
    - Only the supplied URL string is analyzed.
    """

    if not isinstance(url, str):
        url = str(url)

    url = url.strip()

    # --------------------------------------------------------
    # Normalize URL
    # --------------------------------------------------------

    normalized_url = url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized_url):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    # --------------------------------------------------------
    # Canonicalize ONLY a bare root slash
    #
    # https://example.com/
    # becomes equivalent to:
    # https://example.com
    #
    # But /login/, /account/, etc. remain unchanged.
    # --------------------------------------------------------

    feature_url = url

    if (
      parsed.path == "/"
      and not parsed.query
      and not parsed.fragment
    ):
      feature_url = url[:-1]

    # --------------------------------------------------------
    # Basic URL features
    # --------------------------------------------------------

    url_length = len(feature_url)

    hostname_length = len(hostname)

    path = parsed.path

# Treat the root "/" as an empty path.
    if path == "/":
      path = ""

    path_length = len(path)

    dot_count = feature_url.count(".")
    hyphen_count = feature_url.count("-")
    underscore_count = feature_url.count("_")
    question_count = feature_url.count("?")
    equal_count = feature_url.count("=")
    at_count = feature_url.count("@")

    digit_count = sum(
     char.isdigit()
     for char in feature_url
    )

    # --------------------------------------------------------
    # IP / special URL indicators
    # --------------------------------------------------------

    has_ip = is_ip_address(hostname)

    has_at_symbol = int("@" in url)

    # Detect // inside the PATH only.
    # This intentionally does NOT count https://
    # or http://.
    has_double_slash = int("//" in path)

    # --------------------------------------------------------
    # Subdomains
    # --------------------------------------------------------

    subdomain_count = max(
        0,
        hostname.count(".") - 1
    )

    # --------------------------------------------------------
    # Punycode
    # --------------------------------------------------------

    has_punycode = int(
        "xn--" in hostname_lower
    )

    # --------------------------------------------------------
    # Suspicious words
    # --------------------------------------------------------

    url_lower = url.lower()

    found_suspicious_words = []

    for word in SUSPICIOUS_WORDS:
        if word in url_lower:
            found_suspicious_words.append(word)

    suspicious_word_count = len(
        found_suspicious_words
    )

    has_suspicious_word = int(
        suspicious_word_count > 0
    )

    # --------------------------------------------------------
    # Query / fragment
    # --------------------------------------------------------

    query_length = len(query)

    fragment_length = len(fragment)

    # --------------------------------------------------------
    # Character ratios
    # --------------------------------------------------------

    if url_length > 0:

        digit_ratio = (
            digit_count / url_length
        )

        letter_count = sum(
            char.isalpha()
            for char in feature_url
        )

        letter_ratio = (
            letter_count / url_length
        )

        special_count = sum(
            not char.isalnum()
            for char in feature_url
        )

        special_ratio = (
            special_count / url_length
        )

    else:

        digit_ratio = 0.0
        letter_ratio = 0.0
        special_ratio = 0.0

    # --------------------------------------------------------
    # URL entropy
    # --------------------------------------------------------

    url_entropy = calculate_entropy(feature_url)

    # --------------------------------------------------------
    # Brand count
    # --------------------------------------------------------

    found_brands = []

    for brand in BRAND_NAMES:
        if brand in url_lower:
            found_brands.append(brand)

    brand_count = len(found_brands)

    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    suspicious_tld = int(
        any(
            hostname_lower.endswith(tld)
            for tld in SUSPICIOUS_TLDS
        )
    )

    # --------------------------------------------------------
    # Path depth
    # --------------------------------------------------------

    path_parts = [
        part
        for part in path.split("/")
        if part
    ]

    path_depth = len(path_parts)

    # --------------------------------------------------------
    # Encoded characters
    # --------------------------------------------------------

    encoded_character_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    # --------------------------------------------------------
    # Repeated character
    #
    # IMPORTANT:
    # Ignore www.
    # Normal domains such as www.google.com
    # must not be marked suspicious because of
    # the three w's.
    # --------------------------------------------------------

    hostname_repeat_check = hostname_lower

    if hostname_repeat_check.startswith("www."):
        hostname_repeat_check = (
            hostname_repeat_check[4:]
        )

    repeated_character = int(
        bool(
            re.search(
                r"(.)\1\1",
                hostname_repeat_check
            )
        )
    )

    # --------------------------------------------------------
    # Hostname character indicators
    # --------------------------------------------------------

    hostname_digit_count = sum(
        char.isdigit()
        for char in hostname
    )

    hostname_has_digit = int(
        hostname_digit_count > 0
    )

    hostname_has_hyphen = int(
        "-" in hostname
    )

    hostname_has_underscore = int(
        "_" in hostname
    )

    # --------------------------------------------------------
    # Feature dictionary
    #
    # 31 FEATURES
    #
    # Removed:
    # - uses_https
    # - slash_count
    # --------------------------------------------------------

    features = {

        "url_length":
            url_length,

        "hostname_length":
            hostname_length,

        "path_length":
            path_length,

        "dot_count":
            dot_count,

        "hyphen_count":
            hyphen_count,

        "underscore_count":
            underscore_count,

        "question_count":
            question_count,

        "equal_count":
            equal_count,

        "at_count":
            at_count,

        "digit_count":
            digit_count,

        "has_ip":
            has_ip,

        "has_at_symbol":
            has_at_symbol,

        "has_double_slash":
            has_double_slash,

        "subdomain_count":
            subdomain_count,

        "has_punycode":
            has_punycode,

        "has_suspicious_word":
            has_suspicious_word,

        "query_length":
            query_length,

        "fragment_length":
            fragment_length,

        "digit_ratio":
            digit_ratio,

        "letter_ratio":
            letter_ratio,

        "special_ratio":
            special_ratio,

        "url_entropy":
            url_entropy,

        "suspicious_word_count":
            suspicious_word_count,

        "brand_count":
            brand_count,

        "suspicious_tld":
            suspicious_tld,

        "path_depth":
            path_depth,

        "encoded_character_count":
            encoded_character_count,

        "repeated_character":
            repeated_character,

        "hostname_has_digit":
            hostname_has_digit,

        "hostname_has_hyphen":
            hostname_has_hyphen,

        "hostname_has_underscore":
            hostname_has_underscore,
    }

    return features


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "phishhunt_model.pkl"
)