"""Feature extraction and explainable rule signals for ThreatLens.

URLs are analysed as text only. This module never opens or visits links.
"""
import math
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "support", "work", "gq", "tk",
    "ml", "cf", "ga", "zip", "mov", "cam", "rest", "icu",
    "monster", "buzz",
}

URL_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "wallet", "suspend", "unlock",
    "billing", "kyc", "refund", "reward", "claim", "invoice",
    "paypal", "upi", "otp",
]

# Reuse this existing list; no separate list of fake websites is required.
BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "sbi", "hdfc", "icici", "paytm", "phonepe", "facebook",
    "instagram", "whatsapp", "flipkart", "irctc", "axis",
]

URL_FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "num_dots",
    "num_hyphens", "num_digits", "digit_ratio", "num_subdomains",
    "has_at", "has_ip_host", "uses_https", "has_port",
    "is_shortener", "suspicious_tld", "num_keywords",
    "brand_in_subdomain_or_path", "num_special_chars", "host_entropy",
    "has_punycode", "num_params", "double_slash_in_path",
    "long_host_token",
]


def normalize_url(raw: str) -> str:
    raw = raw.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw

    return raw


def _entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = {}

    for char in value:
        counts[char] = counts.get(char, 0) + 1

    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _split(url: str):
    parsed = urlparse(normalize_url(url))
    host = (parsed.hostname or "").lower().rstrip(".")
    return parsed, host


SECOND_LEVEL = {
    "co", "com", "org", "net", "gov", "edu", "ac", "nic", "res"
}


def _registered_domain(host: str) -> str:
    """Approximate registered domain extraction.

    Examples:
        a.example.com -> example.com
        example.co.in -> example.co.in

    This is a lightweight approximation, not a full public-suffix database.
    """
    parts = host.lower().rstrip(".").split(".")

    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _brand_is_genuine(brand: str, registered_domain: str) -> bool:
    """Allow known exact brand-domain name forms."""
    name = registered_domain.split(".")[0].lower()

    accepted_names = {
        brand,
        brand + "bank",
        brand + "india",
        brand + "-bank",
    }

    return name in accepted_names


def detect_brand_imitation(host: str):
    """Return the likely imitated brand when a domain name looks similar.

    The function compares the registered domain label against BRANDS.
    It does not connect to the domain or verify who owns it.
    """
    host = (host or "").lower().rstrip(".")

    if not host:
        return None

    registered_domain = _registered_domain(host)
    name = registered_domain.split(".")[0].lower()

    # Very short names are too ambiguous for reliable spelling comparison.
    if len(name) < 4:
        return None

    for brand in BRANDS:
        # Do not flag the exact brand name or accepted genuine-name forms.
        if _brand_is_genuine(brand, registered_domain):
            continue

        # Similarity catches substitutions, insertions, and deletions.
        similarity = SequenceMatcher(None, name, brand).ratio()

        if similarity >= 0.75:
            return brand

    return None


def extract_url_features(url: str) -> list:
    """Extract the 22 numeric features expected by the URL model."""
    parsed, host = _split(url)
    full = normalize_url(url).lower()
    path = parsed.path or ""
    query = parsed.query or ""

    labels = host.split(".") if host else []
    tld = labels[-1] if labels else ""
    registered_domain = _registered_domain(host)

    sub_and_path = (
        host[:-len(registered_domain)]
        if host.endswith(registered_domain)
        else host
    ) + path + query

    num_digits = sum(char.isdigit() for char in full)

    has_ip = bool(
        re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host)
    ) or bool(re.fullmatch(r"0x[0-9a-f]+", host))

    keywords = sum(1 for keyword in URL_KEYWORDS if keyword in full)

    # Include spelling-based imitation in the model's existing brand feature.
    brand_hit = (
        any(brand in sub_and_path for brand in BRANDS)
        or detect_brand_imitation(host) is not None
    )

    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 1

    return [
        len(full),
        len(host),
        len(path),
        full.count("."),
        full.count("-"),
        num_digits,
        num_digits / max(len(full), 1),
        max(len(labels) - 2, 0),
        int("@" in full),
        int(has_ip),
        int(parsed.scheme == "https"),
        has_port,
        int(host in SHORTENERS),
        int(tld in SUSPICIOUS_TLDS),
        keywords,
        int(brand_hit),
        sum(full.count(char) for char in "!$%^*()=+{}[]|;:,<>?~_"),
        _entropy(host),
        int("xn--" in host),
        len([part for part in query.split("&") if part]),
        int("//" in path),
        max((len(label) for label in labels), default=0),
    ]


def url_signals(url: str) -> list:
    """Return explainable URL warning signals.

    Each signal has the form: (severity, title, detail).
    """
    parsed, host = _split(url)
    full = normalize_url(url).lower()

    labels = host.split(".") if host else []
    tld = labels[-1] if labels else ""
    registered_domain = _registered_domain(host)

    out = []

    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
        out.append((
            "high",
            "Raw IP address",
            "The link uses a numeric IP address instead of a named website.",
        ))

    if "@" in full:
        out.append((
            "high",
            "Contains an @ symbol",
            "An @ symbol can disguise the destination in a web address.",
        ))

    if "xn--" in host:
        out.append((
            "high",
            "Look-alike characters",
            "The domain uses punycode, which can represent characters "
            "that resemble other characters.",
        ))

    if host in SHORTENERS:
        out.append((
            "medium",
            "Shortened link",
            "The destination is hidden behind a shortened address.",
        ))

    if tld in SUSPICIOUS_TLDS:
        out.append((
            "medium",
            f"Unusual domain ending .{tld}",
            "This domain ending is worth checking carefully; it is not "
            "proof of a scam on its own.",
        ))

    # NEW: catch misspellings such as netlfix.com and paypa1.com.
    brand_match = detect_brand_imitation(host)

    if brand_match:
        out.append((
            "high",
            f"Possible imitation of {brand_match}",
            f"The registered domain '{registered_domain}' resembles "
            f"the brand name '{brand_match}'. Verify the official "
            "domain independently before trusting it.",
        ))
    else:
        # Preserve detection of a brand name embedded in a misleading
        # subdomain, such as paypal.example.com.
        for brand in BRANDS:
            if brand in host and not _brand_is_genuine(
                brand, registered_domain
            ):
                out.append((
                    "high",
                    f"Imitates “{brand}”",
                    f"The brand name appears in the address, but the "
                    f"registered domain is {registered_domain}.",
                ))
                break

    if parsed.scheme != "https":
        out.append((
            "low",
            "No HTTPS",
            "The address does not use HTTPS. This alone does not prove "
            "that a website is malicious.",
        ))

    subdomain_count = len(labels) - len(registered_domain.split("."))

    if subdomain_count >= 3:
        out.append((
            "medium",
            "Many subdomains",
            f"The address has {subdomain_count} subdomain levels.",
        ))

    keywords_found = [
        keyword for keyword in URL_KEYWORDS if keyword in full
    ]

    if len(keywords_found) >= 2:
        out.append((
            "medium",
            "Pressure keywords in address",
            "Found: " + ", ".join(keywords_found[:4]) + ".",
        ))

    name = registered_domain.split(".")[0]

    if len(name) >= 10 and sum(char.isdigit() for char in name) >= 3:
        out.append((
            "medium",
            "Random-looking name",
            f"'{name}' contains several digits and deserves closer review.",
        ))

    if host.count("-") >= 3:
        out.append((
            "low",
            "Many hyphens",
            "The address contains many hyphens, which can occur in "
            "look-alike domains.",
        ))

    if len(full) > 90:
        out.append((
            "low",
            "Very long address",
            f"The address contains {len(full)} characters.",
        ))

    return out


# ----------------------------------------------------------------------
# Message analysis
# ----------------------------------------------------------------------

MESSAGE_PATTERNS = [
    (
        "urgency", "high", "Creates urgency",
        r"\b(urgent(ly)?|immediately|right now|asap|within \d+ ?"
        r"(hours?|hrs?|minutes?|mins?)|last chance|expires? (today|soon|in)|"
        r"act now|final (notice|warning)|hurry|valid \d+ hours)\b",
    ),
    (
        "threat", "high", "Threatens consequences",
        r"\b(account (will be|has been|is) "
        r"(blocked|suspended|closed|locked|deactivated)|"
        r"(will be|has been|is) "
        r"(blocked|suspended|disconnected|deactivated)|legal action|"
        r"arrest|court proceedings|(traffic )?fine of|penalty applies|"
        r"freeze[sd]?|permanent(ly)? (suspension|blocked))\b",
    ),
    (
        "credentials", "high", "Asks for private details",
        r"\b(share|send|provide|give|tell|enter|submit|reply with|"
        r"confirm|verify)\b[^.!?\n]{0,40}?\b(otp|cvv|pin|password|"
        r"passcode|card number|aadhaar|aadhar|pan (card|number)|"
        r"net ?banking|login details|bank details|bank account|ifsc|upi id)\b",
    ),
    (
        "reward", "medium", "Promises money or prizes",
        r"\b(you(’|')?ve won|you have won|has won|have been selected|"
        r"selected to receive|winner|lottery|lucky draw|prize|jackpot|"
        r"cashback|reward|free (gift|iphone|entry|holiday|recharge)|"
        r"win a free|wkly comp|guaranteed|claim (your|now)|"
        r"congratulations winner|gift card)\b",
    ),
    (
        "kyc", "medium", "KYC or verification demand",
        r"\b(kyc|verify your (account|identity|details)|"
        r"update your (details|pan|kyc|account)|re-?activate|"
        r"re-?verification|needs to be verified|confirm your "
        r"(account|identity)|verify now)\b",
    ),
    (
        "payment", "medium", "Asks for a payment or fee",
        r"\b(processing fee|registration fee|redelivery fee|"
        r"pay (a )?small|pay (the )?(pending|bill|fine)|"
        r"pay immediately|send (me )?money|transfer (the )?"
        r"(money|funds)|transfer it back|gift cards?|"
        r"(scan|open) (the )?qr|advance (fee|payment)|send your upi)\b",
    ),
    (
        "impersonation", "medium", "Pretends to be someone you know",
        r"\b(new number|changed my number|(using|borrowed) (a )?"
        r"friend'?s (number|phone)|save this number|this is your "
        r"(boss|manager|ceo)|i am a soldier|i accidentally sent money)\b",
    ),
    (
        "premium", "medium", "Asks you to text a short code",
        r"\b(text|sms|reply with)\s+\w+\s+to\s+\d{4,6}\b",
    ),
    (
        "job", "medium", "Too-good job or investment offer",
        r"\b(work from home|earn (up to )?₹?\s?\d|part[- ]?time job|"
        r"per day|daily income|no experience (needed|required)|"
        r"double your money|guaranteed profit|crypto group)\b",
    ),
    (
        "click", "medium", "Pushes you to click",
        r"\b(click (here|the link|below)|tap (here|the link)|"
        r"follow (this|the) link|open (this|the) link|"
        r"visit (the )?link|log ?in (and|here|at))\b",
    ),
]

_COMPILED = [
    (key, severity, title, re.compile(pattern, re.IGNORECASE))
    for key, severity, title, pattern in MESSAGE_PATTERNS
]

_URL_IN_TEXT = re.compile(
    r"((?:https?://|www\.)[^\s<>\"']+|"
    r"(?<![@\w.-])[a-z0-9-]+(?:\.[a-z0-9-]+)*\."
    r"(?:com|net|org|in|xyz|top|click|link|support|work|tk|ml|gq|cf|"
    r"ga|zip|info|biz|co|me|ly)(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)


def find_urls(text: str) -> list:
    """Find URL-like strings in a message without visiting them."""
    urls = []

    for match in _URL_IN_TEXT.finditer(text):
        url = match.group(0).rstrip(".,;:!?)")

        # Do not treat an ordinary email address as a website.
        if "@" in url and "/" not in url:
            continue

        urls.append(url)

    return urls


_NEG = re.compile(
    r"(do not|don't|never|not|won't)\s+(\w+\s+){0,2}$",
    re.IGNORECASE,
)


def _negated(text: str, start: int) -> bool:
    """Avoid treating some warnings such as 'do not share your OTP' as requests."""
    return bool(_NEG.search(text[max(0, start - 24):start]))


def message_signals(text: str):
    """Return (signals, highlights).

    signals: list of (severity, title, detail)
    highlights: list of (start, end, severity)
    """
    signals = []
    highlights = []
    seen = set()

    for key, severity, title, regex in _COMPILED:
        hits = [
            hit for hit in regex.finditer(text)
            if not _negated(text, hit.start())
        ]

        if not hits:
            continue

        if key not in seen:
            samples = ", ".join(
                dict.fromkeys(hit.group(0).strip() for hit in hits[:3])
            )
            signals.append((
                severity,
                title,
                f"Matched: {samples}.",
            ))
            seen.add(key)

        for hit in hits:
            highlights.append((
                hit.start(),
                hit.end(),
                severity,
            ))

    # Highlight URLs and use the URL rules to determine their highlight level.
    for match in _URL_IN_TEXT.finditer(text):
        raw_url = match.group(0).rstrip(".,;:!?)")

        if "@" in raw_url and "/" not in raw_url:
            continue

        risky_signals = url_signals(raw_url)

        if any(signal[0] == "high" for signal in risky_signals):
            severity = "high"
        elif any(signal[0] == "medium" for signal in risky_signals):
            severity = "medium"
        else:
            severity = "link"

        highlights.append((
            match.start(),
            match.start() + len(raw_url),
            severity,
        ))

    letters = [char for char in text if char.isalpha()]

    if (
        len(letters) > 20
        and sum(char.isupper() for char in letters) / len(letters) > 0.4
    ):
        signals.append((
            "low",
            "Shouting in capitals",
            "Scam messages sometimes use many capital letters to create panic.",
        ))

    if text.count("!") >= 3:
        signals.append((
            "low",
            "Excessive exclamation marks",
            f"{text.count('!')} found.",
        ))

    if re.search(
        r"\b(dear (customer|user|sir|madam|client)|valued customer)\b",
        text,
        re.IGNORECASE,
    ):
        signals.append((
            "low",
            "Generic greeting",
            "A generic greeting can be worth checking alongside other evidence.",
        ))

    # Merge overlapping highlights, keeping the strongest severity.
    rank = {"link": 0, "low": 1, "medium": 2, "high": 3}
    highlights.sort(key=lambda item: (item[0], -item[1]))

    merged = []

    for start, end, severity in highlights:
        if merged and start < merged[-1][1]:
            previous_start, previous_end, previous_severity = merged[-1]

            strongest = (
                previous_severity
                if rank[previous_severity] >= rank[severity]
                else severity
            )

            merged[-1] = (
                previous_start,
                max(previous_end, end),
                strongest,
            )
        else:
            merged.append((start, end, severity))

    return signals, merged