
"""
Browser Shield - Module 4
Drive-by Download Risk Detection

Analyzes supplied download metadata. It does not download, open,
execute, or scan files, and does not monitor the browser by itself.
"""

import mimetypes
import re
from urllib.parse import urlsplit, unquote
from pathlib import PurePosixPath, PureWindowsPath


MODULE_NAME = "Drive-by Download Risk Detection"

# Extensions that deserve extra scrutiny.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".msi", ".com", ".dll",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".jar", ".reg", ".lnk",
}

# Some archive formats may contain executable files.
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".iso", ".img",
}

SUSPICIOUS_URL_TERMS = {
    "dropper": 15,
    "payload": 15,
    "malware": 15,
    "exploit": 10,
    "download": 5,
}


def _valid_http_url(url):
    """Return parsed URL parts, or None for invalid/non-HTTP input."""
    if not isinstance(url, str) or not url.strip():
        return None

    try:
        parts = urlsplit(url.strip())

        if parts.scheme.lower() not in ("http", "https"):
            return None

        if not parts.hostname:
            return None

        # Validate port syntax.
        _ = parts.port
        return parts

    except (ValueError, TypeError):
        return None


def _get_filename(filename, content_disposition):
    """Use an explicitly supplied filename, or parse a simple header."""
    if isinstance(filename, str) and filename.strip():
        return filename.strip().strip("\"'")

    if not isinstance(content_disposition, str):
        return ""

    # Handles common filename= and filename*= header values.
    match = re.search(
        r"""filename\*?\s*=\s*(?:UTF-8''|")?([^";]+)""",
        content_disposition,
        re.IGNORECASE,
    )

    if match:
        return unquote(match.group(1).strip().strip("\"'"))

    return ""


def _get_extension(filename):
    """Extract an extension safely from a supplied filename."""
    if not filename:
        return ""

    # Handle both Windows and POSIX-style paths.
    basename = PureWindowsPath(filename).name
    basename = PurePosixPath(basename).name

    if "." not in basename or basename.startswith(".") and basename.count(".") == 1:
        return ""

    return PurePosixPath(basename).suffix.lower()


def _result(url, score=0, indicators=None, explanation=None,
            recommendations=None, invalid=False, filename=""):
    score = max(0, min(int(score), 100))

    if invalid:
        status = "Invalid Input"
        threat = "Unknown"
    elif score == 0:
        status = "No Download Red Flags Found"
        threat = "No configured indicators detected"
    elif score < 30:
        status = "Needs Review"
        threat = "Potential download risk"
    elif score < 60:
        status = "Suspicious"
        threat = "Potential download risk"
    else:
        status = "High Risk"
        threat = "Multiple download risk indicators"

    return {
        "module": MODULE_NAME,
        "threat": threat,
        "risk_score": score,
        "status": status,
        "indicators": indicators or [],
        "explanation": explanation or [],
        "recommendations": recommendations or [],
        "url": url if isinstance(url, str) else "",
        "filename": filename or "",
    }


def analyze_download_risk(
    url,
    filename="",
    content_type="",
    content_disposition="",
    file_size=None,
    user_initiated=True,
):
    """
    Analyze supplied URL/download metadata.

    Parameters:
        url: Source URL supplied by a future extension or test.
        filename: Suggested or observed download filename.
        content_type: Observed response MIME type, if available.
        content_disposition: Response header, if available.
        file_size: Observed size in bytes, if available.
        user_initiated: Whether the user intentionally initiated it.

    This function does not fetch the URL or inspect file contents.
    """

    parts = _valid_http_url(url)

    if parts is None:
        return _result(
            url=url,
            invalid=True,
            explanation=["A valid absolute HTTP/HTTPS URL is required."],
            recommendations=["Provide a complete HTTP/HTTPS URL."],
        )

    score = 0
    indicators = []
    explanation = []
    recommendations = []

    def add_indicator(label, points, detail):
        nonlocal score
        if label not in indicators:
            indicators.append(label)
            explanation.append(f"{detail} (+{points})")
            score += points

    decoded_url = unquote(url).lower()
    resolved_filename = _get_filename(filename, content_disposition)
    extension = _get_extension(resolved_filename)

    # 1. URL indicators
    if parts.scheme.lower() == "http":
        add_indicator(
            "Unencrypted HTTP source",
            5,
            "Download source uses HTTP instead of HTTPS",
        )

    for term, points in SUSPICIOUS_URL_TERMS.items():
        if re.search(
            rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
            decoded_url,
        ):
            add_indicator(
                f"Suspicious URL term: {term}",
                points,
                f"URL contains the term '{term}'",
            )

    # 2. Filename / extension indicators
    if extension in EXECUTABLE_EXTENSIONS:
        add_indicator(
            f"Executable or script extension: {extension}",
            30,
            f"Filename has the potentially risky extension {extension}",
        )

    elif extension in ARCHIVE_EXTENSIONS:
        add_indicator(
            f"Archive extension: {extension}",
            5,
            f"Filename has archive extension {extension}; contents are unknown",
        )

    # 3. MIME type consistency
    mime = content_type.split(";", 1)[0].strip().lower()

    if mime in {
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-executable",
        "application/x-sh",
        "application/x-bat",
    }:
        add_indicator(
            "Executable-like MIME type",
            20,
            f"Observed MIME type is {mime}",
        )

    guessed_type, _ = mimetypes.guess_type(resolved_filename)

    if extension in EXECUTABLE_EXTENSIONS and mime.startswith("text/html"):
        add_indicator(
            "Executable-looking filename with HTML MIME type",
            10,
            "Filename extension and observed MIME type do not align",
        )

    elif (
        guessed_type
        and mime
        and guessed_type != mime
        and extension in EXECUTABLE_EXTENSIONS
    ):
        add_indicator(
            "Filename and MIME type mismatch",
            5,
            "Filename extension and observed MIME type differ",
        )

    # 4. Unexpected / non-user-initiated download signal
    if user_initiated is False:
        add_indicator(
            "Download not marked as user-initiated",
            15,
            "Metadata indicates the download was not user-initiated",
        )

    # 5. File size is context only; size alone is not malicious.
    if file_size is not None:
        try:
            if int(file_size) < 0:
                return _result(
                    url=url,
                    invalid=True,
                    filename=resolved_filename,
                    explanation=["File size cannot be negative."],
                    recommendations=["Provide a non-negative size in bytes."],
                )
        except (TypeError, ValueError):
            return _result(
                url=url,
                invalid=True,
                filename=resolved_filename,
                explanation=["File size must be a non-negative integer."],
                recommendations=["Provide a valid file size in bytes."],
            )

    score = min(score, 100)

    if score >= 60:
        recommendations.extend([
            "Do not open or execute the file until its source is verified.",
            "Check the URL and file with a reputable security scanner.",
            "If the download was unexpected, cancel or remove it safely.",
        ])
    elif score >= 30:
        recommendations.extend([
            "Verify that you expected this file and trust its source.",
            "Do not run executable or script files from unknown sources.",
        ])
    elif score > 0:
        recommendations.append(
            "Review the indicators; they are not proof that the file is malicious."
        )
    else:
        recommendations.append(
            "No configured indicators were found; this does not guarantee safety."
        )

    if not resolved_filename:
        explanation.append(
            "No filename was supplied; filename-based checks were skipped."
        )

    return _result(
        url=url,
        score=score,
        indicators=indicators,
        explanation=explanation,
        recommendations=recommendations,
        filename=resolved_filename,
    )


# Compatibility alias for integration code.
def detect_drive_by_download(url, **metadata):
    return analyze_download_risk(url, **metadata)


if __name__ == "__main__":
    sample = analyze_download_risk(
        url="https://example.com/files/installer.exe",
        filename="installer.exe",
        content_type="application/octet-stream",
        file_size=2048,
        user_initiated=False,
    )

    print("\n=== Browser Shield: Module 4 ===")
    for key, value in sample.items():
        print(f"{key}: {value}")
