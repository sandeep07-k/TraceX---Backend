import re


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list[str]:
    """
    Extract unique HTTP/HTTPS URLs from text.
    """

    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    # Preserve order and remove duplicates
    return list(dict.fromkeys(urls))