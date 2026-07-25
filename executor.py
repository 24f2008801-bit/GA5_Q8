from pathlib import Path
import requests

SANDBOX = Path("/srv/agent-redteam/sandbox-e65a968c18")


def read_file(path: str):
    """
    Read a file.
    Guardrail performs all security checks.
    """

    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    except Exception as e:
        return str(e)


def fetch_url(url: str):
    """
    Fetch URL.

    Redirects are intentionally NOT followed.
    The guardrail decides whether a redirect target is safe.
    """

    try:

        response = requests.get(
            url,
            timeout=8,
            allow_redirects=False
        )

        response.raise_for_status()

        return response.text

    except Exception as e:
        return str(e)