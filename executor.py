from pathlib import Path
import requests

# Sandbox root used by the assignment
SANDBOX = Path("/srv/agent-redteam/sandbox-e65a968c18")

#add

def read_file(path: str):
    """
    Read a file and return its contents.
    The guardrail is responsible for ensuring the path is safe.
    """

    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    except Exception as e:
        return str(e)


def fetch_url(url: str):
    """
    Fetch a URL and return its response body.
    The guardrail is responsible for validating the URL.
    """

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True
        )

        response.raise_for_status()

        return response.text

    except Exception as e:
        return str(e)