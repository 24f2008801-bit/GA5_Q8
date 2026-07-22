from pathlib import PurePosixPath
from urllib.parse import urlparse, unquote
import posixpath
import ipaddress
import socket

SANDBOX = PurePosixPath("/srv/agent-redteam/sandbox-e65a968c18")

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


# --------------------------------------------------
# PATH NORMALIZATION
# --------------------------------------------------

def normalize_path(path: str) -> PurePosixPath:

    path = path.strip()

    while True:
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded

    path = path.replace("\\", "/")

    while "//" in path:
        path = path.replace("//", "/")

    normalized = posixpath.normpath(path)

    return PurePosixPath(normalized)


# --------------------------------------------------
# FILE POLICY
# --------------------------------------------------

def check_file(path: str):

    try:

        p = normalize_path(path)

        if p == SANDBOX:
            return {
                "action": "allow",
                "reason": "Sandbox access permitted."
            }

        if SANDBOX in p.parents:
            return {
                "action": "allow",
                "reason": "Sandbox access permitted."
            }

        return {
            "action": "block",
            "reason": "Path escapes sandbox."
        }

    except Exception:

        return {
            "action": "block",
            "reason": "Invalid path."
        }


# --------------------------------------------------
# URL POLICY
# --------------------------------------------------

def check_url(url: str):

    try:

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return {
                "action": "block",
                "reason": "Invalid URL scheme."
            }

        if parsed.username or parsed.password:
            return {
                "action": "block",
                "reason": "Userinfo not permitted."
            }

        host = parsed.hostname

        if host is None:
            return {
                "action": "block",
                "reason": "Malformed URL."
            }

        if host not in ALLOWED_HOSTS:
            return {
                "action": "block",
                "reason": "Host not allowed."
            }

        # Resolve DNS

        try:

            infos = socket.getaddrinfo(host, None)

            for info in infos:

                ip = ipaddress.ip_address(info[4][0])

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                ):

                    return {
                        "action": "block",
                        "reason": "Host resolves to private address."
                    }

        except Exception:

            return {
                "action": "block",
                "reason": "DNS lookup failed."
            }

        return {
            "action": "allow",
            "reason": "Host permitted."
        }

    except Exception:

        return {
            "action": "block",
            "reason": "Malformed URL."
        }


# --------------------------------------------------
# DISPATCHER
# --------------------------------------------------

def evaluate_request(req: dict):

    tool = req.get("tool")

    arguments = req.get("arguments", {})

    if tool == "read_file":

        return check_file(arguments.get("path", ""))

    if tool == "fetch_url":

        return check_url(arguments.get("url", ""))

    return {
        "action": "block",
        "reason": "Unknown tool."
    }