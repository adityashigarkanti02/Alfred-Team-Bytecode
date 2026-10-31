#!/usr/bin/env python3
"""
ALFRED Web Fetcher & Live Curl Engine.

Provides real HTTP/HTTPS webpage retrieval with rigorous SSRF protection:
- Blocks loopback (127.0.0.0/8, ::1)
- Blocks private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Blocks cloud metadata endpoints (169.254.169.254)
- Enforces timeout, max download size limits, and safe redirect validation
- Strips hidden scripts/styles and extracts title and clean visible text
"""
from __future__ import annotations

import html
import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


class SSRFSecurityError(Exception):
    """Raised when a request attempts to target an internal or forbidden IP/host."""
    pass


class FetchError(Exception):
    """Raised when network fetch fails."""
    pass


FORBIDDEN_HOSTS = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; ALFRED-SecurityAgent/1.0; +https://github.com/adityashigarkanti02/Alfred-Team-Bytecode)"


def is_forbidden_ip(ip_str: str) -> bool:
    """Check if an IP is private, loopback, link-local, multicast, or cloud metadata."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or str(ip) == "169.254.169.254"
        )
    except ValueError:
        return True


def validate_url_safe(url: str) -> Tuple[urllib.parse.ParseResult, str]:
    """
    Validates that a URL is well-formed http/https and does not resolve to an internal/private IP.

    Returns:
        (parsed_url, resolved_ip)
    Raises:
        SSRFSecurityError: if URL points to forbidden destination.
    """
    try:
        parsed = urllib.parse.urlparse(str(url or "").strip())
    except Exception as exc:
        raise SSRFSecurityError(f"Malformed URL: {exc}")

    if parsed.scheme not in ("http", "https"):
        raise SSRFSecurityError(f"Scheme '{parsed.scheme}' is not allowed. Only HTTP and HTTPS are permitted.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise SSRFSecurityError("URL is missing a valid hostname.")

    if hostname in FORBIDDEN_HOSTS or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise SSRFSecurityError(f"Target host '{hostname}' is in the forbidden host list.")

    # Check if hostname itself is an IP literal
    try:
        ip = ipaddress.ip_address(hostname)
        if is_forbidden_ip(str(ip)):
            raise SSRFSecurityError(f"IP address '{hostname}' is a private/internal network destination.")
        return parsed, str(ip)
    except ValueError:
        pass

    # Resolve DNS to verify IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"Could not resolve host '{hostname}': {exc}")

    if not addr_info:
        raise FetchError(f"No IP addresses found for host '{hostname}'.")

    # Check all resolved IPs
    resolved_ips = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_addr = sockaddr[0]
        resolved_ips.append(ip_addr)
        if is_forbidden_ip(ip_addr):
            raise SSRFSecurityError(f"SSRF blocked: Host '{hostname}' resolves to private/internal IP '{ip_addr}'.")

    return parsed, resolved_ips[0]


def extract_title_and_text(html_content: str) -> Tuple[str, str]:
    """Extract clean title and visible text from HTML string."""
    text = str(html_content or "")

    # Extract title
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = html.unescape(title_match.group(1)).strip() if title_match else ""

    # Strip style, script, noscript, svg tags
    clean = re.sub(r"<(script|style|noscript|svg|canvas)[^>]*>.*?</\1>", " ", text, flags=re.IGNORECASE | re.DOTALL)

    # Convert common block tags to newlines
    clean = re.sub(r"<(?:p|div|h[1-6]|li|br|hr|tr)[^>]*>", "\n", clean, flags=re.IGNORECASE)

    # Strip remaining HTML tags
    clean = re.sub(r"<[^>]+>", " ", clean)

    # Unescape HTML entities
    clean = html.unescape(clean)

    # Normalize whitespace
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in clean.splitlines()]
    visible = "\n".join(line for line in lines if line)

    return title, visible


def fetch_webpage(
    url: str,
    timeout: int = 10,
    max_bytes: int = 524288,
    headers: Optional[Dict[str, str]] = None,
    max_redirects: int = 3,
) -> Dict[str, Any]:
    """
    Fetch a real webpage over HTTP/HTTPS with SSRF prevention and content parsing.
    """
    current_url = url
    visited_urls = set()

    req_headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        req_headers.update(headers)

    for _ in range(max_redirects + 1):
        if current_url in visited_urls:
            raise FetchError("Redirect loop detected.")
        visited_urls.add(current_url)

        # Validate URL and SSRF before each jump
        parsed, resolved_ip = validate_url_safe(current_url)

        req = urllib.request.Request(current_url, headers=req_headers)

        try:
            # Custom opener without automatic redirect following so each redirect hop is re-validated
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(NoRedirectHandler)
            with opener.open(req, timeout=timeout) as resp:
                status_code = getattr(resp, "status", resp.getcode())
                content_type = resp.headers.get("Content-Type", "")
                raw_bytes = resp.read(max_bytes + 1024)
                break
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location")
                if not location:
                    raise FetchError(f"HTTP {exc.code} redirect missing Location header.")
                current_url = urllib.parse.urljoin(current_url, location)
                continue
            status_code = exc.code
            content_type = exc.headers.get("Content-Type", "")
            raw_bytes = exc.read(max_bytes)
            break
        except urllib.error.URLError as exc:
            raise FetchError(f"Network error accessing '{current_url}': {exc.reason}")
        except socket.timeout:
            raise FetchError(f"Request to '{current_url}' timed out after {timeout} seconds.")
    else:
        raise FetchError(f"Exceeded maximum redirects ({max_redirects}).")

    # Decode payload
    try:
        charset_match = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
        encoding = charset_match.group(1) if charset_match else "utf-8"
        raw_text = raw_bytes.decode(encoding, errors="replace")
    except Exception:
        raw_text = raw_bytes.decode("utf-8", errors="replace")

    title, visible_text = extract_title_and_text(raw_text)

    return {
        "url": url,
        "final_url": current_url,
        "status_code": status_code,
        "content_type": content_type,
        "title": title or current_url,
        "visible_text": visible_text[:12000],
        "raw_html": raw_text[:30000],
        "size": len(raw_bytes),
        "resolved_ip": resolved_ip,
    }


def curl_page(url: str, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Execute live curl-like fetch with SSRF validation."""
    return fetch_webpage(url, headers=custom_headers)
