"""
URL Safety & Blocking Mechanism for Lost & Found Django Website
Validates user-provided URLs and logs blocked attempts for security review.
Prevents malicious, phishing, and unsafe URL patterns.
"""

import logging
import re
import time
import uuid
from typing import Tuple, Dict, Optional
from urllib.parse import urlparse, parse_qs
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

logger = logging.getLogger("url_safety")

# Configuration (from Django settings, env-overridable)
URL_SAFETY_ENABLED = getattr(settings, "URL_SAFETY_ENABLED", True)

# Malicious domain patterns and suspicious TLDs
BLOCKED_DOMAINS = [
    "bit.ly", "tinyurl.com", "short.link", "goo.gl",  # URL shorteners
    "pastebin.com", "pastie.org", "hastebin.com",  # Paste sites often for payloads
    "iplogger.com", "grabify.link", "discord.gg",  # IP logging / tracking services
    "onion", "i2p",  # Dark web indicators
]

# Dangerous file extensions that could be executed or cause harm
BLOCKED_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".com", ".pif", ".scr",  # Windows executables
    ".msi", ".ps1", ".vbs", ".js", ".jar", ".app",  # Installation / script files
    ".dmg", ".pkg", ".run",  # macOS / Linux installers
    ".zip", ".rar", ".7z", ".tar", ".gz",  # Archives (could contain malware)
]

# Dangerous URL patterns that indicate phishing, injection, or malicious intent
DANGEROUS_PATTERNS = [
    r"javascript:",  # JS injection
    r"data:text/html",  # Data URI injection
    r"<script",  # HTML injection
    r"eval\(",  # Code execution
    r"__proto__",  # Prototype pollution
    r"constructor\[",  # Property access attacks
    r"\.\.\/",  # Path traversal
    r"%2e%2e%2f",  # URL-encoded path traversal
    r"cmd\.exe",  # Windows command execution
    r"/etc/passwd",  # Unix password file access
    r"union\s+select",  # SQL injection patterns
    r"or\s+1\s*=\s*1",  # SQL injection logic
]

# Suspicious keywords that might indicate phishing or spam
SUSPICIOUS_KEYWORDS = [
    "verify account", "confirm identity", "update payment", "reset password",
    "urgent action required", "limited time", "act now", "click here immediately",
    "phishing", "malware", "ransomware", "bitcoin", "crypto", "free money",
]

# Legitimate internal URL patterns that are always safe
ALLOWED_INTERNAL_PATTERNS = [
    r"^/",  # Internal paths
    r"^localhost",
    r"^127\.0\.0\.1",
    r"^192\.168\.",
    r"^10\.",  # Private IP ranges
    r"^172\.(1[6-9]|2[0-9]|3[01])\.",
]


class URLBlockedException(Exception):
    """Raised when a URL fails safety validation."""
    def __init__(self, url: str, reason: str, severity: str = "medium"):
        self.url = url
        self.reason = reason
        self.severity = severity  # "low", "medium", "high", "critical"
        super().__init__(f"URL Blocked: {reason}")


def is_internal_url(url: str) -> bool:
    """Check if URL is an internal application URL (safe)."""
    if not url:
        return False

    if url.startswith("/"):
        return True

    # Remove protocol if present
    test_url = re.sub(r"^https?://", "", url.strip(), flags=re.IGNORECASE)

    for pattern in ALLOWED_INTERNAL_PATTERNS:
        if re.match(pattern, test_url, re.IGNORECASE):
            return True

    return False


def check_url_safety(
    url: str,
    context: Optional[str] = None,
    request: Optional[HttpRequest] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validates a URL for safety against malicious patterns.

    Args:
        url: The URL string to validate
        context: Where the URL came from (e.g., 'item_description', 'claim_proof', 'contact_info')
        request: Django HttpRequest for audit logging (optional)

    Returns:
        Tuple of (is_safe: bool, reason: Optional[str])
        If safe: (True, None)
        If blocked: (False, reason_string)

    Raises:
        URLBlockedException: When URL fails critical safety checks
    """
    if not URL_SAFETY_ENABLED:
        return True, None

    if not url or not isinstance(url, str):
        return True, None

    url = url.strip()
    if len(url) == 0:
        return True, None

    # Internal URLs are always safe
    if is_internal_url(url):
        return True, None

    # Check for dangerous patterns (highest priority)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            reason = f"Dangerous URL pattern detected: {pattern}"
            log_blocked_url(url, reason, "critical", context, request)
            raise URLBlockedException(url, reason, "critical")

    # Parse URL safely
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        # Check for blocked domains
        for blocked_domain in BLOCKED_DOMAINS:
            if blocked_domain in domain or domain.endswith(blocked_domain):
                reason = f"Blocked domain detected: {domain}"
                log_blocked_url(url, reason, "high", context, request)
                raise URLBlockedException(url, reason, "high")

        # Check for suspicious file extensions
        for ext in BLOCKED_EXTENSIONS:
            if path.endswith(ext):
                reason = f"Blocked file extension detected: {ext}"
                log_blocked_url(url, reason, "high", context, request)
                raise URLBlockedException(url, reason, "high")

        # Check for suspicious keywords in URL
        url_lower = url.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                reason = f"Suspicious keyword detected in URL: {keyword}"
                log_blocked_url(url, reason, "medium", context, request)
                # For medium severity, just flag it but don't block
                return False, reason

    except Exception as e:
        if isinstance(e, URLBlockedException):
            raise
        logger.warning(f"Error parsing URL for safety check: {url}, Error: {e}")
        # On parsing errors, assume it's safe (fail-open)
        return True, None

    return True, None


def check_content_for_urls(
    content: str,
    context: Optional[str] = None,
    request: Optional[HttpRequest] = None,
) -> Tuple[bool, list]:
    """
    Scans text content for URLs and validates each one.

    Args:
        content: Text content that might contain URLs
        context: Where the content came from
        request: Django HttpRequest for audit logging

    Returns:
        Tuple of (all_safe: bool, blocked_urls: list of dicts with url and reason)
    """
    if not URL_SAFETY_ENABLED or not content:
        return True, []

    # Simple URL extraction regex
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, content, re.IGNORECASE)

    blocked_urls = []

    for url in set(urls):  # Use set to avoid duplicate checks
        try:
            is_safe, reason = check_url_safety(url, context, request)
            if not is_safe and reason:
                blocked_urls.append({
                    "url": url,
                    "reason": reason,
                    "context": context,
                })
        except URLBlockedException as e:
            blocked_urls.append({
                "url": e.url,
                "reason": e.reason,
                "context": context,
                "severity": e.severity,
            })

    return len(blocked_urls) == 0, blocked_urls


def log_blocked_url(
    url: str,
    reason: str,
    severity: str = "medium",
    context: Optional[str] = None,
    request: Optional[HttpRequest] = None,
) -> None:
    """
    Logs a blocked URL attempt for security audit and monitoring.

    Args:
        url: The blocked URL
        reason: Why it was blocked
        severity: Severity level of the block
        context: Where the URL came from (e.g., 'item_description')
        request: Django HttpRequest for additional context
    """
    try:
        from audit.models import AuditLog

        subject = "anonymous"
        client_ip = "0.0.0.0"

        if request:
            # Get client IP
            x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "").strip()
            if x_forwarded_for:
                client_ip = x_forwarded_for.split(",")[0].strip()
            else:
                client_ip = request.META.get("REMOTE_ADDR", "0.0.0.0")

            # Get authenticated user if available
            if hasattr(request, "user") and request.user.is_authenticated:
                subject = str(request.user.username)
            else:
                subject = client_ip

        # Create audit log entry
        AuditLog.objects.create(
            subject=subject,
            action="url_blocked",
            resource_type="url",
            resource_id=url[:255],  # Truncate for database field
            details={
                "url": url,
                "reason": reason,
                "severity": severity,
                "context": context,
                "client_ip": client_ip,
            },
            severity=severity,
            source="url_safety",
        )

        logger.warning(
            f"URL Blocked [severity={severity}]: {reason} | URL: {url} | Context: {context} | Subject: {subject}"
        )

    except Exception as e:
        # Fallback to basic logging if audit system unavailable
        logger.warning(
            f"URL Blocked [severity={severity}]: {reason} | URL: {url} | Context: {context} | Error: {e}"
        )


def sanitize_url_display(url: str, max_length: int = 100) -> str:
    """
    Sanitizes a URL for safe display to prevent further injection.

    Args:
        url: The URL to sanitize
        max_length: Maximum display length

    Returns:
        Safe string representation of the URL
    """
    if not url:
        return ""

    # Remove any HTML-like characters
    safe_url = url.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

    if len(safe_url) > max_length:
        safe_url = safe_url[:max_length] + "..."

    return safe_url


def render_blocked_link(
    request: HttpRequest,
    url: str,
    reason: str,
    severity: str = "medium",
    context: Optional[str] = None,
    status: int = 403,
) -> HttpResponse:
    """
    Renders the professional blocked link page when a dangerous URL is detected.

    Args:
        request: Django HttpRequest
        url: The blocked URL
        reason: Why the URL was blocked
        severity: Severity level ('low', 'medium', 'high', 'critical')
        context: Where the URL came from
        status: HTTP status code (default 403)

    Returns:
        HttpResponse with blocked link page
    """
    # Generate unique incident ID for tracking
    incident_id = f"URL_BLOCK_{int(time.time())}_{uuid.uuid4().hex[:8].upper()}"

    # Sanitize URL for display
    sanitized_url = sanitize_url_display(url)

    # Map severity to category
    severity_map = {
        "critical": "Critical Threat",
        "high": "High Risk",
        "medium": "Suspicious Content",
        "low": "Low Risk",
    }
    category = severity_map.get(severity, "Suspicious Content")

    # Build explanations based on reason
    explanations = []
    if "javascript" in reason.lower():
        explanations = [
            "This URL contains code injection that could execute malicious scripts.",
            "Script injection attempts are strictly blocked to protect user safety.",
            "Do not attempt to bypass this protection.",
        ]
    elif "malware" in reason.lower() or "phishing" in reason.lower():
        explanations = [
            "This URL has been identified as a known source of malware or phishing attacks.",
            "Our security team maintains an updated list of dangerous domains.",
            "Contact support if you believe this is a false positive.",
        ]
    elif "shortener" in reason.lower():
        explanations = [
            "URL shorteners can be used to hide malicious links.",
            "We require direct, transparent URLs for user safety.",
            "Contact the item owner directly for the actual link if needed.",
        ]
    else:
        explanations = [
            "This URL does not meet our security standards and has been blocked.",
            "The blocking action has been logged for security review.",
            "If you believe this is a mistake, please contact our support team.",
        ]

    context_obj = {
        "sanitized_url": sanitized_url,
        "reason": reason,
        "severity": severity,
        "category": category,
        "incident_id": incident_id,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "explanations": explanations,
        "signals": [
            "malicious_url" if severity in ["high", "critical"] else "suspicious_content",
            f"url_blocked_{severity}",
            context or "unknown_context",
        ],
        "return_url": request.META.get("HTTP_REFERER", "/"),
    }

    response = render(request, "blocked_link.html", context_obj, status=status)
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return response
