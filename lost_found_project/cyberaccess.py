"""
CyberAccess BOLA Defense Integration for Django
Provides real-time object-level authorization and behavioral risk telemetry.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple
from django.conf import settings
from django.shortcuts import render
from django.http import HttpRequest, HttpResponse
import requests

logger = logging.getLogger("cyberaccess")

# Configuration (from Django settings, env-overridable)
CYBERACCESS_ENABLED = getattr(settings, "CYBERACCESS_ENABLED", True)
CYBERACCESS_API_URL = getattr(settings, "CYBERACCESS_API_URL", "http://127.0.0.1:8000")
CYBERACCESS_API_KEY = getattr(settings, "CYBERACCESS_API_KEY", None)
CYBERACCESS_FAIL_OPEN = getattr(settings, "CYBERACCESS_FAIL_OPEN", True)
CYBERACCESS_TIMEOUT = getattr(settings, "CYBERACCESS_TIMEOUT", 2.0)
CYBERACCESS_CANARIES = getattr(settings, "CYBERACCESS_CANARIES", ["0", "999999", "canary_admin_vault"])

# Validate required configuration
if CYBERACCESS_ENABLED and not CYBERACCESS_API_KEY:
    raise RuntimeError(
        "CYBERACCESS_ENABLED=True but CYBERACCESS_API_KEY is not set. "
        "Set the CYBERACCESS_API_KEY environment variable or disable CYBERACCESS_ENABLED."
    )


class CyberAccessBOLAException(Exception):
    """Raised when CyberAccess blocks an adversary due to high risk or lockout."""
    def __init__(self, payload: dict):
        self.payload = payload
        self.decision = payload.get("decision", "block")
        self.score = payload.get("score", 100.0)
        self.category = payload.get("category", "Attack")
        self.signals = payload.get("signals", [])
        self.explanations = payload.get("explanations", [])
        super().__init__(f"CyberAccess BOLA Block: {self.category} (Score: {self.score})")


class CyberAccessClient:
    """Singleton HTTP client for the CyberAccess Product API (/v1/*)."""
    _instance: Optional["CyberAccessClient"] = None

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "X-API-Key": CYBERACCESS_API_KEY,
            "User-Agent": "CyberAccess-Django-Adapter/1.0",
        })

    @classmethod
    def get_instance(cls) -> "CyberAccessClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def authorize(
        self,
        subject: str,
        resource_id: str,
        authorized: bool,
        endpoint: str = "django_view",
        http_verb: str = "GET",
    ) -> dict:
        """Evaluates object authorization through the CyberAccess Behavioral Engine."""
        if not CYBERACCESS_ENABLED:
            return {
                "decision": "allow" if authorized else "deny",
                "score": 0.0,
                "category": "Normal",
                "signals": [],
                "explanations": [],
            }

        # Check for Canary Honeypots
        is_canary = str(resource_id).strip() in CYBERACCESS_CANARIES
        if is_canary:
            authorized = False

        payload = {
            "subject": str(subject),
            "resource_id": str(resource_id),
            "authorized": bool(authorized),
            "endpoint": str(endpoint),
            "http_verb": str(http_verb).upper(),
        }

        try:
            resp = self.session.post(
                f"{CYBERACCESS_API_URL}/v1/authorize",
                json=payload,
                timeout=CYBERACCESS_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                if is_canary and "canary_honeypot_triggered" not in data.get("signals", []):
                    data["signals"].append("canary_honeypot_triggered")
                    data["decision"] = "block"
                    data["score"] = 100.0
                    data["category"] = "Attack"
                return data
            elif resp.status_code == 401:
                # Invalid API key
                logger.error("CyberAccess API rejected request: 401 Unauthorized. Check CYBERACCESS_API_KEY.")
                if not CYBERACCESS_FAIL_OPEN:
                    return {
                        "decision": "deny",
                        "score": 50.0,
                        "category": "High Risk",
                        "signals": ["auth_failure"],
                        "explanations": ["CyberAccess authentication failed, denied by fail-closed policy."],
                    }
            elif resp.status_code == 403:
                # Direct block from rate limiter or pre-existing ban
                return {
                    "decision": "block",
                    "score": 100.0,
                    "category": "Attack",
                    "signals": ["temporarily_blocked"],
                    "explanations": ["Subject is currently quarantined by CyberAccess 3-Strike Policy."],
                }
            else:
                # Unexpected status code
                logger.warning("CyberAccess API returned %d: %s", resp.status_code, resp.text[:100])
        except requests.Timeout:
            logger.warning("CyberAccess API timeout after %.1fs, fail_open=%s", CYBERACCESS_TIMEOUT, CYBERACCESS_FAIL_OPEN)
        except requests.ConnectionError as e:
            logger.warning("CyberAccess API connection error: %s, fail_open=%s", str(e)[:100], CYBERACCESS_FAIL_OPEN)
        except (requests.RequestException, ValueError) as e:
            logger.warning("CyberAccess API error: %s, fail_open=%s", str(e)[:100], CYBERACCESS_FAIL_OPEN)

        if not CYBERACCESS_FAIL_OPEN and not authorized:
            return {
                "decision": "deny",
                "score": 50.0,
                "category": "High Risk",
                "signals": ["engine_unreachable"],
                "explanations": ["CyberAccess engine unreachable, denied by fail-closed policy."],
            }

        # Fail-Open Fallback
        return {
            "decision": "allow" if authorized else "deny",
            "score": 0.0 if authorized else 40.0,
            "category": "Normal" if authorized else "Suspicious",
            "signals": [],
            "explanations": [],
        }


def get_client_subject(request: HttpRequest) -> str:
    """Extracts a reliable subject identity from the request (username or remote IP).

    Priority:
    1. Authenticated Django user (most reliable)
    2. X-Forwarded-For header (first IP in comma-separated list)
    3. REMOTE_ADDR (direct connection)
    4. Fallback to anonymous_user if all else fails
    """
    # Prefer authenticated user
    if hasattr(request, "user") and request.user.is_authenticated:
        return str(request.user.username)

    # Fallback to client IP (X-Forwarded-For for proxied requests)
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "").strip()
    if x_forwarded_for:
        # Take first IP and validate format (basic check)
        client_ip = x_forwarded_for.split(",")[0].strip()
        if client_ip and len(client_ip) <= 45:  # Max IPv6 length
            return client_ip

    # Direct connection IP
    remote_addr = request.META.get("REMOTE_ADDR", "").strip()
    if remote_addr and len(remote_addr) <= 45:
        return remote_addr

    # Last resort: unknown subject (still identifiable for tracking)
    return "unknown_subject"


def enforce_bola(
    request: HttpRequest,
    resource_id: Any,
    is_authorized: bool,
    resource_name: str = "resource",
    http_verb: Optional[str] = None,
) -> Tuple[bool, Optional[str], dict]:
    """
    Primary BOLA Gatekeeper for Django views.
    Returns: (is_allowed: bool, redirect_action: Optional[str], details: dict)
    """
    subject = get_client_subject(request)
    verb = http_verb or request.method
    client = CyberAccessClient.get_instance()

    result = client.authorize(
        subject=subject,
        resource_id=str(resource_id),
        authorized=is_authorized,
        endpoint=resource_name,
        http_verb=verb,
    )

    decision = result.get("decision", "deny")

    if decision == "block":
        return False, "block", result

    if not is_authorized or decision == "deny":
        return False, "deny", result

    return True, None, result


class CyberAccessSecurityMiddleware:
    """
    Django Middleware to catch CyberAccessBOLAException and render
    a military-grade tactical security lockout response.
    Detects 404 object enumeration attempts on /item(s)/* and /claim(s)/* paths.
    """
    # Pre-compiled regex to avoid injection; strictly matches object ID paths
    _OBJECT_PATH_PATTERN = None

    def __init__(self, get_response):
        self.get_response = get_response
        if CyberAccessSecurityMiddleware._OBJECT_PATH_PATTERN is None:
            import re
            CyberAccessSecurityMiddleware._OBJECT_PATH_PATTERN = re.compile(
                r"/(?:item|items|claim|claims)/([a-zA-Z0-9_\-]+)/?$"
            )

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        if response.status_code == 404 and CYBERACCESS_ENABLED:
            m = self._OBJECT_PATH_PATTERN.search(request.path)
            if m:
                obj_id = m.group(1)
                resource_type = "item" if "item" in request.path else "claim"
                allowed, action, details = enforce_bola(
                    request=request,
                    resource_id=f"{resource_type}_{obj_id}",
                    is_authorized=False,
                    resource_name="404_object_fuzz",
                    http_verb=request.method,
                )
                if action == "block":
                    context = {
                        "subject": get_client_subject(request),
                        "decision": "block",
                        "score": details.get("score", 100.0),
                        "category": details.get("category", "Attack"),
                        "signals": details.get("signals", ["rapid_enumeration"]),
                        "explanations": details.get("explanations", ["Subject blocked after automated path enumeration."]),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                    }
                    return render(request, "cyberaccess_blocked.html", context, status=403)
        return response

    def process_exception(self, request: HttpRequest, exception: Exception):
        if isinstance(exception, CyberAccessBOLAException):
            context = {
                "subject": get_client_subject(request),
                "decision": exception.decision,
                "score": exception.score,
                "category": exception.category,
                "signals": exception.signals,
                "explanations": exception.explanations,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
            return render(request, "cyberaccess_blocked.html", context, status=403)
        return None
