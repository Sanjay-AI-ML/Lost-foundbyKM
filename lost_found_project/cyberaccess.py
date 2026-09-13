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
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
import requests

logger = logging.getLogger("cyberaccess")

# Configuration (from Django settings, env-overridable)
CYBERACCESS_ENABLED = getattr(settings, "CYBERACCESS_ENABLED", True)
CYBERACCESS_API_URL = getattr(settings, "CYBERACCESS_API_URL", "http://127.0.0.1:8000")
CYBERACCESS_API_KEY = getattr(settings, "CYBERACCESS_API_KEY", None) or "dev_test_key"
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

    def get_lockout_status(self, subject: str) -> dict:
        """Queries the CyberAccess Behavioral Engine to check if this subject is quarantined."""
        if not CYBERACCESS_ENABLED:
            return {"is_locked": False, "lockout_remaining_seconds": 0, "strike_count": 0}
        try:
            resp = self.session.get(
                f"{CYBERACCESS_API_URL}/lockout-status/{subject}",
                timeout=CYBERACCESS_TIMEOUT,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug("Error checking lockout status for %s: %s", subject, e)
        return {"is_locked": False, "lockout_remaining_seconds": 0, "strike_count": 0}

    def log_timer_event(self, subject: str, remaining_seconds: int, expires_at: Optional[int] = None, strike_count: int = 1, reason: str = "Quarantine cooldown active"):
        """Logs quarantine timer countdown progress into the SOC audit timeline."""
        if not CYBERACCESS_ENABLED:
            return
        try:
            self.session.post(
                f"{CYBERACCESS_API_URL}/v1/audit/timer-log",
                json={
                    "subject": subject,
                    "remaining_seconds": int(remaining_seconds),
                    "expires_at": expires_at,
                    "strike_count": int(strike_count),
                    "reason": reason,
                },
                timeout=1.0,
            )
        except Exception as e:
            logger.debug("Error logging timer audit for %s: %s", subject, e)


# Global in-memory quarantine cache to guarantee timer monotonicity across page refreshes
_ACTIVE_QUARANTINES: dict[str, dict] = {}


def get_or_register_quarantine(subject: str, remaining_seconds: int = 120, expires_at: Optional[int] = None, strike_count: int = 1) -> dict:
    """Retrieves or registers an absolute quarantine expiration to prevent timer resets on refresh."""
    now = time.time()
    existing = _ACTIVE_QUARANTINES.get(subject)
    if existing and existing["expires_at"] > now:
        rem = max(0, int(existing["expires_at"] - now))
        existing["remaining_seconds"] = rem
        return existing

    if expires_at and expires_at > now:
        target_exp = int(expires_at)
        rem = max(0, int(target_exp - now))
    else:
        rem = max(1, remaining_seconds)
        target_exp = int(now + rem)

    entry = {
        "subject": subject,
        "expires_at": target_exp,
        "remaining_seconds": rem,
        "strike_count": strike_count,
        "started_at": int(now),
    }
    _ACTIVE_QUARANTINES[subject] = entry
    return entry


def get_client_ip(request: HttpRequest) -> str:
    """Extracts only the client IP address (no usernames).
    Used for anonymous/scanner-based access attempts (e.g., 404 probes).
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "").strip()
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(",")[0].strip()
        if client_ip and len(client_ip) <= 45:  # Max IPv6 length
            return client_ip

    remote_addr = request.META.get("REMOTE_ADDR", "").strip()
    if remote_addr and len(remote_addr) <= 45:
        return remote_addr

    return "0.0.0.0"


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
    return get_client_ip(request)


def enforce_bola(
    request: HttpRequest,
    resource_id: Any,
    is_authorized: bool,
    resource_name: str = "resource",
    http_verb: Optional[str] = None,
    subject: Optional[str] = None,
) -> Tuple[bool, Optional[str], dict]:
    """
    Primary BOLA Gatekeeper for Django views.
    Returns: (is_allowed: bool, redirect_action: Optional[str], details: dict)
    """
    if subject is None:
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


def render_cyberaccess_blocked(request: HttpRequest, context: dict, status: int = 403) -> HttpResponse:
    """Renders the full-screen integrity warning takeover with strict no-cache headers."""
    response = render(request, "cyberaccess_blocked.html", context, status=status)
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    response["Clear-Site-Data"] = '"cache", "storage"'
    return response


class CyberAccessSecurityMiddleware:
    """
    Django Middleware to catch CyberAccessBOLAException and render
    a military-grade tactical security lockout response.
    Detects 404 object enumeration attempts on /item(s)/* and /claim(s)/* paths.
    """
    # Pre-compiled regex to avoid injection; matches object ID paths for item, claim, and record
    _OBJECT_PATH_PATTERN = None

    def __init__(self, get_response):
        self.get_response = get_response
        if CyberAccessSecurityMiddleware._OBJECT_PATH_PATTERN is None:
            import re
            CyberAccessSecurityMiddleware._OBJECT_PATH_PATTERN = re.compile(
                r"/(?:item|items|claim|claims|record|records)/([a-zA-Z0-9_\-]+)/?$"
            )

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if CYBERACCESS_ENABLED and request.method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            path = request.path

            # Hackathon bypass release: allows demo presenter to bypass cooldown immediately
            if path == '/cyberaccess/bypass/' or request.GET.get('hackathon_bypass') == '1':
                client_ip = get_client_ip(request)
                subject = get_client_subject(request)
                _ACTIVE_QUARANTINES.pop(subject, None)
                _ACTIVE_QUARANTINES.pop(client_ip, None)
                client = CyberAccessClient.get_instance()
                try:
                    client.session.post(
                        f"{CYBERACCESS_API_URL}/hackathon/release",
                        json={"subject": subject, "client_ip": client_ip},
                        timeout=1.5,
                    )
                except Exception as e:
                    logger.debug("Failed calling backend hackathon release: %s", e)
                return HttpResponseRedirect('/?hackathon_cleared=1')

            # Skip static files and admin
            static_exts = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.map', '.mp4')
            is_static = any(path.endswith(ext) for ext in static_exts) or path.startswith('/static/') or path.startswith('/media/')
            is_admin = path.startswith('/admin/') or path.startswith('/admin')

            if not is_static:
                client_ip = get_client_ip(request)
                subject = get_client_subject(request)

                # 1. FULL-SITE INTEGRITY TAKEOVER (Avast/Kaspersky/Bitdefender style):
                # If subject or client IP is under active quarantine cooldown, take over the entire website!
                # Quarantined attackers cannot navigate to home, login, admin, or any other endpoint.
                client = CyberAccessClient.get_instance()
                now_ts = time.time()
                local_q = _ACTIVE_QUARANTINES.get(subject) or _ACTIVE_QUARANTINES.get(client_ip)

                if local_q and local_q["expires_at"] > now_ts:
                    is_locked = True
                    expires_at = local_q["expires_at"]
                    rem_sec = max(0, int(expires_at - now_ts))
                    strike_count = local_q.get("strike_count", 1)
                else:
                    lockout = client.get_lockout_status(subject)
                    if not lockout.get("is_locked") and client_ip != subject:
                        lockout = client.get_lockout_status(client_ip)

                    if lockout.get("is_locked"):
                        is_locked = True
                        expires_at = int(lockout.get("lockout_expires_at") or (now_ts + int(lockout.get("lockout_remaining_seconds", 120))))
                        rem_sec = max(0, int(expires_at - now_ts))
                        strike_count = lockout.get("strike_count", 1)
                        get_or_register_quarantine(subject, rem_sec, expires_at, strike_count)
                    else:
                        is_locked = False
                        expires_at = None
                        rem_sec = 0
                        strike_count = 0

                if is_locked and rem_sec > 0:
                    # Save timer event to audit timeline so refresh and navigation are logged
                    client.log_timer_event(
                        subject=subject,
                        remaining_seconds=rem_sec,
                        expires_at=expires_at,
                        strike_count=strike_count,
                        reason="Page navigation or refresh quarantined by perimeter defense"
                    )
                    context = {
                        "subject": subject,
                        "decision": "block",
                        "score": 100.0,
                        "category": "Attack",
                        "signals": ["temporarily_blocked", f"strike_{strike_count}_soft_lockout_2m" if rem_sec <= 120 else f"strike_{strike_count}_hard_lockout_30m"],
                        "explanations": [
                            "Your identity has been quarantined due to malicious object enumeration or security violations.",
                            f"Strike {strike_count}/3: Active quarantine cooldown penalty enforced across all application endpoints.",
                            "Full-system integrity lockdown active. Direct navigation is disabled across all application endpoints."
                        ],
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                        "contact_email": "security@company.com",
                        "lockout_remaining_seconds": rem_sec,
                        "lockout_expires_at": expires_at,
                        "strike_count": strike_count,
                        "lockout_type": f"strike_{strike_count}_soft_lockout_2m" if rem_sec <= 120 else f"strike_{strike_count}_hard_lockout_30m",
                    }
                    return render_cyberaccess_blocked(request, context, status=403)

                # 2. Administrative Portal Access Gatekeeper:
                # Direct probing or access to /admin or /admin/* by unauthenticated or non-staff visitors
                # is immediately intercepted and quarantined. Never expose Django administration!
                if is_admin:
                    is_authenticated = getattr(request.user, 'is_authenticated', False)
                    is_staff = getattr(request.user, 'is_staff', False)
                    if not (is_authenticated and is_staff):
                        client_ip = get_client_ip(request)
                        now_ts = time.time()
                        client = CyberAccessClient.get_instance()

                        allowed, action, details = enforce_bola(
                            request=request,
                            resource_id="privileged_admin_portal",
                            is_authorized=False,
                            resource_name="admin_login_probe",
                            http_verb=request.method,
                            subject=client_ip,
                        )

                        rem_sec = details.get("lockout_remaining_s") or 120
                        expires_at = details.get("lockout_expires_at") or int(now_ts + rem_sec)
                        rem_sec = max(0, int(expires_at - now_ts))
                        strike_count = details.get("strike_count") or 1

                        get_or_register_quarantine(client_ip, rem_sec, expires_at, strike_count)

                        client.log_timer_event(
                            subject=client_ip,
                            remaining_seconds=rem_sec,
                            expires_at=expires_at,
                            strike_count=strike_count,
                            reason="Direct access to privileged administration portal intercepted"
                        )

                        context = {
                            "subject": client_ip,
                            "decision": "block",
                            "score": details.get("score", 95.0),
                            "category": details.get("category", "Attack"),
                            "signals": details.get("signals") or ["unauthorized_admin_access_attempt", "blocked_due_to_high_risk", f"strike_{strike_count}_soft_lockout_2m"],
                            "explanations": details.get("explanations") or [
                                "Unauthorized direct administrative portal reconnaissance intercepted.",
                                "Direct access to privileged administration endpoints is strictly restricted to authenticated staff.",
                                f"Strike {strike_count}/3: Active quarantine cooldown penalty enforced across all application endpoints."
                            ],
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                            "contact_email": "security@company.com",
                            "lockout_remaining_seconds": rem_sec,
                            "lockout_expires_at": expires_at,
                            "strike_count": strike_count,
                            "lockout_type": f"strike_{strike_count}_soft_lockout_2m" if rem_sec <= 120 else f"strike_{strike_count}_hard_lockout_30m",
                        }
                        return render_cyberaccess_blocked(request, context, status=403)

                # 3. Object Access Check (for non-admin object endpoints)
                if not is_admin and self._OBJECT_PATH_PATTERN.search(path):
                    m = self._OBJECT_PATH_PATTERN.search(path)
                    if m:
                        obj_id = m.group(1)
                        if "record" in path:
                            resource_type = "record"
                        elif "claim" in path:
                            resource_type = "claim"
                        else:
                            resource_type = "item"
                        resource_id = f"{resource_type}_{obj_id}"

                        # EARLY CHECK: Is this subject high-risk? Block before page render
                        allowed, action, details = enforce_bola(
                            request=request,
                            resource_id=resource_id,
                            is_authorized=False,
                            resource_name="resource_access_check",
                            http_verb=request.method,
                            subject=client_ip,
                        )

                        # If blocked at entry point, show blocked page BEFORE rendering website
                        if action == "block":
                            rem_sec = details.get("lockout_remaining_s", 120) or 120
                            expires_at = details.get("lockout_expires_at") or int(now_ts + rem_sec)
                            rem_sec = max(0, int(expires_at - now_ts))
                            get_or_register_quarantine(client_ip, rem_sec, expires_at, 1)
                            client.log_timer_event(
                                subject=client_ip,
                                remaining_seconds=rem_sec,
                                expires_at=expires_at,
                                strike_count=1,
                                reason="Early object check blocked access"
                            )
                            context = {
                                "subject": client_ip,
                                "decision": "block",
                                "score": details.get("score", 100.0),
                                "category": details.get("category", "Attack"),
                                "signals": details.get("signals", ["automated_enumeration"]),
                                "explanations": details.get("explanations", ["Abnormal access pattern detected. Access quarantined."]),
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                                "contact_email": "security@company.com",
                                "lockout_remaining_seconds": rem_sec,
                                "lockout_expires_at": expires_at,
                                "strike_count": 1,
                                "lockout_type": "soft_lockout_2m" if rem_sec <= 120 else "hard_lockout_30m",
                            }
                            return render_cyberaccess_blocked(request, context, status=403)

        response = self.get_response(request)
        if CYBERACCESS_ENABLED:
            path = request.path
            static_exts = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.map', '.mp4')
            if not any(path.endswith(ext) for ext in static_exts) and not path.startswith('/static/') and not path.startswith('/media/'):
                is_admin = path.startswith('/admin/') or path.startswith('/admin')
                if is_admin:
                    is_authenticated = getattr(request.user, 'is_authenticated', False)
                    is_staff = getattr(request.user, 'is_staff', False)
                    # In Django admin, failed login POST returns 200 (re-rendering form with errors) or 401/403.
                    # Successful login returns 302 redirect.
                    is_failed_admin_login = (
                        request.method == 'POST' and (
                            (response.status_code == 200 and not (is_authenticated and is_staff))
                            or response.status_code in (401, 403)
                        )
                    )
                    if is_failed_admin_login:
                        attempted_user = request.POST.get('username', '').strip() or 'unknown'
                        client_ip = get_client_ip(request)
                        now_ts = time.time()
                        client = CyberAccessClient.get_instance()

                        # Enforce through CyberAccess Behavioral Risk Engine
                        allowed, action, details = enforce_bola(
                            request=request,
                            resource_id="privileged_admin_portal",
                            is_authorized=False,
                            resource_name="admin_login_probe",
                            http_verb=request.method,
                            subject=client_ip,
                        )

                        rem_sec = details.get("lockout_remaining_s") or 120
                        expires_at = details.get("lockout_expires_at") or int(now_ts + rem_sec)
                        rem_sec = max(0, int(expires_at - now_ts))
                        strike_count = details.get("strike_count") or 1

                        get_or_register_quarantine(client_ip, rem_sec, expires_at, strike_count)
                        if attempted_user and attempted_user != "unknown":
                            get_or_register_quarantine(attempted_user, rem_sec, expires_at, strike_count)

                        client.log_timer_event(
                            subject=client_ip,
                            remaining_seconds=rem_sec,
                            expires_at=expires_at,
                            strike_count=strike_count,
                            reason=f"Failed administrative credential entry for '{attempted_user}'"
                        )

                        context = {
                            "subject": client_ip,
                            "decision": "block",
                            "score": details.get("score", 95.0),
                            "category": details.get("category", "Attack"),
                            "signals": details.get("signals") or ["unauthorized_admin_access_attempt", "blocked_due_to_high_risk", f"strike_{strike_count}_soft_lockout_2m"],
                            "explanations": details.get("explanations") or [
                                "Unauthorized administrative access probe detected.",
                                "Direct credential brute-forcing against privileged portals is prohibited.",
                                f"Strike {strike_count}/3: Active quarantine cooldown penalty enforced across all application endpoints."
                            ],
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                            "contact_email": "security@company.com",
                            "lockout_remaining_seconds": rem_sec,
                            "lockout_expires_at": expires_at,
                            "strike_count": strike_count,
                            "lockout_type": f"strike_{strike_count}_soft_lockout_2m" if rem_sec <= 120 else f"strike_{strike_count}_hard_lockout_30m",
                        }
                        return render_cyberaccess_blocked(request, context, status=403)

                if response.status_code == 404:
                    m = self._OBJECT_PATH_PATTERN.search(path)
                    # If this is an object access attempt (item/claim/record), show blocked page instead of 404
                    if m:
                        obj_id = m.group(1)
                        if "record" in path:
                            resource_type = "record"
                        elif "claim" in path:
                            resource_type = "claim"
                        else:
                            resource_type = "item"
                        resource_id = f"{resource_type}_{obj_id}"

                        client_ip = get_client_ip(request)
                        allowed, action, details = enforce_bola(
                            request=request,
                            resource_id=resource_id,
                            is_authorized=False,
                            resource_name="resource_not_found",
                            http_verb=request.method,
                            subject=client_ip,
                        )

                        now = time.time()
                        q_entry = get_or_register_quarantine(client_ip, 120)
                        rem_sec = q_entry["remaining_seconds"]
                        expires_at = q_entry["expires_at"]

                        client = CyberAccessClient.get_instance()
                        client.log_timer_event(
                            subject=client_ip,
                            remaining_seconds=rem_sec,
                            expires_at=expires_at,
                            strike_count=1,
                            reason="Object enumeration probe on non-existent record"
                        )

                        context = {
                            "subject": client_ip,
                            "decision": "block",
                            "score": details.get("score", 75.0),
                            "category": details.get("category", "Suspicious Activity"),
                            "signals": details.get("signals", ["object_enumeration", "resource_discovery"]),
                            "explanations": details.get("explanations", [
                                "Access to this resource is restricted.",
                                "Object enumeration attempts are monitored and logged."
                            ]),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                            "contact_email": "security@company.com",
                            "strike_count": 1,
                            "is_locked": True,
                            "lockout_remaining_seconds": rem_sec,
                            "lockout_expires_at": expires_at,
                            "lockout_type": "soft_lockout_2m",
                        }
                        return render_cyberaccess_blocked(request, context, status=403)
        return response

    def process_exception(self, request: HttpRequest, exception: Exception):
        if isinstance(exception, CyberAccessBOLAException):
            subject = get_client_subject(request)
            client_ip = get_client_ip(request)
            now_ts = time.time()

            # Monotonic quarantine calculation
            local_q = _ACTIVE_QUARANTINES.get(subject) or _ACTIVE_QUARANTINES.get(client_ip)
            if local_q and local_q["expires_at"] > now_ts:
                expires_at = local_q["expires_at"]
                rem_sec = max(0, int(expires_at - now_ts))
                strike_count = local_q.get("strike_count", 1)
            else:
                raw_rem = int(exception.payload.get("lockout_remaining_s", 0) or 0)
                if raw_rem <= 0:
                    raw_rem = 120
                expires_at = int(exception.payload.get("lockout_expires_at") or (now_ts + raw_rem))
                rem_sec = max(0, int(expires_at - now_ts))
                strike_count = int(exception.payload.get("strike_count") or 1)
                get_or_register_quarantine(subject, rem_sec, expires_at, strike_count)
                if client_ip != subject:
                    get_or_register_quarantine(client_ip, rem_sec, expires_at, strike_count)

            client = CyberAccessClient.get_instance()
            client.log_timer_event(
                subject=subject,
                remaining_seconds=rem_sec,
                expires_at=expires_at,
                strike_count=strike_count,
                reason="Object enumeration probe intercepted"
            )

            context = {
                "subject": subject,
                "decision": "block",
                "score": exception.score,
                "category": exception.category,
                "signals": exception.signals,
                "explanations": exception.explanations,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "contact_email": "security@company.com",
                "lockout_remaining_seconds": rem_sec,
                "lockout_expires_at": expires_at,
                "strike_count": strike_count,
                "lockout_type": "soft_lockout_2m" if rem_sec <= 120 else "hard_lockout_30m",
            }
            return render_cyberaccess_blocked(request, context, status=403)
        return None
