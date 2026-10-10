"""Server-to-server CyberAccess integration. The only credential is X-API-Key."""
from __future__ import annotations

import logging
import math
import re
from threading import local
from urllib.parse import quote

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import render
from .security_feedback import block_expiry, publish_security_feedback

logger = logging.getLogger("cyberaccess")
CYBERACCESS_CANARIES = getattr(settings, "CYBERACCESS_CANARIES", [])
_ACTIVE_QUARANTINES = {}  # Compatibility with the old local demonstration script.


class CyberAccessBOLAException(Exception):
    def __init__(self, payload):
        self.payload = payload
        super().__init__("CyberAccess denied this request")


class CyberAccessClient:
    _instance = None

    def __init__(self):
        self.enabled = settings.CYBERACCESS_ENABLED
        self.api_key = settings.CYBERACCESS_API_KEY.strip()
        self.base_url = settings.CYBERACCESS_API_URL.rstrip("/")
        self.timeout = settings.CYBERACCESS_TIMEOUT
        self.fail_open = settings.CYBERACCESS_FAIL_OPEN
        self._threads = local()
        if self.enabled and not self.api_key:
            raise ImproperlyConfigured("Set CYBERACCESS_API_KEY to your tenant key before enabling CyberAccess.")
        if self.enabled and self.api_key in ("dev_test_key", "demo-key-unused"):
            raise ImproperlyConfigured("Use a tenant API key from the CyberAccess dashboard, not a shared development key.")

    @property
    def session(self):
        if not hasattr(self._threads, "session"):
            session = requests.Session()
            session.headers.update({"X-API-Key": self.api_key, "User-Agent": "LostFound-CyberAccess/2.0"})
            self._threads.session = session
        return self._threads.session

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _fallback(self, authorized, signal, *, credentials_rejected=False):
        allow = authorized and self.fail_open and not credentials_rejected
        return {"decision": "allow" if allow else "deny", "score": None,
                "category": "Unavailable", "signals": [signal], "source": "local_fallback",
                "explanations": ["CyberAccess could not evaluate this request. Local ownership rules still apply."]}

    def authorize(self, subject, resource_id, authorized, endpoint="django_view", http_verb="GET"):
        if not self.enabled:
            return {"decision": "allow" if authorized else "deny", "score": None,
                    "category": "Disabled", "signals": [], "explanations": [], "source": "disabled"}
        payload = {"subject": str(subject), "resource_id": str(resource_id), "authorized": bool(authorized),
                   "endpoint": endpoint, "http_verb": http_verb.upper()}
        try:
            response = self.session.post(f"{self.base_url}/v1/authorize", json=payload,
                                         timeout=self.timeout, allow_redirects=False)
            if response.status_code in (401, 403):
                logger.warning("CyberAccess rejected the integration credential (HTTP %s)", response.status_code)
                return self._fallback(authorized, "api_key_rejected", credentials_rejected=True)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict) or data.get("decision") not in ("allow", "deny", "block"):
                raise ValueError("Invalid authorization response")
            score = data.get("score")
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 100:
                raise ValueError("Invalid risk score")
            if not isinstance(data.get("signals", []), list) or not isinstance(data.get("explanations", []), list):
                raise ValueError("Invalid authorization signals")
            # A remote decision can never override the application's own ownership denial.
            if not authorized and data["decision"] == "allow":
                data["decision"] = "deny"
            data["source"] = "cyberaccess"
            return data
        except (requests.RequestException, ValueError):
            # Never log request headers, keys, response bodies, or claim contents.
            logger.warning("CyberAccess unavailable; applying the configured local fallback")
            return self._fallback(authorized, "engine_unavailable")

    def get_lockout_status(self, subject):
        clear = {"is_locked": False, "lockout_remaining_seconds": 0, "strike_count": 0}
        if not self.enabled:
            return clear
        try:
            response = self.session.get(f"{self.base_url}/lockout-status/{quote(str(subject), safe='')}",
                                        timeout=self.timeout, allow_redirects=False)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict) and type(data.get("is_locked")) is bool:
                return data
        except (requests.RequestException, ValueError):
            pass
        return clear

    def log_timer_event(self, subject, remaining_seconds, expires_at=None, strike_count=1, reason="Quarantine active"):
        if self.enabled:
            try:
                self.session.post(f"{self.base_url}/v1/audit/timer-log", json={
                    "subject": subject, "remaining_seconds": remaining_seconds, "expires_at": expires_at,
                    "strike_count": strike_count, "reason": reason}, timeout=self.timeout, allow_redirects=False)
            except requests.RequestException:
                pass


def get_client_ip(request):
    # Forwarded headers are not trusted unless a proxy is explicitly configured.
    return request.META.get("REMOTE_ADDR", "unknown")


def get_client_subject(request):
    if getattr(request.user, "is_authenticated", False):
        return f"lost-found:user:{request.user.pk}"
    return f"lost-found:anonymous:{get_client_ip(request)}"


def enforce_bola(request, resource_id, is_authorized, resource_name="resource", http_verb=None, subject=None):
    request._bola_evaluated = True
    result = CyberAccessClient.get_instance().authorize(
        subject or get_client_subject(request), str(resource_id), is_authorized,
        endpoint=resource_name, http_verb=http_verb or request.method)
    request._bola_result = result
    publish_security_feedback(request, result, resource_id, resource_name)
    decision = result["decision"]
    if decision == "deny" and result.get("source") in ("local_fallback", "disabled"):
        raise CyberAccessBOLAException(result)
    if decision == "block":
        return False, "block", result
    if not is_authorized or decision != "allow":
        return False, "deny", result
    return True, None, result


def render_cyberaccess_blocked(request, context, status=403):
    response = render(request, "cyberaccess_decision.html", context, status=status)
    response["Cache-Control"] = "no-store"
    return response


class CyberAccessSecurityMiddleware:
    """Honor engine decisions without sharing one user's lockout with other users on the same IP."""
    object_path = re.compile(r"/(?:items?|records?|claims/(?:status|approved|rejected|success))/([0-9]+)/?$")

    def __init__(self, get_response):
        self.get_response = get_response
        self.client = CyberAccessClient.get_instance()

    def __call__(self, request):
        # Login/logout remain available. Demo controls never release a real quarantine.
        skip = request.path.startswith(("/static/", "/media/", "/accounts/", "/login/", "/logout/", "/register/", "/signup/", "/cyberaccess/demo/", "/notifications/"))
        if self.client.enabled and not skip and getattr(request.user, "is_authenticated", False):
            lockout = self.client.get_lockout_status(get_client_subject(request))
            if lockout.get("is_locked"):
                remembered = request.session.get("cyberaccess_block_decision", {})
                same_block = (remembered.get("subject") == get_client_subject(request)
                              and remembered.get("expires_at") == lockout.get("lockout_expires_at"))
                # The status API has no score. Preserve a score from this block's actual
                # decision, or leave it unknown on a fresh session; never invent 100.
                result = {"decision": "block", "score": remembered.get("score") if same_block else None,
                          "score_context": "at_block", "category": "Attack", "source": "cyberaccess",
                          "signals": ["temporarily_blocked"], "explanations": ["This account is temporarily quarantined."],
                          "lockout_remaining_s": lockout.get("lockout_remaining_seconds", 0),
                          "lockout_expires_at": lockout.get("lockout_expires_at"), "strike_count": lockout.get("strike_count", 0)}
                request._bola_result = result
                publish_security_feedback(request, result, "quarantined_account", "quarantine_gate")
                return self._headers(self._decision_page(request, result), result)
        response = self.get_response(request)
        if self.client.enabled and response.status_code == 404 and not getattr(request, "_bola_evaluated", False):
            match = self.object_path.search(request.path)
            if match:
                _, action, result = enforce_bola(request, match.group(1), False, "object_probe")
                if action == "block":
                    response = self._decision_page(request, result)
        result = getattr(request, "_bola_result", None)
        return self._headers(response, result) if result else response

    @staticmethod
    def _headers(response, result):
        response["X-CyberAccess-Decision"] = result["decision"]
        response["X-CyberAccess-Source"] = result.get("source", "cyberaccess")
        if result.get("score") is not None:
            response["X-CyberAccess-Risk-Score"] = str(result["score"])
        response["Cache-Control"] = "no-store"
        return response

    def _decision_page(self, request, result):
        context = dict(result, subject=get_client_subject(request),
                       lockout_remaining_seconds=result.get("lockout_remaining_s", 0),
                       quarantine_expiry=block_expiry(result))
        status = 503 if result.get("source") == "local_fallback" else 403
        return render_cyberaccess_blocked(request, context, status)

    def process_exception(self, request, exception):
        if isinstance(exception, CyberAccessBOLAException):
            return self._headers(self._decision_page(request, exception.payload), exception.payload)
        return None
