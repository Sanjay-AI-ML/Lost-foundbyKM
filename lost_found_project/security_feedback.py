"""Turn API decisions into local feedback without weakening authorization."""
import json
import logging
import math
from datetime import datetime, timedelta, timezone as datetime_timezone

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db import DatabaseError, transaction
from django.urls import reverse
from django.utils import timezone
from notifications.models import Notification

logger = logging.getLogger("cyberaccess")


def block_expiry(result):
    """Use the engine's absolute expiry, never extend it from a browser timer."""
    value = result.get("lockout_expires_at")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    try:
        return datetime.fromtimestamp(value, tz=datetime_timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def publish_security_feedback(request, result, resource_id, endpoint):
    decision, source = result["decision"], result.get("source", "cyberaccess")
    user = getattr(request, "user", None)
    subject = f"lost-found:user:{user.pk}" if user and user.is_authenticated else "anonymous"
    if source == "cyberaccess" and decision == "block" and result.get("score") is not None and hasattr(request, "session"):
        remembered = request.session.get("cyberaccess_block_decision", {})
        if remembered.get("subject") != subject or remembered.get("expires_at") != result.get("lockout_expires_at"):
            request.session["cyberaccess_block_decision"] = {"subject": subject, "expires_at": result.get("lockout_expires_at"), "score": result["score"]}
    if decision != "allow" or settings.CYBERACCESS_LOG_ALLOWED:
        # Explicit metadata whitelist: no keys, headers, private proof or response bodies.
        event = {"event": "cyberaccess.decision", "time": timezone.now().isoformat(),
                 "subject": subject, "resource": str(resource_id)[:100], "endpoint": str(endpoint)[:100],
                 "decision": decision, "source": source, "risk_score": result.get("score"),
                 "score_context": result.get("score_context", "authorization"),
                 "signals": [signal[:100] for signal in result.get("signals", [])[:10] if isinstance(signal, str)]}
        logger.log(logging.INFO if decision == "allow" else logging.WARNING, json.dumps(event, ensure_ascii=True))

    # An unavailable engine is not evidence of an attack. Disabled integration emits no security notices.
    if source != "cyberaccess" or decision not in ("deny", "block"):
        return None
    if decision == "block":
        title = "CyberAccess: account temporarily blocked"
        text = "CyberAccess stopped a risky access pattern. Protected pages remain unavailable until the server lifts the quarantine."
    else:
        title = "CyberAccess: access denied"
        text = "A request from your account was denied. You cannot access another member's private information."
    if result.get("score") is not None:
        text += f" Risk score: {result['score']:g}/100."
    expiry = block_expiry(result) if decision == "block" else None
    expiry_marker = f" Quarantine ends at: {expiry.isoformat()}." if expiry else ""
    text += expiry_marker
    feedback = {"title": title, "message": text, "created": False}
    request._cyberaccess_feedback = feedback
    if not settings.CYBERACCESS_NOTIFICATIONS_ENABLED or not user or not user.is_authenticated:
        return feedback

    try:
        # A failed notification write must not turn a denied request into an allowed one.
        with transaction.atomic():
            # Serialize notice creation per recipient when PostgreSQL supports row locks.
            get_user_model().objects.select_for_update().get(pk=user.pk)
            recent = Notification.objects.filter(recipient=user, title=title)
            if expiry_marker:
                # One alert per server quarantine, including blocks longer than the cooldown.
                recent = recent.filter(message__endswith=expiry_marker)
            else:
                recent = recent.filter(created_at__gte=timezone.now() - timedelta(seconds=settings.CYBERACCESS_NOTIFICATION_COOLDOWN_SECONDS))
            if not recent.exists():
                Notification.objects.create(recipient=user, title=title, message=text,
                                            link=reverse("items:dashboard") if decision == "block" else reverse("notifications:list"))
                feedback["created"] = True
    except DatabaseError:
        logger.error("CyberAccess notification could not be stored; the authorization decision still applies")
    if feedback["created"]:
        messages.warning(request, f"{title}. View your security alerts for details.", fail_silently=True)
    return feedback
