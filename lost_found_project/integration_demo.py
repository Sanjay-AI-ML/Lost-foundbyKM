"""Local-only controls to exercise the same gate used by the portal's real views."""
import ipaddress
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.http import Http404, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from claims.models import Claim
from notifications.models import Notification
from .cyberaccess import enforce_bola, get_client_subject, CyberAccessBOLAException

PERSONAS = {"alice": "cyberaccess_demo_alice", "mallory": "cyberaccess_demo_mallory"}


def _local_demo_only(request):
    try:
        local = ipaddress.ip_address(request.META.get("REMOTE_ADDR", "")).is_loopback
    except ValueError:
        local = False
    if not (settings.DEBUG and settings.CYBERACCESS_DEMO_ENABLED and local):
        raise Http404


def demo_view(request):
    _local_demo_only(request)
    if request.method == "POST":
        username = PERSONAS.get(request.POST.get("persona"))
        user = User.objects.filter(username=username).first() if username else None
        if not user:
            return JsonResponse({"error": "Run seed_cyberaccess_demo first."}, status=400)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        return redirect("cyberaccess_demo")
    active = request.user.is_authenticated and request.user.username in PERSONAS.values()
    own = Claim.objects.filter(claimant=request.user).first() if active else None
    other = Claim.objects.filter(claimant__username__in=PERSONAS.values()).exclude(claimant=request.user).first() if active else None
    return render(request, "cyberaccess_demo.html", {"demo_active": active, "own_claim": own,
                  "other_claim": other, "console_url": settings.CYBERACCESS_CONSOLE_URL,
                  "subject": get_client_subject(request), "key_configured": bool(settings.CYBERACCESS_API_KEY)})


@require_POST
def demo_check(request):
    _local_demo_only(request)
    if not request.user.is_authenticated or request.user.username not in PERSONAS.values():
        return JsonResponse({"error": "Choose a test user first."}, status=401)
    action = request.POST.get("action")
    if action not in ("own", "other", "enumerate"):
        return JsonResponse({"error": "Unknown test."}, status=400)
    rows = []
    if action in ("own", "other"):
        query = Claim.objects.filter(claimant__username__in=PERSONAS.values())
        claim = (query.filter(claimant=request.user) if action == "own" else query.exclude(claimant=request.user)).first()
        if not claim:
            return JsonResponse({"error": "Demo claims are missing. Run seed_cyberaccess_demo."}, status=409)
        authorized = request.user == claim.claimant or request.user == claim.item.user or request.user.is_staff
        checks = [(f"claim_{claim.pk}", authorized)]
    else:
        # Bounded enumeration of nonexistent objects; no private claim data is read.
        next_id = max(900000, request.session.get("cyberaccess_probe_id", 900000))
        checks = [(f"claim_{next_id + i}", False) for i in range(10)]
        request.session["cyberaccess_probe_id"] = next_id + 10
    for resource_id, authorized in checks:
        try:
            allowed, _, result = enforce_bola(request, resource_id, authorized, "claims_status" if action != "enumerate" else "claims_fuzz_probe")
        except CyberAccessBOLAException as exc:
            allowed, result = False, exc.payload
        rows.append({"resource_id": resource_id, "authorized": authorized, "allowed": allowed,
                     **{key: result.get(key) for key in ("decision", "score", "category", "source", "signals", "lockout_remaining_s")}})
        if result["decision"] == "block" or result.get("source") != "cyberaccess":
            break
    live = all(row["source"] == "cyberaccess" for row in rows)
    own = Claim.objects.filter(claimant=request.user).first()
    block_url = reverse("claims:claim_status", args=[own.pk]) if own and rows[-1]["decision"] == "block" else None
    response = JsonResponse({"subject": get_client_subject(request), "checks": rows, "live": live,
                             "notification": getattr(request, "_cyberaccess_feedback", None),
                             "unread_notifications": Notification.objects.filter(recipient=request.user, is_read=False).count(),
                             "block_page_url": block_url}, status=200 if live else 503)
    response["Cache-Control"] = "no-store"
    return response
