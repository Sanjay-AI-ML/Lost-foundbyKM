import json
from datetime import timedelta
from unittest.mock import Mock, patch

import requests
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from claims.models import Claim
from items.models import Item
from notifications.models import Notification
from .cyberaccess_adapter import CyberAccessClient


@override_settings(CYBERACCESS_ENABLED=True, CYBERACCESS_API_KEY="sk_isolated_unit_test",
                   CYBERACCESS_API_URL="http://engine.test", CYBERACCESS_FAIL_OPEN=False, CYBERACCESS_TIMEOUT=2)
class ApiKeyAdapterTests(SimpleTestCase):
    def setUp(self):
        self.http = Mock()
        self.http.headers = {}
        self.session_patch = patch("lost_found_project.cyberaccess_adapter.requests.Session", return_value=self.http)
        self.session_patch.start()
        self.addCleanup(self.session_patch.stop)
        self.guard = CyberAccessClient()

    def reply(self, decision="allow", score=4, status=200):
        response = Mock(status_code=status)
        response.json.return_value = {"decision": decision, "score": score, "signals": [], "explanations": []}
        self.http.post.return_value = response
        return response

    def test_key_is_only_credential_and_no_private_data_sent(self):
        self.reply()
        self.assertEqual(self.guard.authorize("lost-found:user:1", "claim_2", True)["source"], "cyberaccess")
        self.assertEqual(self.http.headers["X-API-Key"], "sk_isolated_unit_test")
        self.assertNotIn("Authorization", self.http.headers)
        args, kwargs = self.http.post.call_args
        self.assertEqual(args[0], "http://engine.test/v1/authorize")
        self.assertEqual(set(kwargs["json"]), {"subject", "resource_id", "authorized", "endpoint", "http_verb"})
        self.assertFalse(kwargs["allow_redirects"])

    def test_remote_allow_cannot_override_local_ownership(self):
        self.reply()
        self.assertEqual(self.guard.authorize("u", "claim_2", False)["decision"], "deny")

    def test_timeout_fail_closed_denies_even_an_owner(self):
        self.http.post.side_effect = requests.Timeout()
        result = self.guard.authorize("u", "claim_2", True)
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["source"], "local_fallback")
        self.assertIsNone(result["score"])

    def test_fail_open_still_preserves_local_denial(self):
        self.guard.fail_open = True
        self.http.post.side_effect = requests.ConnectionError()
        self.assertEqual(self.guard.authorize("u", "claim_2", True)["decision"], "allow")
        self.assertEqual(self.guard.authorize("u", "claim_2", False)["decision"], "deny")

    def test_invalid_key_never_fails_open(self):
        self.guard.fail_open = True
        self.reply(status=401)
        result = self.guard.authorize("u", "claim_2", True)
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["signals"], ["api_key_rejected"])

    def test_malformed_payload_does_not_grant_access(self):
        for decision, score in [("unknown", 3), ("allow", -1), ("allow", 101), ("allow", float("nan")), ("allow", True)]:
            with self.subTest(decision=decision, score=score):
                self.reply(decision, score)
                self.assertEqual(self.guard.authorize("u", "claim_2", True)["decision"], "deny")

    def test_missing_and_shared_keys_are_rejected(self):
        for key in ("", "dev_test_key"):
            with self.subTest(key=key), override_settings(CYBERACCESS_API_KEY=key):
                with self.assertRaises(ImproperlyConfigured):
                    CyberAccessClient()

    def test_lockout_subject_is_url_encoded(self):
        self.http.get.return_value.json.return_value = {"is_locked": False}
        self.guard.get_lockout_status("user/../other?tenant=bad")
        self.assertIn("user%2F..%2Fother%3Ftenant%3Dbad", self.http.get.call_args.args[0])

    def test_lockout_timeout_is_not_reported_as_a_clear_account(self):
        self.http.get.side_effect = requests.Timeout()
        self.assertFalse(self.guard.get_lockout_status("u")["available"])

    def test_lockout_bad_credentials_are_reported_even_in_fail_open_mode(self):
        self.guard.fail_open = True
        self.http.get.return_value.status_code = 401
        status = self.guard.get_lockout_status("u")
        self.assertFalse(status["available"])
        self.assertTrue(status["credentials_rejected"])


@override_settings(CYBERACCESS_ENABLED=True, CYBERACCESS_API_KEY="sk_isolated_unit_test", CYBERACCESS_DEMO_ENABLED=True,
                   CYBERACCESS_NOTIFICATIONS_ENABLED=True, CYBERACCESS_LOG_ALLOWED=False, CYBERACCESS_NOTIFICATION_COOLDOWN_SECONDS=60)
class PortalEnforcementTests(TestCase):
    def setUp(self):
        self.finder = User.objects.create_user("cyberaccess_demo_finder")
        self.alice = User.objects.create_user("cyberaccess_demo_alice")
        self.mallory = User.objects.create_user("cyberaccess_demo_mallory")
        self.item = Item.objects.create(user=self.finder, title="Private test wallet", description="Test listing",
                                       location="Demo", item_type="FOUND", date_lost_or_found=timezone.now().date())
        self.claim = Claim.objects.create(item=self.item, claimant=self.alice, proof_details="PRIVATE_PROOF_MUST_NOT_LEAK", contact_info="private@example.test")
        self.other = Claim.objects.create(item=self.item, claimant=self.mallory, proof_details="OTHER_PRIVATE_PROOF", contact_info="other@example.test")
        self.guard = Mock(enabled=True)
        self.guard.fail_open = False
        self.guard.get_lockout_status.return_value = {"is_locked": False}
        self.guard.authorize.side_effect = lambda subject, resource, authorized, **kwargs: {
            "decision": "allow" if authorized else "deny", "score": 5 if authorized else 25,
            "signals": [], "explanations": [], "source": "cyberaccess"}
        self.patch = patch("lost_found_project.cyberaccess_adapter.CyberAccessClient.get_instance", return_value=self.guard)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.client.force_login(self.alice)

    def test_owner_can_read_private_claim(self):
        response = self.client.get(f"/claims/status/{self.claim.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-CyberAccess-Decision"], "allow")

    def test_unrelated_user_cannot_read_private_claim(self):
        self.client.force_login(self.mallory)
        response = self.client.get(f"/claims/status/{self.claim.pk}/")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(b"PRIVATE_PROOF_MUST_NOT_LEAK", response.content)
        self.assertFalse(self.guard.authorize.call_args.args[2])

    def test_claim_receipts_are_also_protected(self):
        self.client.force_login(self.mallory)
        for page in ("approved", "rejected"):
            response = self.client.get(f"/claims/{page}/{self.claim.pk}/")
            self.assertEqual(response.status_code, 403)
            self.assertNotIn(b"PRIVATE_PROOF_MUST_NOT_LEAK", response.content)

    def test_claimant_cannot_authorize_review_mutation(self):
        response = self.client.post(f"/claims/status/{self.claim.pk}/", {"status": "APPROVED"})
        self.assertEqual(response["X-CyberAccess-Decision"], "deny")
        self.claim.refresh_from_db()
        self.assertEqual(self.claim.status, "PENDING")

    def test_public_item_still_honors_behavioral_block(self):
        self.guard.authorize.side_effect = None
        self.guard.authorize.return_value = {"decision": "block", "score": 95, "source": "cyberaccess", "signals": [], "lockout_remaining_s": 120}
        response = self.client.get(f"/item/{self.item.pk}/")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["X-CyberAccess-Decision"], "block")
        self.assertNotIn(b"Private test wallet", response.content)

    def test_outage_returns_503_without_fake_risk_score(self):
        self.guard.authorize.side_effect = None
        self.guard.authorize.return_value = {"decision": "deny", "score": None, "source": "local_fallback", "signals": ["engine_unavailable"]}
        response = self.client.get(f"/claims/status/{self.claim.pk}/")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("X-CyberAccess-Risk-Score", response)
        self.assertNotIn(b"PRIVATE_PROOF_MUST_NOT_LEAK", response.content)

    def test_lockout_is_per_user_not_shared_ip(self):
        self.guard.get_lockout_status.side_effect = lambda subject: {"is_locked": subject == f"lost-found:user:{self.alice.pk}", "lockout_remaining_seconds": 120}
        self.assertEqual(self.client.get(f"/item/{self.item.pk}/").status_code, 403)
        self.client.force_login(self.mallory)
        self.assertEqual(self.client.get(f"/item/{self.item.pk}/").status_code, 200)

    def test_demo_controls_hidden_when_disabled_nonlocal_or_production(self):
        with override_settings(CYBERACCESS_DEMO_ENABLED=False):
            self.assertEqual(self.client.get("/cyberaccess/demo/").status_code, 404)
        self.assertEqual(self.client.get("/cyberaccess/demo/", REMOTE_ADDR="203.0.113.10").status_code, 404)
        with override_settings(DEBUG=False):
            self.assertEqual(self.client.get("/cyberaccess/demo/").status_code, 404)

    @override_settings(DEBUG=True)
    def test_demo_check_uses_guard_and_does_not_expose_key_or_claim_contents(self):
        response = self.client.post("/cyberaccess/demo/check/", {"action": "other"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["checks"][0]["decision"], "deny")
        self.assertNotIn(b"sk_isolated_unit_test", response.content)
        self.assertNotIn(b"OTHER_PRIVATE_PROOF", response.content)

    def test_hackathon_bypass_does_not_release_anyone(self):
        self.assertEqual(self.client.get("/cyberaccess/bypass/").status_code, 404)

    def test_dashboard_uses_integration_status_not_broken_bypass_toggle(self):
        # Regression: ISSUE-001, found by /qa on 2026-10-10.
        # Report: .gstack/lost-found-demo/qa-report.md
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Tenant API-key integration configured")
        self.assertNotContains(response, "dashboardToggleBtn")
        self.assertNotContains(response, "/toggle-defense-status")

    def test_dashboard_does_not_return_private_data_during_outage(self):
        self.guard.authorize.side_effect = None
        self.guard.authorize.return_value = {"decision": "deny", "score": None, "source": "local_fallback", "signals": ["engine_unavailable"]}
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"PRIVATE_PROOF_MUST_NOT_LEAK", response.content)

    def test_denied_request_notifies_only_the_requesting_user_and_logs_safe_metadata(self):
        with self.assertLogs("cyberaccess", level="WARNING") as captured:
            response = self.client.get(f"/claims/status/{self.other.pk}/")
        self.assertEqual(response.status_code, 302)
        notice = Notification.objects.get()
        self.assertEqual(notice.recipient, self.alice)
        self.assertIn("Risk score: 25/100", notice.message)
        event = json.loads(captured.records[0].getMessage())
        self.assertEqual(event["decision"], "deny")
        self.assertEqual(event["subject"], f"lost-found:user:{self.alice.pk}")
        self.assertEqual(event["risk_score"], 25)
        self.assertNotIn("sk_isolated_unit_test", captured.output[0] + notice.message)
        self.assertNotIn("OTHER_PRIVATE_PROOF", captured.output[0] + notice.message)

    def test_repeated_denials_are_grouped_but_new_alert_can_follow_cooldown(self):
        for _ in range(2):
            self.client.get(f"/claims/status/{self.other.pk}/")
        self.assertEqual(Notification.objects.count(), 1)
        Notification.objects.update(created_at=timezone.now() - timedelta(minutes=2))
        self.client.get(f"/claims/status/{self.other.pk}/")
        self.assertEqual(Notification.objects.count(), 2)

    def test_block_alert_remains_deduplicated_for_the_entire_quarantine(self):
        expires_at = int((timezone.now() + timedelta(minutes=30)).timestamp())
        self.guard.authorize.side_effect = None
        self.guard.authorize.return_value = {"decision": "block", "score": 95, "source": "cyberaccess",
                                            "signals": [], "lockout_remaining_s": 1800, "lockout_expires_at": expires_at}
        self.client.get(f"/item/{self.item.pk}/")
        Notification.objects.update(created_at=timezone.now() - timedelta(minutes=5))
        self.guard.get_lockout_status.return_value = {"is_locked": True, "lockout_remaining_seconds": 1500, "lockout_expires_at": expires_at}
        response = self.client.get(f"/item/{self.item.pk}/")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Notification.objects.count(), 1)
        self.assertEqual(int(response.context["quarantine_expiry"].timestamp()), expires_at)
        self.assertEqual(response["X-CyberAccess-Risk-Score"], "95")
        self.assertContains(response, "quarantine-timer", status_code=403)
        self.assertNotContains(response, "cyberaccess/bypass", status_code=403)

    def test_blocked_user_can_read_own_alerts_without_unblocking_private_pages(self):
        Notification.objects.create(recipient=self.mallory, title="Mallory only", message="PRIVATE_OTHER_NOTICE")
        self.guard.get_lockout_status.return_value = {"is_locked": True, "lockout_remaining_seconds": 120}
        self.assertEqual(self.client.get(f"/claims/status/{self.claim.pk}/").status_code, 403)
        response = self.client.get("/notifications/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CyberAccess: account temporarily blocked")
        self.assertNotContains(response, "PRIVATE_OTHER_NOTICE")
        other_notice = Notification.objects.get(recipient=self.mallory)
        self.assertEqual(self.client.get(f"/notifications/read/{other_notice.pk}/").status_code, 404)
        self.assertEqual(self.client.get(f"/claims/status/{self.claim.pk}/").status_code, 403)

    def test_fresh_blocked_session_does_not_invent_a_risk_score(self):
        self.guard.get_lockout_status.return_value = {"is_locked": True, "lockout_remaining_seconds": 120}
        response = self.client.get(f"/claims/status/{self.claim.pk}/")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("X-CyberAccess-Risk-Score", response)
        self.assertNotContains(response, "100/100", status_code=403)

    def test_score_from_an_old_quarantine_is_not_attached_to_a_new_one(self):
        expires_at = int((timezone.now() + timedelta(minutes=2)).timestamp())
        self.guard.authorize.side_effect = None
        self.guard.authorize.return_value = {"decision": "block", "score": 91, "source": "cyberaccess",
                                            "signals": [], "lockout_remaining_s": 120, "lockout_expires_at": expires_at}
        self.client.get(f"/item/{self.item.pk}/")
        self.guard.get_lockout_status.return_value = {"is_locked": True, "lockout_remaining_seconds": 1800,
                                                    "lockout_expires_at": expires_at + 1800}
        response = self.client.get(f"/item/{self.item.pk}/")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("X-CyberAccess-Risk-Score", response)

    def test_outage_is_logged_as_unavailable_not_as_an_attack_notification(self):
        self.guard.authorize.side_effect = None
        self.guard.authorize.return_value = {"decision": "deny", "score": None, "source": "local_fallback", "signals": ["engine_unavailable"]}
        with self.assertLogs("cyberaccess", level="WARNING") as captured:
            response = self.client.get(f"/claims/status/{self.claim.pk}/")
        self.assertEqual(response.status_code, 503)
        self.assertFalse(Notification.objects.exists())
        self.assertEqual(json.loads(captured.records[0].getMessage())["source"], "local_fallback")

    def test_notification_storage_failure_cannot_bypass_block(self):
        self.guard.get_lockout_status.return_value = {"is_locked": True, "lockout_remaining_seconds": 120}
        with patch("lost_found_project.security_feedback.Notification.objects.create", side_effect=DatabaseError("offline")):
            response = self.client.get(f"/claims/status/{self.claim.pk}/")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b"PRIVATE_PROOF_MUST_NOT_LEAK", response.content)

    def test_allowed_requests_do_not_spam_security_notifications_or_logs(self):
        with self.assertNoLogs("cyberaccess"):
            self.assertEqual(self.client.get(f"/claims/status/{self.claim.pk}/").status_code, 200)
        self.assertFalse(Notification.objects.exists())

    @override_settings(DEBUG=True)
    def test_demo_exposes_saved_alert_and_real_block_page_link_without_secrets(self):
        self.guard.authorize.side_effect = None
        self.guard.authorize.return_value = {"decision": "block", "score": 100, "source": "cyberaccess",
                                            "signals": [], "lockout_remaining_s": 120}
        response = self.client.post("/cyberaccess/demo/check/", {"action": "enumerate"})
        data = response.json()
        self.assertTrue(data["notification"]["created"])
        self.assertEqual(data["unread_notifications"], 1)
        self.assertEqual(data["block_page_url"], f"/claims/status/{self.claim.pk}/")
        self.assertNotIn(b"sk_isolated_unit_test", response.content)
        self.assertNotIn(b"PRIVATE_PROOF_MUST_NOT_LEAK", response.content)

    def test_failed_quarantine_lookup_stops_item_and_claim_writes_before_the_view(self):
        self.guard.get_lockout_status.return_value = {"available": False}
        before = (Item.objects.count(), Claim.objects.count())
        for path in ("/item/add/lost/", "/item/add/found/", f"/claims/submit/{self.item.pk}/"):
            response = self.client.post(path, {"title": "Should never be created", "proof_details": "Should never be stored"})
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response["X-CyberAccess-Source"], "local_fallback")
        self.assertEqual(before, (Item.objects.count(), Claim.objects.count()))
        self.guard.authorize.assert_not_called()

    def test_bad_quarantine_credentials_cannot_fail_open(self):
        self.guard.fail_open = True
        self.guard.get_lockout_status.return_value = {"available": False, "credentials_rejected": True}
        self.assertEqual(self.client.get("/item/add/lost/").status_code, 503)

    def test_profile_and_password_routes_are_protected_during_quarantine(self):
        self.guard.get_lockout_status.return_value = {"is_locked": True, "lockout_remaining_seconds": 120}
        for path in ("/accounts/profile/", "/accounts/profile/edit/", "/accounts/password/change/", "/profile/"):
            self.assertEqual(self.client.get(path).status_code, 403)
        self.assertEqual(self.client.get("/accounts/logout/").status_code, 302)

    @override_settings(DEBUG=True)
    def test_demo_login_refuses_privileged_and_password_based_accounts(self):
        self.client.logout()
        for field in ("is_staff", "is_superuser"):
            setattr(self.alice, field, True)
            self.alice.save()
            self.assertEqual(self.client.post("/cyberaccess/demo/", {"persona": "alice"}).status_code, 400)
            self.assertNotIn("_auth_user_id", self.client.session)
            setattr(self.alice, field, False)
        self.alice.set_password("This-is-not-a-demo-account-123!")
        self.alice.save()
        self.assertEqual(self.client.post("/cyberaccess/demo/", {"persona": "alice"}).status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_missing_receipt_outage_returns_503_instead_of_middleware_exception(self):
        self.guard.authorize.side_effect = None
        self.guard.authorize.return_value = {"decision": "deny", "score": None, "source": "local_fallback", "signals": ["engine_unavailable"]}
        response = self.client.get("/claims/approved/999999/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response["X-CyberAccess-Decision"], "deny")

    def test_non_owner_cannot_edit_or_delete_another_users_item(self):
        for action in ("edit", "delete"):
            response = self.client.post(f"/item/{self.item.pk}/{action}/", {"title": "Modified without permission"})
            self.assertEqual(response["X-CyberAccess-Decision"], "deny")
            self.assertTrue(Item.objects.filter(pk=self.item.pk, title="Private test wallet").exists())

    def test_locked_owner_cannot_edit_or_delete_their_own_item(self):
        self.client.force_login(self.finder)
        self.guard.get_lockout_status.return_value = {"is_locked": True, "lockout_remaining_seconds": 120}
        for action in ("edit", "delete"):
            self.assertEqual(self.client.post(f"/item/{self.item.pk}/{action}/").status_code, 403)
            self.assertTrue(Item.objects.filter(pk=self.item.pk, title="Private test wallet").exists())
