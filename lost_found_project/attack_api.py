"""
Attack simulation API endpoints for dashboard demo
"""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json
from lost_found_project.url_safety import log_blocked_url
from audit.models import AuditLog


@csrf_exempt
@require_http_methods(["POST"])
def trigger_attack(request):
    """
    Trigger simulated attacks for jury demo
    """
    try:
        data = json.loads(request.body)
        attack_type = data.get('attack_type', '')

        if attack_type == 'URL_BLOCKING_1':
            # Horizontal privilege escalation with malicious URLs
            malicious_urls = [
                "https://bit.ly/phishing",
                "https://tinyurl.com/malware",
                "javascript:alert('xss')",
                "data:text/html,<script>steal()</script>",
                "https://example.com/file.exe",
                "https://phishing.com/verify_account",
                "file:///etc/passwd",
                "http://192.168.1.1/admin",
            ]

            for url in malicious_urls:
                log_blocked_url(
                    url=url,
                    reason=f"Malicious pattern detected",
                    severity="high",
                    subject="alice",
                    context="form_submission"
                )

            return JsonResponse({
                'success': True,
                'message': f'Blocked {len(malicious_urls)} malicious URLs from alice',
                'attack_type': 'horizontal_privilege_escalation'
            })

        elif attack_type == 'URL_BLOCKING_2':
            # Enumeration - rapid multi-URL submission
            attack_urls = [
                "https://bit.ly/steal1",
                "https://tinyurl.com/steal2",
                "https://ow.ly/steal3",
                "javascript:void(0)",
                "data:text/html,<img src=x>",
                "file:///etc/passwd",
                "http://malware.com/payload.exe",
                "https://phishing.com/verify_account",
                "https://stealing-service.com/capture",
                "ftp://internal-server.com",
                "https://bit.ly/another",
                "http://192.168.1.1/router",
                "https://admin-panel.fake/login",
                "javascript:stealData()",
                "data:application/x-msdownload,exec()",
            ]

            for url in attack_urls:
                log_blocked_url(
                    url=url,
                    reason=f"Blocked in claim submission",
                    severity="high",
                    subject="bob",
                    context="claim_form"
                )

            return JsonResponse({
                'success': True,
                'message': f'Detected enumeration attack: {len(attack_urls)} URLs blocked from bob',
                'attack_type': 'enumeration'
            })

        elif attack_type == 'URL_BLOCKING_3':
            # Multi-endpoint mixing
            mixed_attacks = [
                ("https://bit.ly/item1", "charlie", "item_form"),
                ("https://tinyurl.com/claim1", "charlie", "claim_form"),
                ("javascript:hack()", "charlie", "message_form"),
                ("data:text/html,<s>ript>", "charlie", "item_form"),
                ("https://phishing.com/verify", "charlie", "claim_form"),
                ("file:///etc/passwd", "charlie", "message_form"),
                ("https://shortener.io/bad", "charlie", "item_form"),
                ("http://malware.com/exe", "charlie", "claim_form"),
                ("javascript:void(0)", "charlie", "message_form"),
                ("https://example.com/bad.exe", "charlie", "item_form"),
            ]

            for url, subject, context in mixed_attacks:
                log_blocked_url(
                    url=url,
                    reason=f"Blocked across endpoints",
                    severity="medium",
                    subject=subject,
                    context=context
                )

            return JsonResponse({
                'success': True,
                'message': f'Multi-endpoint attack blocked: {len(mixed_attacks)} URLs across 3 endpoints from charlie',
                'attack_type': 'pattern_obfuscation'
            })

        elif attack_type == 'URL_BLOCKING_4':
            # Canary probe - honeypot detection
            canary_attacks = [
                ("https://bit.ly/probe1", "eve", "canary_probe"),
                ("https://tinyurl.com/probe2", "eve", "canary_probe"),
            ]

            for url, subject, context in canary_attacks:
                log_blocked_url(
                    url=url,
                    reason=f"Honeypot/Canary accessed - pre-attack reconnaissance",
                    severity="critical",
                    subject=subject,
                    context=context
                )

            return JsonResponse({
                'success': True,
                'message': f'Canary probe detected: eve probing honeypot URLs',
                'attack_type': 'canary_probe'
            })

        else:
            return JsonResponse({'success': False, 'message': 'Unknown attack type'}, status=400)

    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def reset_demo(request):
    """
    Reset everything: clear audit timeline and demo state
    """
    try:
        # Delete all audit logs
        deleted_count, _ = AuditLog.objects.all().delete()

        return JsonResponse({
            'success': True,
            'message': f'Reset complete: {deleted_count} audit log entries deleted',
            'audit_logs_cleared': deleted_count,
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        }, status=500)
