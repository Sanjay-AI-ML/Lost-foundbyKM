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

            for url, context_val, context_type in mixed_attacks:
                log_blocked_url(
                    url=url,
                    reason=f"Blocked across endpoints",
                    severity="medium",
                    context=context_type
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

            for url, context_val, context_type in canary_attacks:
                log_blocked_url(
                    url=url,
                    reason=f"Honeypot/Canary accessed - pre-attack reconnaissance",
                    severity="critical",
                    context=context_type
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
    Reset everything: clear audit timeline, quarantine cache, and demo state
    """
    try:
        # Delete all audit logs from database
        deleted_count, _ = AuditLog.objects.all().delete()

        # Clear in-memory quarantine cache (active timers)
        quarantine_count = 0
        try:
            from lost_found_project.cyberaccess import _ACTIVE_QUARANTINES
            quarantine_count = len(_ACTIVE_QUARANTINES)
            _ACTIVE_QUARANTINES.clear()
        except ImportError:
            pass  # If import fails, just skip quarantine clearing

        response = JsonResponse({
            'success': True,
            'message': f'Reset complete: {deleted_count} audit logs, {quarantine_count} quarantine timers cleared',
            'audit_logs_cleared': deleted_count,
            'quarantine_timers_cleared': quarantine_count,
        })
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'POST'
        return response

    except Exception as e:
        response = JsonResponse({
            'success': False,
            'message': str(e)
        }, status=500)
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'POST'
        return response


def _get_defense_state():
    """Get BOLA defense state from cache or database"""
    from django.core.cache import cache
    state = cache.get('bola_defense_enabled')
    if state is None:
        state = True
        cache.set('bola_defense_enabled', state, timeout=None)
    return state


def _set_defense_state(enabled):
    """Set BOLA defense state in cache"""
    from django.core.cache import cache
    cache.set('bola_defense_enabled', enabled, timeout=None)


@csrf_exempt
@require_http_methods(["GET"])
def get_defense_status(request):
    """
    Get current BOLA defense system status (ON/OFF)
    Used to load state on page refresh
    """
    try:
        defense_enabled = is_bola_defense_enabled()
        response = JsonResponse({
            'success': True,
            'defense_enabled': defense_enabled,
            'status': 'PROTECTED' if defense_enabled else 'VULNERABLE'
        })
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET'
        return response
    except Exception as e:
        response = JsonResponse({
            'success': False,
            'message': str(e)
        }, status=500)
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET'
        return response


@csrf_exempt
@require_http_methods(["POST"])
def toggle_defense_system(request):
    """
    Toggle BOLA defense system on/off for hackathon demo
    Shows what happens when defenses are active vs disabled
    Persists state in cache
    """
    try:
        current_state = _get_defense_state()
        new_state = not current_state
        _set_defense_state(new_state)

        response = JsonResponse({
            'success': True,
            'defense_enabled': new_state,
            'message': f'BOLA Defense System is now {"ON" if new_state else "OFF"}',
            'status': 'PROTECTED' if new_state else 'VULNERABLE'
        })
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'POST'
        return response
    except Exception as e:
        response = JsonResponse({
            'success': False,
            'message': str(e)
        }, status=500)
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'POST'
        return response


def is_bola_defense_enabled():
    """Check if BOLA defense system is enabled - persists across requests"""
    return _get_defense_state()
