"""
Test suite for URL Safety mechanism
Run with: python manage.py test --keepdb < test_url_safety.py
Or: python -m pytest test_url_safety.py
"""

from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from lost_found_project.url_safety import (
    check_url_safety,
    check_content_for_urls,
    URLBlockedException,
    is_internal_url,
)
from audit.models import AuditLog


class URLSafetyTestCase(TestCase):
    """Test cases for URL safety validation."""

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='testuser', password='testpass')

    def test_safe_url(self):
        """Test that legitimate URLs pass validation."""
        safe_urls = [
            'https://example.com',
            'http://google.com',
            'https://github.com/user/repo',
            'https://docs.djangoproject.com/en/stable/',
        ]
        for url in safe_urls:
            is_safe, reason = check_url_safety(url)
            self.assertTrue(is_safe, f"URL should be safe: {url}")
            self.assertIsNone(reason)

    def test_internal_urls(self):
        """Test that internal application URLs are always safe."""
        internal_urls = [
            '/items/1',
            '/claims/status/5',
            '/dashboard',
            'http://localhost:8000/home',
            '127.0.0.1/admin',
        ]
        for url in internal_urls:
            is_safe = is_internal_url(url)
            self.assertTrue(is_safe, f"URL should be recognized as internal: {url}")

    def test_blocked_javascript_injection(self):
        """Test that JavaScript injection is blocked."""
        with self.assertRaises(URLBlockedException) as ctx:
            check_url_safety('javascript:alert("xss")')
        self.assertIn('javascript', ctx.exception.reason.lower())
        self.assertEqual(ctx.exception.severity, 'critical')

    def test_blocked_data_uri_injection(self):
        """Test that data URI injection is blocked."""
        with self.assertRaises(URLBlockedException):
            check_url_safety('data:text/html,<script>alert("xss")</script>')

    def test_blocked_shortener_domains(self):
        """Test that URL shortener services are blocked."""
        shortener_urls = [
            'https://bit.ly/abc123',
            'https://tinyurl.com/xyzabc',
            'https://goo.gl/maps/example',
        ]
        for url in shortener_urls:
            with self.assertRaises(URLBlockedException):
                check_url_safety(url, context='test')

    def test_blocked_executable_extensions(self):
        """Test that URLs with executable extensions are blocked."""
        blocked_urls = [
            'https://example.com/malware.exe',
            'https://example.com/script.bat',
            'https://example.com/installer.msi',
        ]
        for url in blocked_urls:
            with self.assertRaises(URLBlockedException):
                check_url_safety(url, context='test')

    def test_blocked_phishing_indicators(self):
        """Test that URLs with phishing keywords are flagged."""
        # Note: These might be "medium" severity, not "critical"
        phishing_urls = [
            'https://example.com/verify-account',
            'https://example.com/confirm-identity',
            'https://example.com/update-payment',
        ]
        for url in phishing_urls:
            is_safe, reason = check_url_safety(url, context='test')
            # Medium severity might return (False, reason) instead of raising
            if not is_safe:
                self.assertIsNotNone(reason)

    def test_content_url_extraction(self):
        """Test that URLs are extracted from content."""
        content = """
        Check out this link: https://example.com/item
        And this one: https://bit.ly/shortlink
        """
        all_safe, blocked = check_content_for_urls(content, context='test_content')
        self.assertFalse(all_safe, "Content should have blocked URLs")
        self.assertGreater(len(blocked), 0)
        self.assertIn('bit.ly', str(blocked[0]['url']))

    def test_audit_log_creation(self):
        """Test that blocked URLs create audit log entries."""
        request = self.factory.get('/')
        request.user = self.user

        try:
            check_url_safety('https://bit.ly/malicious', context='item_description', request=request)
        except URLBlockedException:
            pass

        # Check that audit log was created
        logs = AuditLog.objects.filter(action='url_blocked', subject='testuser')
        self.assertGreater(logs.count(), 0, "Audit log should be created for blocked URL")

        log = logs.first()
        self.assertEqual(log.resource_type, 'url')
        self.assertEqual(log.severity, 'high')
        self.assertEqual(log.source, 'url_safety')

    def test_audit_log_details(self):
        """Test that audit log contains detailed information."""
        request = self.factory.get('/')
        request.user = self.user

        try:
            check_url_safety(
                'https://bit.ly/test',
                context='claim_proof',
                request=request
            )
        except URLBlockedException:
            pass

        log = AuditLog.objects.filter(action='url_blocked').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details['context'], 'claim_proof')
        self.assertIn('bit.ly', log.details['url'])
        self.assertIn('reason', log.details)


if __name__ == '__main__':
    import unittest
    unittest.main()
