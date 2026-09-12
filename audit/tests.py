from django.test import TestCase
from django.contrib.auth.models import User
from .models import AuditLog


class AuditLogTestCase(TestCase):
    """Test cases for audit log functionality."""

    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')

    def test_audit_log_creation(self):
        """Test that audit logs can be created and retrieved."""
        log = AuditLog.objects.create(
            subject='testuser',
            action='url_blocked',
            resource_type='url',
            resource_id='http://malicious.com',
            details={'reason': 'Blocked domain'},
            severity='high',
            source='url_safety',
        )
        self.assertIsNotNone(log.id)
        self.assertEqual(log.subject, 'testuser')
        self.assertEqual(log.action, 'url_blocked')

    def test_mark_reviewed(self):
        """Test marking audit log as reviewed."""
        log = AuditLog.objects.create(
            subject='testuser',
            action='url_blocked',
            resource_type='url',
            resource_id='http://malicious.com',
            severity='high',
            source='url_safety',
        )
        log.mark_reviewed(reviewer=self.user, notes='False positive')
        log.refresh_from_db()
        self.assertTrue(log.reviewed)
        self.assertEqual(log.reviewed_by, self.user)
        self.assertEqual(log.review_notes, 'False positive')

    def test_get_unreviewed_critical(self):
        """Test retrieving unreviewed critical events."""
        AuditLog.objects.create(
            subject='testuser',
            action='url_blocked',
            resource_type='url',
            resource_id='http://critical.com',
            severity='critical',
            source='url_safety',
        )
        AuditLog.objects.create(
            subject='testuser',
            action='url_blocked',
            resource_type='url',
            resource_id='http://medium.com',
            severity='medium',
            source='url_safety',
        )
        critical = AuditLog.get_unreviewed_critical()
        self.assertEqual(critical.count(), 1)
        self.assertEqual(critical.first().severity, 'critical')

    def test_get_by_subject(self):
        """Test retrieving logs by subject."""
        AuditLog.objects.create(
            subject='user1',
            action='url_blocked',
            resource_type='url',
            resource_id='http://malicious.com',
            severity='medium',
            source='url_safety',
        )
        AuditLog.objects.create(
            subject='user2',
            action='url_blocked',
            resource_type='url',
            resource_id='http://other.com',
            severity='medium',
            source='url_safety',
        )
        user1_logs = AuditLog.get_by_subject('user1')
        self.assertEqual(user1_logs.count(), 1)
        self.assertEqual(user1_logs.first().subject, 'user1')
