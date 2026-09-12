"""
Audit Logging System for Security Events
Records all security-related events (blocked URLs, BOLA violations, etc.) for review and analysis.
"""

import json
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class AuditLog(models.Model):
    """
    Comprehensive audit log for security events, access patterns, and threat detection.
    Used by URL Safety, CyberAccess BOLA, and other security modules.
    """

    SEVERITY_CHOICES = (
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    )

    ACTION_CHOICES = (
        ("url_blocked", "URL Blocked"),
        ("bola_violation", "BOLA Violation"),
        ("enumeration_attempt", "Enumeration Attempt"),
        ("authorization_denied", "Authorization Denied"),
        ("claim_submitted", "Claim Submitted"),
        ("item_created", "Item Created"),
        ("item_accessed", "Item Accessed"),
        ("account_login", "Account Login"),
        ("password_reset", "Password Reset"),
        ("security_event", "Security Event"),
        ("suspicious_activity", "Suspicious Activity"),
    )

    RESOURCE_TYPE_CHOICES = (
        ("url", "URL"),
        ("item", "Item"),
        ("claim", "Claim"),
        ("user", "User"),
        ("endpoint", "Endpoint"),
        ("resource", "Generic Resource"),
    )

    # Core Audit Fields
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    subject = models.CharField(
        max_length=255,
        db_index=True,
        help_text="User identity (username or IP address) who triggered this event",
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="medium", db_index=True)

    # Resource Identification
    resource_type = models.CharField(max_length=50, choices=RESOURCE_TYPE_CHOICES)
    resource_id = models.CharField(max_length=255, db_index=True, help_text="ID of the affected resource")

    # Audit Details
    details = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional context (JSON): reason, client_ip, url, etc.",
    )

    # Traceability
    source = models.CharField(
        max_length=100,
        db_index=True,
        default="manual",
        help_text="What system logged this (e.g., 'url_safety', 'cyberaccess', 'admin')",
    )
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
        help_text="Authenticated user if available",
    )

    # Status Tracking
    reviewed = models.BooleanField(default=False, db_index=True, help_text="Has security team reviewed this?")
    review_notes = models.TextField(blank=True, help_text="Security team review comments")
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_audit_logs",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["timestamp", "severity"]),
            models.Index(fields=["subject", "action"]),
            models.Index(fields=["resource_type", "resource_id"]),
            models.Index(fields=["reviewed", "severity"]),
        ]
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"

    def __str__(self):
        return f"[{self.severity.upper()}] {self.action} by {self.subject} on {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

    @property
    def client_ip(self) -> str:
        """Extracts client IP from details if available."""
        return self.details.get("client_ip", self.subject)

    @property
    def display_subject(self) -> str:
        """Returns a safe display name for the subject."""
        return self.subject if self.subject and self.subject != "anonymous" else "Anonymous"

    def mark_reviewed(self, reviewer: User = None, notes: str = "") -> None:
        """Mark this audit log as reviewed by security team."""
        self.reviewed = True
        self.reviewed_by = reviewer
        self.reviewed_at = timezone.now()
        if notes:
            self.review_notes = notes
        self.save()

    @classmethod
    def get_unreviewed_critical(cls):
        """Get all unreviewed critical security events."""
        return cls.objects.filter(reviewed=False, severity="critical").order_by("-timestamp")

    @classmethod
    def get_by_subject(cls, subject: str, days: int = 7):
        """Get recent audit logs for a specific subject."""
        from datetime import timedelta
        cutoff = timezone.now() - timedelta(days=days)
        return cls.objects.filter(subject=subject, timestamp__gte=cutoff).order_by("-timestamp")

    @classmethod
    def get_suspicious_activity(cls, severity_min: str = "medium", days: int = 7):
        """Get suspicious/blocked activity for the specified timeframe."""
        from datetime import timedelta
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_level = severity_order.get(severity_min, 2)

        cutoff = timezone.now() - timedelta(days=days)
        all_severities = [s[0] for s in cls.SEVERITY_CHOICES if severity_order[s[0]] >= min_level]

        return cls.objects.filter(
            severity__in=all_severities,
            timestamp__gte=cutoff,
        ).order_by("-timestamp")
