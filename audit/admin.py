"""
Django Admin integration for Audit Logs - allows security team to review security events.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Professional audit log admin interface for security review."""

    list_display = [
        "timestamp_display",
        "severity_badge",
        "action",
        "subject",
        "resource_display",
        "reviewed_status",
    ]
    list_filter = ["severity", "action", "resource_type", "reviewed", "timestamp"]
    search_fields = ["subject", "resource_id", "action"]
    readonly_fields = [
        "timestamp",
        "subject",
        "action",
        "severity",
        "resource_type",
        "resource_id",
        "details",
        "source",
        "user",
        "details_json_display",
    ]
    fieldsets = (
        ("Event Details", {
            "fields": ("timestamp", "subject", "action", "severity", "source"),
        }),
        ("Resource Information", {
            "fields": ("resource_type", "resource_id", "user"),
        }),
        ("Details", {
            "fields": ("details_json_display", "details"),
            "classes": ("collapse",),
        }),
        ("Security Review", {
            "fields": ("reviewed", "reviewed_by", "reviewed_at", "review_notes"),
        }),
    )

    def timestamp_display(self, obj):
        """Display timestamp in a human-readable format."""
        return obj.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    timestamp_display.short_description = "Timestamp"

    def severity_badge(self, obj):
        """Display severity as a colored badge."""
        color_map = {
            "critical": "ff4444",
            "high": "ff8844",
            "medium": "ffaa44",
            "low": "44aa44",
        }
        color = color_map.get(obj.severity, "888888")
        return format_html(
            '<span style="background-color: #{}; color: white; padding: 3px 10px; border-radius: 3px; font-weight: bold;">{}</span>',
            color,
            obj.get_severity_display().upper(),
        )
    severity_badge.short_description = "Severity"

    def resource_display(self, obj):
        """Display resource type and ID together."""
        return f"{obj.get_resource_type_display()}: {obj.resource_id[:50]}"
    resource_display.short_description = "Resource"

    def reviewed_status(self, obj):
        """Display reviewed status with badge."""
        if obj.reviewed:
            return format_html(
                '<span style="background-color: #44aa44; color: white; padding: 3px 10px; border-radius: 3px;">✓ Reviewed</span>'
            )
        else:
            return format_html(
                '<span style="background-color: #ffaa44; color: white; padding: 3px 10px; border-radius: 3px;">⚠ Pending</span>'
            )
    reviewed_status.short_description = "Review Status"

    def details_json_display(self, obj):
        """Display JSON details in a formatted way."""
        import json
        try:
            formatted = json.dumps(obj.details, indent=2)
            return format_html("<pre>{}</pre>", formatted)
        except:
            return str(obj.details)
    details_json_display.short_description = "Event Details (JSON)"

    def get_readonly_fields(self, request, obj=None):
        """Make all fields readonly except review fields for non-superusers."""
        if obj is None:
            return self.readonly_fields
        if not request.user.is_superuser:
            return self.readonly_fields
        return self.readonly_fields

    actions = ["mark_as_reviewed", "mark_as_unreviewed"]

    def mark_as_reviewed(self, request, queryset):
        """Admin action to mark audit logs as reviewed."""
        for log in queryset:
            log.mark_reviewed(reviewer=request.user)
        self.message_user(request, f"{queryset.count()} audit logs marked as reviewed.")
    mark_as_reviewed.short_description = "Mark selected as reviewed"

    def mark_as_unreviewed(self, request, queryset):
        """Admin action to mark audit logs as unreviewed."""
        queryset.update(reviewed=False, reviewed_by=None, reviewed_at=None)
        self.message_user(request, f"{queryset.count()} audit logs marked as unreviewed.")
    mark_as_unreviewed.short_description = "Mark selected as unreviewed"

    def get_queryset(self, request):
        """Customize queryset ordering."""
        qs = super().get_queryset(request)
        # Show unreviewed critical items first
        return qs.order_by("-severity", "-timestamp")
