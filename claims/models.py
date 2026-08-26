from django.db import models
from django.contrib.auth.models import User
from items.models import Item


class Claim(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending Verification'),
        ('APPROVED', 'Claim Approved'),
        ('REJECTED', 'Claim Rejected'),
    )

    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name='claims')
    claimant = models.ForeignKey(User, on_delete=models.CASCADE, related_name='claims')
    proof_details = models.TextField(
        help_text="Provide specific proof of ownership (e.g. unique identifiers, lock screen passcode, receipt, exact contents)."
    )
    proof_image = models.ImageField(upload_to='claims_proof/', blank=True, null=True)
    contact_info = models.CharField(max_length=200, help_text="Phone number or preferred contact method")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    review_notes = models.TextField(blank=True, null=True, help_text="Notes from the finder/owner when reviewing this claim")
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = ('item', 'claimant')

    def __str__(self):
        return f"Claim #{self.id} on '{self.item.title}' by {self.claimant.username} ({self.status})"
