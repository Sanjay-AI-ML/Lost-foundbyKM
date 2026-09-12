from django import forms
from django.core.exceptions import ValidationError
from .models import Claim
from lost_found_project.url_safety import check_content_for_urls, URLBlockedException


class ClaimSubmissionForm(forms.ModelForm):
    class Meta:
        model = Claim
        fields = ['proof_details', 'proof_image', 'contact_info']
        widgets = {
            'proof_details': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Provide detailed proof of ownership such as serial number, unique scratches, wallpaper description, item contents, or receipt details.'
            }),
            'proof_image': forms.FileInput(attrs={'class': 'form-control-file'}),
            'contact_info': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g. +1 555-0199 or user@example.com'
            }),
        }

    def clean(self):
        """Validate URLs in user-provided content."""
        cleaned_data = super().clean()

        # Check proof details for suspicious URLs
        proof_details = cleaned_data.get('proof_details', '')
        if proof_details:
            try:
                is_safe, blocked_urls = check_content_for_urls(
                    proof_details,
                    context='claim_proof_details'
                )
                if not is_safe and blocked_urls:
                    raise ValidationError(
                        f"Your proof details contain unsafe links that are blocked: {blocked_urls[0]['reason']}"
                    )
            except URLBlockedException as e:
                raise ValidationError(
                    f"Your proof details contain a blocked URL: {e.reason}"
                )

        # Check contact info for suspicious URLs
        contact_info = cleaned_data.get('contact_info', '')
        if contact_info:
            try:
                is_safe, blocked_urls = check_content_for_urls(
                    contact_info,
                    context='claim_contact_info'
                )
                if not is_safe and blocked_urls:
                    raise ValidationError(
                        f"Your contact info contains unsafe links that are blocked: {blocked_urls[0]['reason']}"
                    )
            except URLBlockedException as e:
                raise ValidationError(
                    f"Your contact info contains a blocked URL: {e.reason}"
                )

        return cleaned_data


class ClaimReviewForm(forms.ModelForm):
    class Meta:
        model = Claim
        fields = ['status', 'review_notes']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-control'}),
            'review_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Add a response note or pickup/delivery instructions for the claimant.'
            }),
        }

    def clean(self):
        """Validate URLs in review notes."""
        cleaned_data = super().clean()

        review_notes = cleaned_data.get('review_notes', '')
        if review_notes:
            try:
                is_safe, blocked_urls = check_content_for_urls(
                    review_notes,
                    context='claim_review_notes'
                )
                if not is_safe and blocked_urls:
                    raise ValidationError(
                        f"Your review notes contain unsafe links that are blocked: {blocked_urls[0]['reason']}"
                    )
            except URLBlockedException as e:
                raise ValidationError(
                    f"Your review notes contain a blocked URL: {e.reason}"
                )

        return cleaned_data
