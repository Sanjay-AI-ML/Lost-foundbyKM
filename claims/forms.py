from django import forms
from .models import Claim


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
