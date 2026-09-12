from django import forms
from django.core.exceptions import ValidationError
from .models import Item, Category
from lost_found_project.url_safety import check_content_for_urls, URLBlockedException


class ItemForm(forms.ModelForm):
    class Meta:
        model = Item
        fields = [
            'title', 'category', 'item_type', 'location',
            'date_lost_or_found', 'reward', 'contact_phone',
            'contact_email', 'image', 'description'
        ]
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. OnePlus AirPods, Blue iPhone 14 Pro, Black Leather Wallet'}),
            'category': forms.Select(attrs={'class': 'form-control'}),
            'item_type': forms.Select(attrs={'class': 'form-control'}),
            'location': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Central Library 2nd Floor, Main Bus Terminal, Starbucks Table 4'}),
            'date_lost_or_found': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'reward': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. $50 (Optional)'}),
            'contact_phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. +1 555-0123'}),
            'contact_email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'e.g. yourname@example.com'}),
            'image': forms.FileInput(attrs={'class': 'form-control-file'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4, 'placeholder': 'Describe distinctive marks, serial numbers, case color, unique scratches, condition, etc.'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['category'].empty_label = "Select Category"
        self.fields['item_type'].required = False
        self.fields['reward'].required = False
        self.fields['contact_phone'].required = False
        self.fields['contact_email'].required = False
        self.fields['image'].required = False

    def clean(self):
        """Validate URLs in user-provided content."""
        cleaned_data = super().clean()

        # Check description for suspicious URLs
        description = cleaned_data.get('description', '')
        if description:
            try:
                is_safe, blocked_urls = check_content_for_urls(
                    description,
                    context='item_description'
                )
                if not is_safe and blocked_urls:
                    raise ValidationError(
                        f"Your item description contains unsafe links that are blocked: {blocked_urls[0]['reason']}"
                    )
            except URLBlockedException as e:
                raise ValidationError(
                    f"Your item description contains a blocked URL: {e.reason}"
                )

        # Check reward field for suspicious URLs
        reward = cleaned_data.get('reward', '')
        if reward:
            try:
                is_safe, blocked_urls = check_content_for_urls(
                    reward,
                    context='item_reward'
                )
                if not is_safe and blocked_urls:
                    raise ValidationError(
                        f"Your reward field contains unsafe links that are blocked: {blocked_urls[0]['reason']}"
                    )
            except URLBlockedException as e:
                raise ValidationError(
                    f"Your reward field contains a blocked URL: {e.reason}"
                )

        return cleaned_data


class ItemSearchForm(forms.Form):
    q = forms.CharField(required=False, widget=forms.TextInput(attrs={
        'class': 'form-control search-input',
        'placeholder': 'Search by item name, keywords or location...'
    }))
    category = forms.ModelChoiceField(
        queryset=Category.objects.all(),
        required=False,
        empty_label="All Categories",
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    item_type = forms.ChoiceField(
        choices=[('', 'All Types'), ('LOST', 'Lost Items'), ('FOUND', 'Found Items')],
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
