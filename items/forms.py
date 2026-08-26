from django import forms
from .models import Item, Category


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
