from django.db import models
from django.contrib.auth.models import User
from django.utils.text import slugify
from django.urls import reverse


class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True, blank=True)
    icon = models.CharField(max_length=50, default='fa-box', help_text="FontAwesome icon class, e.g. fa-laptop, fa-wallet")
    description = models.TextField(blank=True)

    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


def item_directory_path(instance, filename):
    folder = 'lost_items' if instance.item_type == 'LOST' else 'found_items'
    return f'{folder}/{filename}'


class Item(models.Model):
    ITEM_TYPE_CHOICES = (
        ('LOST', 'Lost Item'),
        ('FOUND', 'Found Item'),
    )

    STATUS_CHOICES = (
        ('OPEN', 'Open / Active'),
        ('CLAIM_PENDING', 'Claim Pending'),
        ('RESOLVED', 'Resolved / Returned'),
        ('CLOSED', 'Closed'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='items')
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, related_name='items')
    title = models.CharField(max_length=200)
    description = models.TextField()
    item_type = models.CharField(max_length=10, choices=ITEM_TYPE_CHOICES, default='LOST')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    location = models.CharField(max_length=200, help_text="Specific place/address where item was lost or found")
    date_lost_or_found = models.DateField(help_text="Date when the item was lost or found")
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    contact_email = models.EmailField(blank=True, null=True)
    image = models.ImageField(upload_to=item_directory_path, blank=True, null=True)
    reward = models.CharField(max_length=100, blank=True, null=True, help_text="Optional reward amount or note")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.item_type}] {self.title} - {self.location}"

    @property
    def image_url(self):
        if self.image and hasattr(self.image, 'url'):
            return self.image.url
        return '/static/images/no_image.png'

    def get_absolute_url(self):
        return reverse('items:item_detail', kwargs={'pk': self.pk})
