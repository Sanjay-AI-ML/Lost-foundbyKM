from django.contrib import admin
from .models import Category, Item


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'icon')
    prepopulated_fields = {'slug': ('name',)}
    search_fields = ('name', 'description')


@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    list_display = ('title', 'item_type', 'category', 'status', 'user', 'location', 'date_lost_or_found', 'created_at')
    list_filter = ('item_type', 'status', 'category', 'created_at')
    search_fields = ('title', 'description', 'location', 'contact_phone', 'contact_email')
    date_hierarchy = 'created_at'
