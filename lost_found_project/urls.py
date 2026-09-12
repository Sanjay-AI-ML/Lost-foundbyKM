"""
URL configuration for lost_found_project.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import render
from lost_found_project.attack_api import trigger_attack, reset_demo

def about_view(request):
    return render(request, 'about.html')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('trigger-attack', trigger_attack, name='trigger_attack'),
    path('reset', reset_demo, name='reset_demo'),
    path('', include('items.urls', namespace='items')),
    path('accounts/', include('accounts.urls', namespace='accounts')),
    path('claims/', include('claims.urls', namespace='claims')),
    path('notifications/', include('notifications.urls', namespace='notifications')),
    path('about/', about_view, name='about'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

handler404 = 'items.views.custom_404_view'
handler500 = 'items.views.custom_500_view'
