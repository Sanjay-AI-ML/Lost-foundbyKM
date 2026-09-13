"""
URL configuration for lost_found_project.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import render
from lost_found_project.attack_api import trigger_attack, reset_demo, toggle_defense_system, get_defense_status
from accounts.views import login_view, register_view, logout_view, profile_view

def about_view(request):
    return render(request, 'about.html')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('trigger-attack', trigger_attack, name='trigger_attack'),
    path('reset', reset_demo, name='reset_demo'),
    path('toggle-defense', toggle_defense_system, name='toggle_defense'),
    path('toggle-defense-status', get_defense_status, name='get_defense_status'),
    path('login/', login_view, name='direct_login'),
    path('register/', register_view, name='direct_register'),
    path('signup/', register_view, name='direct_signup'),
    path('logout/', logout_view, name='direct_logout'),
    path('profile/', profile_view, name='direct_profile'),
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
