"""
URL configuration for lost_found_project.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import render
from . import auth_views

def about_view(request):
    return render(request, 'about.html')

from items.views import home_view

urlpatterns = [
    path('admin/', admin.site.urls),

    # Authentication routes (production quality)
    path('login/', auth_views.login_view, name='login'),
    path('logout/', auth_views.logout_view, name='logout'),
    path('register/', auth_views.register_view, name='register'),
    path('dashboard/', auth_views.dashboard_view, name='dashboard'),
    path('password/reset/', auth_views.password_reset_request, name='password_reset'),

    # App routes
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
