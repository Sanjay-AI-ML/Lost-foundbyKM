from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    path('', views.notifications_list_view, name='list'),
    path('read/<int:pk>/', views.mark_as_read_view, name='mark_as_read'),
    path('read-all/', views.mark_all_as_read_view, name='mark_all_as_read'),
]
