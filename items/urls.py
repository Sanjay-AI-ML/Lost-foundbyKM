from django.urls import path
from . import views

app_name = 'items'

urlpatterns = [
    path('', views.home_view, name='home'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('lost-items/', views.lost_items_view, name='lost_items'),
    path('found-items/', views.found_items_view, name='found_items'),
    path('item/<int:pk>/', views.item_detail_view, name='item_detail'),
    path('item/<int:pk>', views.item_detail_view),
    path('items/<int:pk>/', views.item_detail_view),
    path('items/<int:pk>', views.item_detail_view),
    path('item/add/lost/', views.add_lost_item_view, name='add_lost_item'),
    path('item/add/found/', views.add_found_item_view, name='add_found_item'),
    path('item/<int:pk>/edit/', views.edit_item_view, name='edit_item'),
    path('item/<int:pk>/delete/', views.delete_item_view, name='delete_item'),
    path('search/', views.search_results_view, name='search_results'),
    path('category/<slug:slug>/', views.category_items_view, name='category_items'),
]
