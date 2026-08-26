from django.urls import path
from . import views

app_name = 'claims'

urlpatterns = [
    path('submit/<int:item_id>/', views.submit_claim_view, name='submit_claim'),
    path('status/<int:claim_id>/', views.claim_status_view, name='claim_status'),
    path('success/<int:claim_id>/', views.claim_success_view, name='claim_success'),
    path('approved/<int:claim_id>/', views.claim_approved_view, name='claim_approved'),
    path('rejected/<int:claim_id>/', views.claim_rejected_view, name='claim_rejected'),
]
