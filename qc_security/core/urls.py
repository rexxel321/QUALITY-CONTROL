from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('submission/action/<int:submission_id>/<str:action>/', views.submission_action, name='submission_action'),
]