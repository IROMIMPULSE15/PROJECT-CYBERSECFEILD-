"""
URL configuration for user account management.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'accounts'

urlpatterns = [
    # Authentication endpoints
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),
    
    # Profile management
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('password/change/', views.PasswordChangeView.as_view(), name='password_change'),
    
    # Two-factor authentication
    path('2fa/enable/', views.Enable2FAView.as_view(), name='enable_2fa'),
    path('2fa/disable/', views.Disable2FAView.as_view(), name='disable_2fa'),
    
    # Session management
    path('sessions/', views.UserSessionsView.as_view(), name='sessions'),
    path('sessions/<int:session_id>/terminate/', views.TerminateSessionView.as_view(), name='terminate_session'),
    
    # Activity and security
    path('activities/', views.UserActivityView.as_view(), name='activities'),
    path('security/dashboard/', views.security_dashboard, name='security_dashboard'),
]
