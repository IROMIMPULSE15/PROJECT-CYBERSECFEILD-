"""
Advanced user account views with comprehensive security features.
"""

from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, logout
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from .models import CustomUser, UserSession, UserActivity
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,
    Enable2FASerializer, UserSessionSerializer, UserActivitySerializer,
    PasswordChangeSerializer, PasswordResetRequestSerializer,
    SecuritySettingsSerializer
)
from security.utils import get_client_ip, get_geolocation, get_device_info
import pyotp
import secrets
import logging

logger = logging.getLogger('accounts')
security_logger = logging.getLogger('security')


class UserRegistrationView(generics.CreateAPIView):
    """User registration with enhanced security validation."""
    
    queryset = CustomUser.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegistrationSerializer
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.save()
        
        # Log registration activity
        UserActivity.objects.create(
            user=user,
            activity_type='registration',
            description=f"User registered with email {user.email}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            location=get_geolocation(get_client_ip(request)),
            metadata={
                'plan': user.plan,
                'verification_required': not user.is_verified
            }
        )
        
        # Send verification email
        self.send_verification_email(user, request)
        
        logger.info(f"New user registered: {user.email}")
        
        return Response({
            'message': 'User registered successfully. Please check your email for verification.',
            'user_id': user.id,
            'verification_required': not user.is_verified
        }, status=status.HTTP_201_CREATED)
    
    def send_verification_email(self, user, request):
        """Send email verification."""
        try:
            subject = 'Verify your CyberDefense Platform account'
            verification_url = f"{settings.FRONTEND_URL}/verify-email?token={user.verification_token}"
            
            html_message = render_to_string('emails/verification.html', {
                'user': user,
                'verification_url': verification_url,
                'site_name': 'CyberDefense Platform'
            })
            plain_message = strip_tags(html_message)
            
            send_mail(
                subject,
                plain_message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                html_message=html_message,
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Failed to send verification email to {user.email}: {e}")


class UserLoginView(APIView):
    """Enhanced user login with security monitoring."""
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            remember_me = serializer.validated_data.get('remember_me', False)
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Set token expiration based on remember_me
            if remember_me:
                refresh.set_exp(lifetime=timezone.timedelta(days=30))
                access_token.set_exp(lifetime=timezone.timedelta(hours=24))
            
            # Create user session
            session = self.create_user_session(user, request, access_token)
            
            # Log successful login
            UserActivity.objects.create(
                user=user,
                activity_type='login',
                description=f"Successful login from {session.ip_address}",
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                location=session.country_name,
                metadata={
                    'session_id': str(session.session_token),
                    'device_type': session.device_type,
                    'risk_score': session.risk_score
                }
            )
            
            logger.info(f"User login successful: {user.email} from {session.ip_address}")
            
            return Response({
                'message': 'Login successful',
                'access_token': str(access_token),
                'refresh_token': str(refresh),
                'user': UserProfileSerializer(user).data,
                'session': UserSessionSerializer(session).data
            }, status=status.HTTP_200_OK)
            
        except serializers.ValidationError as e:
            # Log failed login attempt
            email = request.data.get('email', 'unknown')
            ip_address = get_client_ip(request)
            
            security_logger.warning(
                f"Failed login attempt for {email} from {ip_address}: {e.detail}"
            )
            
            return Response({
                'error': 'Login failed',
                'details': e.detail
            }, status=status.HTTP_401_UNAUTHORIZED)
    
    def create_user_session(self, user, request, access_token):
        """Create and return user session with security assessment."""
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        device_info = get_device_info(user_agent)
        geo_info = get_geolocation(ip_address)
        
        # Calculate risk score
        risk_score = self.calculate_session_risk(user, ip_address, geo_info, device_info)
        
        # Determine trust level
        if risk_score <= 30:
            trust_level = 'high'
        elif risk_score <= 60:
            trust_level = 'medium'
        else:
            trust_level = 'low'
        
        # Create session
        session = UserSession.objects.create(
            user=user,
            session_key=request.session.session_key or secrets.token_urlsafe(32),
            ip_address=ip_address,
            user_agent=user_agent,
            country=geo_info.get('country_code', ''),
            country_name=geo_info.get('country_name', ''),
            region=geo_info.get('region', ''),
            city=geo_info.get('city', ''),
            device_type=device_info.get('device_type', 'unknown'),
            device_fingerprint=device_info.get('fingerprint', ''),
            browser_name=device_info.get('browser_name', ''),
            browser_version=device_info.get('browser_version', ''),
            os_name=device_info.get('os_name', ''),
            os_version=device_info.get('os_version', ''),
            expires_at=timezone.now() + timezone.timedelta(hours=24),
            trust_level=trust_level,
            risk_score=risk_score,
            is_suspicious=risk_score > 70,
            requires_verification=risk_score > 80
        )
        
        return session
    
    def calculate_session_risk(self, user, ip_address, geo_info, device_info):
        """Calculate risk score for the session."""
        risk_score = 0
        
        # Geographic risk
        high_risk_countries = getattr(settings, 'SECURITY_SETTINGS', {}).get(
            'HIGH_RISK_COUNTRIES', []
        )
        if geo_info.get('country_code') in high_risk_countries:
            risk_score += 30
        
        # New device risk
        existing_sessions = UserSession.objects.filter(
            user=user,
            device_fingerprint=device_info.get('fingerprint', '')
        ).exists()
        
        if not existing_sessions:
            risk_score += 20
        
        # Time-based risk (unusual login hours)
        current_hour = timezone.now().hour
        if current_hour < 6 or current_hour > 23:
            risk_score += 10
        
        # User's historical risk
        risk_score += min(user.risk_score // 2, 20)
        
        return min(risk_score, 100)


class UserLogoutView(APIView):
    """Enhanced user logout with session cleanup."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            # Get current session
            session_key = request.session.session_key
            if session_key:
                try:
                    session = UserSession.objects.get(
                        user=request.user,
                        session_key=session_key,
                        is_active=True
                    )
                    session.terminate_session()
                except UserSession.DoesNotExist:
                    pass
            
            # Log logout activity
            UserActivity.objects.create(
                user=request.user,
                activity_type='logout',
                description=f"User logged out from {get_client_ip(request)}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                location=get_geolocation(get_client_ip(request))
            )
            
            # Django logout
            logout(request)
            
            logger.info(f"User logout: {request.user.email}")
            
            return Response({
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Logout error for {request.user.email}: {e}")
            return Response({
                'error': 'Logout failed'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfileView(generics.RetrieveUpdateAPIView):
    """User profile management with security validation."""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserProfileSerializer
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        
        # Log profile update
        UserActivity.objects.create(
            user=request.user,
            activity_type='profile_update',
            description="User updated profile information",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            location=get_geolocation(get_client_ip(request)),
            metadata={'updated_fields': list(request.data.keys())}
        )
        
        return response


class Enable2FAView(APIView):
    """Enable two-factor authentication."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        
        # Generate 2FA secret if not exists
        if not user.two_factor_secret:
            user.two_factor_secret = pyotp.random_base32()
            user.save(update_fields=['two_factor_secret'])
        
        serializer = Enable2FASerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            # Enable 2FA
            user.two_factor_enabled = True
            backup_codes = user.generate_backup_codes()
            user.save(update_fields=['two_factor_enabled', 'backup_codes'])
            
            # Log 2FA enable
            UserActivity.objects.create(
                user=user,
                activity_type='2fa_enable',
                description="Two-factor authentication enabled",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                location=get_geolocation(get_client_ip(request))
            )
            
            logger.info(f"2FA enabled for user: {user.email}")
            
            return Response({
                'message': '2FA enabled successfully',
                'backup_codes': backup_codes
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Disable2FAView(APIView):
    """Disable two-factor authentication."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        password = request.data.get('password', '')
        
        if not user.check_password(password):
            return Response({
                'error': 'Invalid password'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Disable 2FA
        user.two_factor_enabled = False
        user.two_factor_secret = ''
        user.backup_codes = []
        user.save(update_fields=['two_factor_enabled', 'two_factor_secret', 'backup_codes'])
        
        # Log 2FA disable
        UserActivity.objects.create(
            user=user,
            activity_type='2fa_disable',
            description="Two-factor authentication disabled",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            location=get_geolocation(get_client_ip(request))
        )
        
        logger.info(f"2FA disabled for user: {user.email}")
        
        return Response({
            'message': '2FA disabled successfully'
        }, status=status.HTTP_200_OK)


class UserSessionsView(generics.ListAPIView):
    """List user's active sessions."""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSessionSerializer
    
    def get_queryset(self):
        return UserSession.objects.filter(
            user=self.request.user,
            is_active=True
        ).order_by('-created_at')


class TerminateSessionView(APIView):
    """Terminate a specific user session."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, session_id):
        try:
            session = UserSession.objects.get(
                id=session_id,
                user=request.user,
                is_active=True
            )
            session.terminate_session()
            
            # Log session termination
            UserActivity.objects.create(
                user=request.user,
                activity_type='session_terminate',
                description=f"Session terminated: {session.ip_address}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                location=get_geolocation(get_client_ip(request)),
                metadata={'terminated_session_id': session_id}
            )
            
            return Response({
                'message': 'Session terminated successfully'
            }, status=status.HTTP_200_OK)
            
        except UserSession.DoesNotExist:
            return Response({
                'error': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)


class UserActivityView(generics.ListAPIView):
    """List user's activity history."""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserActivitySerializer
    
    def get_queryset(self):
        return UserActivity.objects.filter(
            user=self.request.user
        ).order_by('-timestamp')[:100]  # Last 100 activities


class PasswordChangeView(APIView):
    """Change user password with enhanced security."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Log password change
            UserActivity.objects.create(
                user=user,
                activity_type='password_change',
                description="Password changed successfully",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                location=get_geolocation(get_client_ip(request))
            )
            
            # Send notification email
            self.send_password_change_notification(user)
            
            logger.info(f"Password changed for user: {user.email}")
            
            return Response({
                'message': 'Password changed successfully'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def send_password_change_notification(self, user):
        """Send password change notification email."""
        try:
            subject = 'Password Changed - CyberDefense Platform'
            html_message = render_to_string('emails/password_changed.html', {
                'user': user,
                'timestamp': timezone.now(),
                'site_name': 'CyberDefense Platform'
            })
            plain_message = strip_tags(html_message)
            
            send_mail(
                subject,
                plain_message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                html_message=html_message,
                fail_silently=True,
            )
        except Exception as e:
            logger.error(f"Failed to send password change notification to {user.email}: {e}")


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def security_dashboard(request):
    """Get user's security dashboard data."""
    user = request.user
    
    # Recent activities
    recent_activities = UserActivity.objects.filter(
        user=user
    ).order_by('-timestamp')[:10]
    
    # Active sessions
    active_sessions = UserSession.objects.filter(
        user=user,
        is_active=True
    ).count()
    
    # Security score calculation
    security_score = 100 - user.risk_score
    
    # Security recommendations
    recommendations = []
    if not user.two_factor_enabled:
        recommendations.append({
            'type': 'warning',
            'message': 'Enable two-factor authentication for better security',
            'action': 'enable_2fa'
        })
    
    if user.risk_score > 50:
        recommendations.append({
            'type': 'danger',
            'message': 'Your account has elevated risk. Review recent activities.',
            'action': 'review_activities'
        })
    
    return Response({
        'security_score': security_score,
        'trust_level': user.trust_level,
        'risk_score': user.risk_score,
        'two_factor_enabled': user.two_factor_enabled,
        'active_sessions': active_sessions,
        'recent_activities': UserActivitySerializer(recent_activities, many=True).data,
        'recommendations': recommendations,
        'last_login': user.last_login,
        'account_age_days': (timezone.now() - user.created_at).days
    })
