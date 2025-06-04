"""
Serializers for user account management with advanced security features.
"""

from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import CustomUser, UserSession, UserActivity
import pyotp
import qrcode
import io
import base64


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration with enhanced security."""
    
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=CustomUser.objects.all())]
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    password_confirm = serializers.CharField(write_only=True, required=True)
    gdpr_consent = serializers.BooleanField(required=True)
    terms_accepted_version = serializers.CharField(required=True)
    
    class Meta:
        model = CustomUser
        fields = (
            'email', 'password', 'password_confirm', 'first_name', 'last_name',
            'phone_number', 'plan', 'gdpr_consent', 'terms_accepted_version'
        )
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        
        if not attrs.get('gdpr_consent', False):
            raise serializers.ValidationError(
                {"gdpr_consent": "GDPR consent is required."}
            )
        
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm', None)
        
        user = CustomUser.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone_number=validated_data.get('phone_number', ''),
            plan=validated_data.get('plan', 'basic'),
            gdpr_consent=validated_data['gdpr_consent'],
            gdpr_consent_date=timezone.now(),
            terms_accepted_version=validated_data['terms_accepted_version'],
            terms_accepted_date=timezone.now(),
        )
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login with 2FA support."""
    
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)
    totp_token = serializers.CharField(required=False, allow_blank=True)
    remember_me = serializers.BooleanField(default=False)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        totp_token = attrs.get('totp_token', '')
        
        if email and password:
            # Get user
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                raise serializers.ValidationError(
                    'Invalid credentials.'
                )
            
            # Check if account is locked
            if user.is_account_locked():
                raise serializers.ValidationError(
                    'Account is temporarily locked due to multiple failed login attempts.'
                )
            
            # Authenticate user
            user = authenticate(username=email, password=password)
            if not user:
                # Increment failed attempts for existing user
                try:
                    existing_user = CustomUser.objects.get(email=email)
                    existing_user.increment_failed_login()
                except CustomUser.DoesNotExist:
                    pass
                
                raise serializers.ValidationError(
                    'Invalid credentials.'
                )
            
            # Check if user is active
            if not user.is_active:
                raise serializers.ValidationError(
                    'User account is disabled.'
                )
            
            # Check 2FA if enabled
            if user.two_factor_enabled:
                if not totp_token:
                    raise serializers.ValidationError(
                        'Two-factor authentication code is required.'
                    )
                
                if not user.verify_totp(totp_token):
                    raise serializers.ValidationError(
                        'Invalid two-factor authentication code.'
                    )
            
            # Reset failed login attempts on successful login
            user.reset_failed_login()
            attrs['user'] = user
            
        else:
            raise serializers.ValidationError(
                'Must include email and password.'
            )
        
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile management."""
    
    email = serializers.EmailField(read_only=True)
    two_factor_qr_code = serializers.SerializerMethodField()
    backup_codes = serializers.ListField(read_only=True)
    
    class Meta:
        model = CustomUser
        fields = (
            'id', 'email', 'first_name', 'last_name', 'phone_number',
            'plan', 'plan_expires_at', 'is_verified', 'two_factor_enabled',
            'two_factor_qr_code', 'backup_codes', 'trust_level', 'risk_score',
            'created_at', 'updated_at', 'last_login'
        )
        read_only_fields = (
            'id', 'plan_expires_at', 'trust_level', 'risk_score',
            'created_at', 'updated_at', 'last_login'
        )
    
    def get_two_factor_qr_code(self, obj):
        """Generate QR code for 2FA setup."""
        if not obj.two_factor_secret:
            return None
        
        qr_url = obj.get_totp_qr_url()
        if not qr_url:
            return None
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{qr_code_data}"


class Enable2FASerializer(serializers.Serializer):
    """Serializer for enabling 2FA."""
    
    totp_token = serializers.CharField(required=True)
    
    def validate_totp_token(self, value):
        user = self.context['request'].user
        
        if not user.two_factor_secret:
            raise serializers.ValidationError(
                "2FA secret not generated. Please refresh and try again."
            )
        
        totp = pyotp.TOTP(user.two_factor_secret)
        if not totp.verify(value, valid_window=1):
            raise serializers.ValidationError(
                "Invalid TOTP token."
            )
        
        return value


class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for user session information."""
    
    user_email = serializers.CharField(source='user.email', read_only=True)
    is_current = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = (
            'id', 'user_email', 'ip_address', 'country_name', 'city',
            'device_type', 'browser_name', 'os_name', 'created_at',
            'last_activity', 'expires_at', 'is_active', 'trust_level',
            'risk_score', 'is_suspicious', 'is_current'
        )
        read_only_fields = fields
    
    def get_is_current(self, obj):
        """Check if this is the current session."""
        request = self.context.get('request')
        if request and hasattr(request, 'session'):
            return obj.session_key == request.session.session_key
        return False


class UserActivitySerializer(serializers.ModelSerializer):
    """Serializer for user activity logs."""
    
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = UserActivity
        fields = (
            'id', 'user_email', 'activity_type', 'description',
            'ip_address', 'location', 'timestamp', 'metadata'
        )
        read_only_fields = fields


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""
    
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password]
    )
    new_password_confirm = serializers.CharField(required=True)
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError(
                {"new_password": "Password fields didn't match."}
            )
        return attrs
    
    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.password_changed_at = timezone.now()
        user.save()
        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request."""
    
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        try:
            user = CustomUser.objects.get(email=value)
            if not user.is_active:
                raise serializers.ValidationError(
                    "User account is disabled."
                )
        except CustomUser.DoesNotExist:
            # Don't reveal if email exists or not
            pass
        
        return value


class SecuritySettingsSerializer(serializers.ModelSerializer):
    """Serializer for user security settings."""
    
    class Meta:
        model = CustomUser
        fields = (
            'two_factor_enabled', 'phone_number', 'trust_level',
            'risk_score', 'failed_login_attempts', 'account_locked_until'
        )
        read_only_fields = (
            'trust_level', 'risk_score', 'failed_login_attempts',
            'account_locked_until'
        )
