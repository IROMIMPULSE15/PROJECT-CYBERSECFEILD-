"""
Advanced user account models with comprehensive security features.
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.core.validators import EmailValidator
import uuid
import secrets
import pyotp
from datetime import timedelta


class CustomUser(AbstractUser):
    """Extended user model with advanced security features."""
    
    PLAN_CHOICES = [
        ('basic', 'Basic'),
        ('professional', 'Professional'),
        ('enterprise', 'Enterprise'),
        ('custom', 'Custom'),
    ]
    
    TRUST_LEVEL_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('verified', 'Verified'),
    ]
    
    # Basic information
    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()],
        help_text="User's email address"
    )
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="User's phone number for 2FA"
    )
    
    # Subscription and plan
    plan = models.CharField(
        max_length=20,
        choices=PLAN_CHOICES,
        default='basic',
        help_text="User's subscription plan"
    )
    plan_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the current plan expires"
    )
    
    # Security fields
    is_verified = models.BooleanField(
        default=False,
        help_text="Whether the user's email is verified"
    )
    verification_token = models.UUIDField(
        default=uuid.uuid4,
        help_text="Token for email verification"
    )
    
    # Two-factor authentication
    two_factor_enabled = models.BooleanField(
        default=False,
        help_text="Whether 2FA is enabled"
    )
    two_factor_secret = models.CharField(
        max_length=32,
        blank=True,
        help_text="Secret key for TOTP 2FA"
    )
    backup_codes = models.JSONField(
        default=list,
        help_text="Backup codes for 2FA recovery"
    )
    
    # Account security
    failed_login_attempts = models.PositiveIntegerField(
        default=0,
        help_text="Number of consecutive failed login attempts"
    )
    account_locked_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the account lock expires"
    )
    password_changed_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the password was last changed"
    )
    
    # Trust and risk assessment
    trust_level = models.CharField(
        max_length=10,
        choices=TRUST_LEVEL_CHOICES,
        default='medium',
        help_text="User's trust level based on behavior"
    )
    risk_score = models.PositiveIntegerField(
        default=50,
        help_text="Risk score from 0-100 (higher = more risky)"
    )
    
    # Compliance and legal
    gdpr_consent = models.BooleanField(
        default=False,
        help_text="GDPR consent given"
    )
    gdpr_consent_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When GDPR consent was given"
    )
    terms_accepted_version = models.CharField(
        max_length=10,
        blank=True,
        help_text="Version of terms accepted"
    )
    terms_accepted_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When terms were accepted"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']
    
    class Meta:
        db_table = 'accounts_customuser'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['trust_level']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.email} ({self.get_full_name()})"
    
    def save(self, *args, **kwargs):
        # Generate 2FA secret if enabling 2FA
        if self.two_factor_enabled and not self.two_factor_secret:
            self.two_factor_secret = pyotp.random_base32()
            self.generate_backup_codes()
        
        super().save(*args, **kwargs)
    
    def generate_backup_codes(self, count=10):
        """Generate backup codes for 2FA recovery."""
        self.backup_codes = [secrets.token_hex(4).upper() for _ in range(count)]
        return self.backup_codes
    
    def verify_totp(self, token):
        """Verify TOTP token for 2FA."""
        if not self.two_factor_enabled or not self.two_factor_secret:
            return False
        
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(token, valid_window=1)
    
    def verify_backup_code(self, code):
        """Verify and consume a backup code."""
        if code.upper() in self.backup_codes:
            self.backup_codes.remove(code.upper())
            self.save(update_fields=['backup_codes'])
            return True
        return False
    
    def is_account_locked(self):
        """Check if account is currently locked."""
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        """Lock the account for specified duration."""
        self.account_locked_until = timezone.now() + timedelta(minutes=duration_minutes)
        self.save(update_fields=['account_locked_until'])
    
    def unlock_account(self):
        """Unlock the account and reset failed attempts."""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['account_locked_until', 'failed_login_attempts'])
    
    def increment_failed_login(self):
        """Increment failed login attempts and lock if necessary."""
        self.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.lock_account()
        
        self.save(update_fields=['failed_login_attempts'])
    
    def reset_failed_login(self):
        """Reset failed login attempts on successful login."""
        if self.failed_login_attempts > 0:
            self.failed_login_attempts = 0
            self.save(update_fields=['failed_login_attempts'])
    
    def update_risk_score(self, adjustment):
        """Update user's risk score."""
        self.risk_score = max(0, min(100, self.risk_score + adjustment))
        
        # Update trust level based on risk score
        if self.risk_score <= 20:
            self.trust_level = 'high'
        elif self.risk_score <= 40:
            self.trust_level = 'medium'
        else:
            self.trust_level = 'low'
        
        self.save(update_fields=['risk_score', 'trust_level'])
    
    def get_totp_qr_url(self):
        """Get QR code URL for TOTP setup."""
        if not self.two_factor_secret:
            return None
        
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.provisioning_uri(
            name=self.email,
            issuer_name="CyberDefense Platform"
        )


class UserSession(models.Model):
    """Enhanced session tracking with security features."""
    
    DEVICE_TYPE_CHOICES = [
        ('desktop', 'Desktop'),
        ('mobile', 'Mobile'),
        ('tablet', 'Tablet'),
        ('unknown', 'Unknown'),
    ]
    
    TRUST_LEVEL_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    
    # Session identification
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='sessions'
    )
    session_key = models.CharField(
        max_length=40,
        unique=True,
        help_text="Django session key"
    )
    session_token = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        help_text="Additional session token"
    )
    
    # Connection details
    ip_address = models.GenericIPAddressField(
        help_text="IP address of the session"
    )
    user_agent = models.TextField(
        help_text="User agent string"
    )
    
    # Geographic information
    country = models.CharField(max_length=2, blank=True)
    country_name = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    
    # Device information
    device_type = models.CharField(
        max_length=10,
        choices=DEVICE_TYPE_CHOICES,
        default='unknown'
    )
    device_fingerprint = models.CharField(
        max_length=64,
        help_text="Unique device fingerprint"
    )
    browser_name = models.CharField(max_length=100, blank=True)
    browser_version = models.CharField(max_length=50, blank=True)
    os_name = models.CharField(max_length=100, blank=True)
    os_version = models.CharField(max_length=50, blank=True)
    
    # Session timing
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    
    # Security assessment
    is_active = models.BooleanField(default=True)
    trust_level = models.CharField(
        max_length=10,
        choices=TRUST_LEVEL_CHOICES,
        default='medium'
    )
    risk_score = models.PositiveIntegerField(
        default=50,
        help_text="Session risk score 0-100"
    )
    is_suspicious = models.BooleanField(
        default=False,
        help_text="Flagged as suspicious activity"
    )
    requires_verification = models.BooleanField(
        default=False,
        help_text="Requires additional verification"
    )
    
    class Meta:
        db_table = 'accounts_usersession'
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['created_at']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['is_suspicious']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.email} - {self.ip_address} ({self.created_at})"
    
    def is_expired(self):
        """Check if session is expired."""
        return timezone.now() > self.expires_at
    
    def extend_session(self, hours=1):
        """Extend session expiration."""
        self.expires_at = timezone.now() + timedelta(hours=hours)
        self.save(update_fields=['expires_at'])
    
    def terminate_session(self):
        """Terminate the session."""
        self.is_active = False
        self.ended_at = timezone.now()
        self.save(update_fields=['is_active', 'ended_at'])


class UserActivity(models.Model):
    """Track user activities for security monitoring."""
    
    ACTIVITY_TYPES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('password_change', 'Password Change'),
        ('2fa_enable', '2FA Enable'),
        ('2fa_disable', '2FA Disable'),
        ('profile_update', 'Profile Update'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('security_alert', 'Security Alert'),
    ]
    
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='activities'
    )
    activity_type = models.CharField(
        max_length=20,
        choices=ACTIVITY_TYPES
    )
    description = models.TextField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'accounts_useractivity'
        verbose_name = 'User Activity'
        verbose_name_plural = 'User Activities'
        indexes = [
            models.Index(fields=['user', 'activity_type']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['ip_address']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.user.email} - {self.activity_type} ({self.timestamp})"
