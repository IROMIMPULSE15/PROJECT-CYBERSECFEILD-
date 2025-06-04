"""
Security middleware for threat detection and monitoring.
"""

import json
import time
import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.gis.geoip2 import GeoIP2
from django.core.cache import cache
from django.conf import settings
from accounts.models import UserActivity
from .models import SecurityEvent, ThreatIntelligence
from .utils import get_client_ip, detect_sql_injection, detect_xss, calculate_risk_score
import re
import hashlib

logger = logging.getLogger('security')


class SecurityEventMiddleware(MiddlewareMixin):
    """Middleware to log security events and monitor threats."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.suspicious_patterns = [
            r'(\.\./|\.\.\\)',  # Directory traversal
            r'(union|select|insert|delete|update|drop|create|alter)',  # SQL injection
            r'<script[^>]*>.*?</script>',  # XSS
            r'(eval|exec|system|shell_exec)',  # Code injection
            r'(\||;|&|`|\$\()',  # Command injection
        ]
        super().__init__(get_response)
    
    def __call__(self, request):
        start_time = time.time()
        
        # Process request
        response = self.get_response(request)
        
        # Calculate response time
        response_time = int((time.time() - start_time) * 1000)
        
        # Log security event
        self.log_security_event(request, response, response_time)
        
        return response
    
    def log_security_event(self, request, response, response_time):
        """Log security events for analysis."""
        try:
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            request_url = request.get_full_path()
            
            # Calculate risk score
            risk_score = self.calculate_request_risk(request)
            
            # Determine event type and severity
            event_type, severity = self.classify_request(request, response, risk_score)
            
            # Create security event
            SecurityEvent.objects.create(
                event_type=event_type,
                event_category=self.get_event_category(event_type),
                severity=severity,
                ip_address=ip_address,
                user_agent=user_agent,
                request_method=request.method,
                request_url=request_url,
                request_headers=dict(request.headers),
                request_body=self.get_safe_request_body(request),
                response_status=response.status_code,
                response_time_ms=response_time,
                user_id=request.user.id if request.user.is_authenticated else None,
                risk_score=risk_score,
                blocked=response.status_code == 403,
                details={
                    'content_length': len(getattr(response, 'content', b'')),
                    'referer': request.META.get('HTTP_REFERER', ''),
                    'query_params': dict(request.GET),
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    def calculate_request_risk(self, request):
        """Calculate risk score for the request."""
        risk_score = 0
        
        # Check for suspicious patterns in URL
        url = request.get_full_path()
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                risk_score += 25
        
        # Check request body for threats
        if hasattr(request, 'body') and request.body:
            body_str = request.body.decode('utf-8', errors='ignore')
            if detect_sql_injection(body_str):
                risk_score += 30
            if detect_xss(body_str):
                risk_score += 25
        
        # Check user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        if not user_agent or len(user_agent) < 10:
            risk_score += 15
        
        # Check for bot patterns
        bot_patterns = ['bot', 'crawler', 'spider', 'scraper']
        if any(pattern in user_agent.lower() for pattern in bot_patterns):
            risk_score += 20
        
        return min(risk_score, 100)
    
    def classify_request(self, request, response, risk_score):
        """Classify request and determine event type and severity."""
        if response.status_code >= 500:
            return 'SERVER_ERROR', 'HIGH'
        elif response.status_code == 403:
            return 'ACCESS_DENIED', 'MEDIUM'
        elif response.status_code == 404:
            return 'NOT_FOUND', 'LOW'
        elif risk_score > 70:
            return 'HIGH_RISK_REQUEST', 'CRITICAL'
        elif risk_score > 40:
            return 'SUSPICIOUS_REQUEST', 'MEDIUM'
        elif request.path.startswith('/admin/'):
            return 'ADMIN_ACCESS', 'MEDIUM'
        elif request.path.startswith('/api/'):
            return 'API_REQUEST', 'LOW'
        else:
            return 'NORMAL_REQUEST', 'LOW'
    
    def get_event_category(self, event_type):
        """Get event category based on event type."""
        categories = {
            'HIGH_RISK_REQUEST': 'ATTACK',
            'SUSPICIOUS_REQUEST': 'ANOMALY',
            'ACCESS_DENIED': 'AUTHORIZATION',
            'ADMIN_ACCESS': 'AUTHENTICATION',
            'API_REQUEST': 'SYSTEM',
            'SERVER_ERROR': 'SYSTEM',
            'NOT_FOUND': 'SYSTEM',
            'NORMAL_REQUEST': 'SYSTEM',
        }
        return categories.get(event_type, 'SYSTEM')
    
    def get_safe_request_body(self, request):
        """Get request body safely for logging."""
        try:
            if hasattr(request, 'body') and request.body:
                body_str = request.body.decode('utf-8', errors='ignore')
                # Limit body size for storage
                if len(body_str) > 5000:
                    body_str = body_str[:5000] + '...[truncated]'
                return json.loads(body_str) if body_str.startswith('{') else body_str
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        return None


class ThreatDetectionMiddleware(MiddlewareMixin):
    """Advanced threat detection and blocking middleware."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.blocked_ips = cache.get('blocked_ips', set())
        self.rate_limit_cache = {}
        super().__init__(get_response)
    
    def __call__(self, request):
        # Check if IP is blocked
        ip_address = get_client_ip(request)
        if self.is_ip_blocked(ip_address):
            return self.block_request(request, 'IP_BLOCKED')
        
        # Check rate limiting
        if self.is_rate_limited(request):
            return self.block_request(request, 'RATE_LIMITED')
        
        # Check for known threats
        if self.is_known_threat(request):
            return self.block_request(request, 'KNOWN_THREAT')
        
        # Advanced threat detection
        threat_detected = self.detect_advanced_threats(request)
        if threat_detected:
            return self.block_request(request, threat_detected)
        
        response = self.get_response(request)
        
        # Update rate limiting counters
        self.update_rate_limit(request)
        
        return response
    
    def is_ip_blocked(self, ip_address):
        """Check if IP address is blocked."""
        return ip_address in self.blocked_ips
    
    def is_rate_limited(self, request):
        """Check if request should be rate limited."""
        ip_address = get_client_ip(request)
        current_time = int(time.time())
        
        # Get rate limit data for IP
        ip_data = self.rate_limit_cache.get(ip_address, {
            'requests': 0,
            'window_start': current_time
        })
        
        # Reset window if needed (1 minute window)
        if current_time - ip_data['window_start'] >= 60:
            ip_data = {'requests': 0, 'window_start': current_time}
        
        # Check limits based on endpoint
        max_requests = self.get_rate_limit(request)
        return ip_data['requests'] >= max_requests
    
    def get_rate_limit(self, request):
        """Get rate limit for the request."""
        if request.path.startswith('/api/auth/login'):
            return 5  # 5 login attempts per minute
        elif request.path.startswith('/api/auth/register'):
            return 3  # 3 registrations per minute
        elif request.path.startswith('/api/'):
            return 100  # 100 API requests per minute
        else:
            return 200  # 200 general requests per minute
    
    def update_rate_limit(self, request):
        """Update rate limiting counters."""
        ip_address = get_client_ip(request)
        current_time = int(time.time())
        
        ip_data = self.rate_limit_cache.get(ip_address, {
            'requests': 0,
            'window_start': current_time
        })
        
        # Reset window if needed
        if current_time - ip_data['window_start'] >= 60:
            ip_data = {'requests': 1, 'window_start': current_time}
        else:
            ip_data['requests'] += 1
        
        self.rate_limit_cache[ip_address] = ip_data
    
    def is_known_threat(self, request):
        """Check against threat intelligence database."""
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Check IP reputation
        threat_intel = ThreatIntelligence.objects.filter(
            ip_addresses__contains=ip_address,
            is_active=True
        ).first()
        
        if threat_intel:
            return True
        
        # Check user agent patterns
        malicious_ua_patterns = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zap',
            'burp', 'w3af', 'acunetix', 'netsparker'
        ]
        
        for pattern in malicious_ua_patterns:
            if pattern in user_agent.lower():
                return True
        
        return False
    
    def detect_advanced_threats(self, request):
        """Detect advanced threats using ML and heuristics."""
        threats = []
        
        # Path traversal detection
        if self.detect_path_traversal(request):
            threats.append('PATH_TRAVERSAL')
        
        # SQL injection detection
        if self.detect_sql_injection_advanced(request):
            threats.append('SQL_INJECTION')
        
        # XSS detection
        if self.detect_xss_advanced(request):
            threats.append('XSS_ATTACK')
        
        # Command injection detection
        if self.detect_command_injection(request):
            threats.append('COMMAND_INJECTION')
        
        # File upload threats
        if self.detect_malicious_upload(request):
            threats.append('MALICIOUS_UPLOAD')
        
        return threats[0] if threats else None
    
    def detect_path_traversal(self, request):
        """Detect path traversal attempts."""
        traversal_patterns = [
            r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
            r'%252e%252e%252f', r'%c0%ae%c0%ae%c0%af'
        ]
        
        url = request.get_full_path()
        for pattern in traversal_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False
    
    def detect_sql_injection_advanced(self, request):
        """Advanced SQL injection detection."""
        sql_patterns = [
            r"('|(\\')|(;|(\s*;\s*))|(--)|(/\*.*\*/))",
            r"((\s+)or(\s+).*=.*)|((\s+)or(\s+).*<.*)|((\s+)or(\s+).*>.*)|((\s+)or(\s+).*\sis\s*.*)|((\s+)or(\s+).*\s(not\s+)?like\s*.*)",
            r"(union\s*select)|(union\s*all\s*select)",
            r"(insert\s+into)|(delete\s+from)|(update\s+.+\s+set)|(create\s+table)|(drop\s+table)|(alter\s+table)",
            r"(exec(\s|\+)+(s|x)p\w+)|(sp_\w+)"
        ]
        
        # Check URL parameters
        for param, value in request.GET.items():
            for pattern in sql_patterns:
                if re.search(pattern, str(value), re.IGNORECASE):
                    return True
        
        # Check POST data
        if hasattr(request, 'POST'):
            for param, value in request.POST.items():
                for pattern in sql_patterns:
                    if re.search(pattern, str(value), re.IGNORECASE):
                        return True
        
        return False
    
    def detect_xss_advanced(self, request):
        """Advanced XSS detection."""
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
            r'<style[^>]*>.*?</style>',
            r'expression\s*\(',
            r'url\s*\(',
            r'@import'
        ]
        
        # Check all request data
        all_data = []
        all_data.extend(request.GET.values())
        if hasattr(request, 'POST'):
            all_data.extend(request.POST.values())
        
        for value in all_data:
            for pattern in xss_patterns:
                if re.search(pattern, str(value), re.IGNORECASE):
                    return True
        
        return False
    
    def detect_command_injection(self, request):
        """Detect command injection attempts."""
        cmd_patterns = [
            r';.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
            r'\|.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
            r'&.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
            r'`.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
            r'\$\(.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
            r'(nc|netcat|ncat).*?-[lp]',
            r'/bin/(sh|bash|csh|tcsh|zsh)',
            r'cmd\.exe',
            r'powershell\.exe'
        ]
        
        # Check all request data
        all_data = []
        all_data.extend(request.GET.values())
        if hasattr(request, 'POST'):
            all_data.extend(request.POST.values())
        
        for value in all_data:
            for pattern in cmd_patterns:
                if re.search(pattern, str(value), re.IGNORECASE):
                    return True
        
        return False
    
    def detect_malicious_upload(self, request):
        """Detect malicious file uploads."""
        if request.method != 'POST':
            return False
        
        dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr',
            '.vbs', '.js', '.jar', '.php', '.asp', '.aspx',
            '.jsp', '.pl', '.py', '.rb', '.sh', '.ps1'
        ]
        
        for file_field in request.FILES.values():
            filename = file_field.name.lower()
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    return True
        
        return False
    
    def block_request(self, request, reason):
        """Block request and log the event."""
        ip_address = get_client_ip(request)
        
        # Add IP to blocked list temporarily
        self.blocked_ips.add(ip_address)
        cache.set('blocked_ips', self.blocked_ips, 3600)  # Block for 1 hour
        
        # Log security event
        SecurityEvent.objects.create(
            event_type=f'BLOCKED_{reason}',
            event_category='ATTACK',
            severity='CRITICAL',
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            request_method=request.method,
            request_url=request.get_full_path(),
            request_headers=dict(request.headers),
            blocked=True,
            action_taken=f'Request blocked: {reason}',
            risk_score=100,
            details={'block_reason': reason}
        )
        
        logger.warning(f"Blocked request from {ip_address}: {reason}")
        
        return JsonResponse({
            'error': 'Request blocked by security policy',
            'reason': reason,
            'timestamp': time.time()
        }, status=403)


class IPReputationMiddleware(MiddlewareMixin):
    """Middleware to check IP reputation and geographic restrictions."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.high_risk_countries = getattr(settings, 'SECURITY_SETTINGS', {}).get(
            'HIGH_RISK_COUNTRIES', []
        )
        super().__init__(get_response)
    
    def __call__(self, request):
        ip_address = get_client_ip(request)
        
        # Check IP reputation
        if self.is_high_risk_ip(ip_address):
            return self.handle_high_risk_ip(request, ip_address)
        
        # Check geographic restrictions
        if self.is_restricted_country(ip_address):
            return self.handle_restricted_country(request, ip_address)
        
        return self.get_response(request)
    
    def is_high_risk_ip(self, ip_address):
        """Check if IP has poor reputation."""
        # Check cache first
        cache_key = f'ip_reputation_{ip_address}'
        reputation = cache.get(cache_key)
        
        if reputation is None:
            # Check database
            from .models import IPReputation
            try:
                ip_rep = IPReputation.objects.get(ip_address=ip_address)
                reputation = ip_rep.reputation_score
                cache.set(cache_key, reputation, 3600)  # Cache for 1 hour
            except IPReputation.DoesNotExist:
                reputation = 50  # Neutral score
                cache.set(cache_key, reputation, 3600)
        
        return reputation < 30  # Consider below 30 as high risk
    
    def is_restricted_country(self, ip_address):
        """Check if IP is from a restricted country."""
        try:
            g = GeoIP2()
            country_code = g.country_code(ip_address)
            return country_code in self.high_risk_countries
        except Exception:
            return False
    
    def handle_high_risk_ip(self, request, ip_address):
        """Handle requests from high-risk IPs."""
        logger.warning(f"High-risk IP detected: {ip_address}")
        
        # Log security event
        SecurityEvent.objects.create(
            event_type='HIGH_RISK_IP',
            event_category='ANOMALY',
            severity='HIGH',
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            request_method=request.method,
            request_url=request.get_full_path(),
            details={'reason': 'High-risk IP reputation'},
            risk_score=80
        )
        
        # Apply additional scrutiny but don't block entirely
        request.security_context = getattr(request, 'security_context', {})
        request.security_context['high_risk_ip'] = True
        
        return self.get_response(request)
    
    def handle_restricted_country(self, request, ip_address):
        """Handle requests from restricted countries."""
        try:
            g = GeoIP2()
            country = g.country(ip_address)
            country_name = country.get('country_name', 'Unknown')
        except Exception:
            country_name = 'Unknown'
        
        logger.warning(f"Request from restricted country: {country_name} ({ip_address})")
        
        # Log security event
        SecurityEvent.objects.create(
            event_type='RESTRICTED_COUNTRY',
            event_category='ANOMALY',
            severity='MEDIUM',
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            request_method=request.method,
            request_url=request.get_full_path(),
            details={'country': country_name},
            risk_score=60
        )
        
        # For high-security endpoints, block completely
        if request.path.startswith('/admin/') or request.path.startswith('/api/admin/'):
            return JsonResponse({
                'error': 'Access denied from your location',
                'country': country_name
            }, status=403)
        
        # For other endpoints, add to security context
        request.security_context = getattr(request, 'security_context', {})
        request.security_context['restricted_country'] = True
        
        return self.get_response(request)
