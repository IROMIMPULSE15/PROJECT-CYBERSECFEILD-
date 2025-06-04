"""
Security models for monitoring and protection features.
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import JSONField, ArrayField
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid
from datetime import datetime, timedelta
from django.utils import timezone

User = get_user_model()


class SecurityEvent(models.Model):
    """Security event model for logging security-related events."""
    
    event_type = models.CharField(max_length=100)
    event_category = models.CharField(max_length=50)
    severity = models.CharField(max_length=20)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    request_method = models.CharField(max_length=10, null=True, blank=True)
    request_url = models.URLField(max_length=2048, null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    details = models.JSONField(default=dict)
    timestamp = models.DateTimeField(default=timezone.now)
    risk_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        default=0
    )
    blocked = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return f"{self.event_type} - {self.severity} - {self.timestamp}"


class ThreatIntelligence(models.Model):
    """Threat intelligence data model."""
    
    threat_type = models.CharField(max_length=50)
    threat_name = models.CharField(max_length=255)
    threat_description = models.TextField()
    severity = models.CharField(max_length=20)
    confidence = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    source = models.CharField(max_length=100)
    indicators = models.JSONField(default=list)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['threat_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.threat_name} ({self.threat_type})"


class IPReputation(models.Model):
    """IP address reputation tracking model."""
    
    ip_address = models.GenericIPAddressField(unique=True)
    reputation_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    country_code = models.CharField(max_length=2, blank=True)
    organization = models.CharField(max_length=255, blank=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_seen_malicious = models.DateTimeField(null=True, blank=True)
    is_whitelisted = models.BooleanField(default=False)
    threat_types = models.JSONField(default=list)

    class Meta:
        ordering = ['reputation_score']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['reputation_score']),
            models.Index(fields=['country_code']),
        ]

    def __str__(self):
        return f"{self.ip_address} (Score: {self.reputation_score})"


class WAFRule(models.Model):
    """Web Application Firewall rule model."""
    
    rule_name = models.CharField(max_length=255, unique=True)
    rule_description = models.TextField()
    rule_category = models.CharField(max_length=50)
    rule_pattern = models.TextField()
    rule_type = models.CharField(max_length=20)
    action = models.CharField(max_length=20)
    severity = models.CharField(max_length=20)
    is_active = models.BooleanField(default=True)
    is_custom = models.BooleanField(default=False)
    priority = models.IntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['priority']
        indexes = [
            models.Index(fields=['rule_category']),
            models.Index(fields=['severity']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.rule_name} ({self.rule_category})"


class DDoSProtection(models.Model):
    """DDoS protection configuration and monitoring model."""
    
    protection_level = models.CharField(max_length=20)
    auto_mitigation = models.BooleanField(default=True)
    attack_detected = models.BooleanField(default=False)
    attack_type = models.CharField(max_length=50, blank=True)
    current_rps = models.IntegerField(default=0)
    current_bandwidth_mbps = models.FloatField(default=0.0)
    current_connections = models.IntegerField(default=0)
    requests_per_second_threshold = models.IntegerField(default=1000)
    bandwidth_threshold_mbps = models.IntegerField(default=1000)
    last_attack = models.DateTimeField(null=True, blank=True)
    mitigation_methods = models.JSONField(default=list)

    def __str__(self):
        return f"DDoS Protection ({self.protection_level})"


class BotDetection(models.Model):
    """Bot detection and management model."""
    
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    bot_type = models.CharField(max_length=20)
    confidence_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    action = models.CharField(max_length=20)
    blocked = models.BooleanField(default=False)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(auto_now=True)
    request_count = models.IntegerField(default=1)
    characteristics = models.JSONField(default=dict)

    class Meta:
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['bot_type']),
            models.Index(fields=['blocked']),
        ]

    def __str__(self):
        return f"{self.ip_address} ({self.bot_type})"


class SSLCertificate(models.Model):
    """SSL/TLS certificate management."""
    
    CERTIFICATE_TYPES = [
        ('DV', 'Domain Validated'),
        ('OV', 'Organization Validated'),
        ('EV', 'Extended Validation'),
        ('WILDCARD', 'Wildcard'),
        ('MULTI_DOMAIN', 'Multi-Domain'),
    ]
    
    STATUS_CHOICES = [
        ('VALID', 'Valid'),
        ('EXPIRED', 'Expired'),
        ('EXPIRING_SOON', 'Expiring Soon'),
        ('INVALID', 'Invalid'),
        ('REVOKED', 'Revoked'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Certificate details
    domain = models.CharField(max_length=255, db_index=True)
    san_domains = models.JSONField()
    issuer = models.CharField(max_length=255)
    subject = models.TextField()
    
    # Certificate properties
    certificate_type = models.CharField(max_length=15, choices=CERTIFICATE_TYPES)
    algorithm = models.CharField(max_length=100)
    key_size = models.IntegerField()
    signature_algorithm = models.CharField(max_length=50)
    
    # Validity
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField(db_index=True)
    status = models.CharField(max_length=20, db_index=True)
    
    # Certificate data
    certificate_pem = models.TextField()
    private_key_pem = models.TextField(blank=True)  # Encrypted storage recommended
    certificate_chain = models.TextField(blank=True)
    
    # Management
    auto_renewal = models.BooleanField(default=True)
    last_renewed = models.DateTimeField(null=True, blank=True)
    renewal_attempts = models.IntegerField(default=0)
    
    # Security assessment
    ssl_grade = models.CharField(max_length=2, db_index=True)
    vulnerabilities = models.JSONField()
    
    # Timing
    last_scan = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'ssl_certificates'
        indexes = [
            models.Index(fields=['domain', 'status']),
            models.Index(fields=['valid_to', 'status']),
        ]


class SSLVulnerability(models.Model):
    certificate = models.ForeignKey(SSLCertificate, on_delete=models.CASCADE, related_name='vulnerability_records')
    vulnerability_type = models.CharField(max_length=50)
    description = models.TextField()
    severity = models.CharField(max_length=20)
    detected_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default='OPEN')

    class Meta:
        indexes = [
            models.Index(fields=['vulnerability_type', 'status']),
        ]


class SSLAuditLog(models.Model):
    certificate = models.ForeignKey(SSLCertificate, on_delete=models.CASCADE, related_name='audit_logs')
    event_type = models.CharField(max_length=50)
    description = models.TextField()
    old_value = models.JSONField(null=True)
    new_value = models.JSONField(null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.CharField(max_length=100, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
        ]


class SSLMetrics(models.Model):
    certificate = models.ForeignKey(SSLCertificate, on_delete=models.CASCADE, related_name='metrics')
    metric_type = models.CharField(max_length=50)
    value = models.FloatField()
    unit = models.CharField(max_length=20)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['metric_type', 'timestamp']),
        ]


class LoadBalancer(models.Model):
    """Load balancer configuration and health monitoring."""
    
    ALGORITHMS = [
        ('ROUND_ROBIN', 'Round Robin'),
        ('LEAST_CONNECTIONS', 'Least Connections'),
        ('WEIGHTED_ROUND_ROBIN', 'Weighted Round Robin'),
        ('IP_HASH', 'IP Hash'),
        ('GEOGRAPHIC', 'Geographic'),
    ]
    
    HEALTH_STATUS = [
        ('HEALTHY', 'Healthy'),
        ('DEGRADED', 'Degraded'),
        ('UNHEALTHY', 'Unhealthy'),
        ('MAINTENANCE', 'Maintenance'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    
    # Configuration
    algorithm = models.CharField(max_length=20, choices=ALGORITHMS, default='ROUND_ROBIN')
    session_affinity = models.BooleanField(default=False)
    
    # Health checking
    health_check_enabled = models.BooleanField(default=True)
    health_check_url = models.URLField(blank=True)
    health_check_interval = models.IntegerField(default=30)  # seconds
    health_check_timeout = models.IntegerField(default=5)  # seconds
    health_check_retries = models.IntegerField(default=3)
    
    # Status
    status = models.CharField(max_length=15, choices=HEALTH_STATUS, default='HEALTHY')
    active_servers = models.IntegerField(default=0)
    total_servers = models.IntegerField(default=0)
    
    # Performance metrics
    requests_per_second = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    average_response_time = models.IntegerField(default=0)  # milliseconds
    error_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)  # percentage
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'load_balancers'


class LoadBalancerServer(models.Model):
    """Individual servers in load balancer pools."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    load_balancer = models.ForeignKey(LoadBalancer, on_delete=models.CASCADE, related_name='servers')
    
    # Server details
    name = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    port = models.IntegerField()
    weight = models.IntegerField(default=100)
    
    # Status
    status = models.CharField(max_length=15, choices=LoadBalancer.HEALTH_STATUS, default='HEALTHY')
    enabled = models.BooleanField(default=True)
    
    # Health metrics
    last_health_check = models.DateTimeField(null=True, blank=True)
    consecutive_failures = models.IntegerField(default=0)
    response_time = models.IntegerField(default=0)  # milliseconds
    
    # Performance metrics
    active_connections = models.IntegerField(default=0)
    total_requests = models.BigIntegerField(default=0)
    failed_requests = models.BigIntegerField(default=0)
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'load_balancer_servers'
        unique_together = ['load_balancer', 'ip_address', 'port']


class PerformanceMetrics(models.Model):
    """System performance metrics collection."""
    
    METRIC_TYPES = [
        ('CPU', 'CPU Usage'),
        ('MEMORY', 'Memory Usage'),
        ('DISK', 'Disk Usage'),
        ('NETWORK', 'Network Traffic'),
        ('RESPONSE_TIME', 'Response Time'),
        ('THROUGHPUT', 'Throughput'),
        ('ERROR_RATE', 'Error Rate'),
        ('AVAILABILITY', 'Availability'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Metric identification
    metric_type = models.CharField(max_length=20, choices=METRIC_TYPES)
    metric_name = models.CharField(max_length=255)
    
    # Metric data
    value = models.DecimalField(max_digits=15, decimal_places=4)
    unit = models.CharField(max_length=20)  # %, ms, MB/s, etc.
    
    # Context
    server_id = models.CharField(max_length=255, blank=True)
    service_name = models.CharField(max_length=255, blank=True)
    
    # Additional data
    tags = JSONField(default=dict)
    metadata = JSONField(default=dict)
    
    # Timing
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'performance_metrics'
        indexes = [
            models.Index(fields=['metric_type']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['server_id']),
        ]


class IncidentResponse(models.Model):
    """Incident response and management."""
    
    INCIDENT_TYPES = [
        ('DDOS', 'DDoS Attack'),
        ('DATA_BREACH', 'Data Breach'),
        ('MALWARE', 'Malware Detection'),
        ('UNAUTHORIZED_ACCESS', 'Unauthorized Access'),
        ('SYSTEM_COMPROMISE', 'System Compromise'),
        ('SERVICE_OUTAGE', 'Service Outage'),
        ('PERFORMANCE_DEGRADATION', 'Performance Degradation'),
        ('SECURITY_VIOLATION', 'Security Policy Violation'),
    ]
    
    SEVERITY_LEVELS = [
        ('P1', 'Critical - Service Down'),
        ('P2', 'High - Major Impact'),
        ('P3', 'Medium - Minor Impact'),
        ('P4', 'Low - Minimal Impact'),
    ]
    
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Investigating'),
        ('IDENTIFIED', 'Identified'),
        ('MONITORING', 'Monitoring'),
        ('RESOLVED', 'Resolved'),
        ('CLOSED', 'Closed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Incident details
    title = models.CharField(max_length=255)
    description = models.TextField()
    incident_type = models.CharField(max_length=25, choices=INCIDENT_TYPES)
    severity = models.CharField(max_length=2, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='OPEN')
    
    # Assignment
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    team = models.CharField(max_length=100, blank=True)
    
    # Impact assessment
    affected_services = ArrayField(models.CharField(max_length=100), default=list, blank=True)
    affected_users = models.IntegerField(default=0)
    estimated_impact = models.TextField(blank=True)
    
    # Timeline
    detected_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    
    # Response actions
    actions_taken = JSONField(default=list)
    mitigation_steps = JSONField(default=list)
    
    # Root cause analysis
    root_cause = models.TextField(blank=True)
    lessons_learned = models.TextField(blank=True)
    
    # Related data
    related_events = ArrayField(models.UUIDField(), default=list, blank=True)
    external_references = JSONField(default=list)
    
    class Meta:
        db_table = 'incident_response'
        indexes = [
            models.Index(fields=['incident_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['detected_at']),
        ]


class ComplianceReport(models.Model):
    """Compliance monitoring and reporting."""
    
    COMPLIANCE_FRAMEWORKS = [
        ('PCI_DSS', 'PCI DSS'),
        ('HIPAA', 'HIPAA'),
        ('GDPR', 'GDPR'),
        ('SOX', 'Sarbanes-Oxley'),
        ('ISO_27001', 'ISO 27001'),
        ('NIST', 'NIST Framework'),
        ('SOC2', 'SOC 2'),
        ('FedRAMP', 'FedRAMP'),
    ]
    
    STATUS_CHOICES = [
        ('COMPLIANT', 'Compliant'),
        ('NON_COMPLIANT', 'Non-Compliant'),
        ('PARTIAL', 'Partially Compliant'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Report details
    framework = models.CharField(max_length=15, choices=COMPLIANCE_FRAMEWORKS)
    report_period_start = models.DateTimeField()
    report_period_end = models.DateTimeField()
    
    # Compliance status
    overall_status = models.CharField(max_length=15, choices=STATUS_CHOICES)
    compliance_score = models.DecimalField(max_digits=5, decimal_places=2)  # Percentage
    
    # Requirements assessment
    total_requirements = models.IntegerField()
    compliant_requirements = models.IntegerField()
    non_compliant_requirements = models.IntegerField()
    
    # Detailed findings
    findings = JSONField(default=list)
    recommendations = JSONField(default=list)
    
    # Report metadata
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    
    # File attachments
    report_file = models.FileField(upload_to='compliance_reports/', blank=True)
    
    class Meta:
        db_table = 'compliance_reports'
        indexes = [
            models.Index(fields=['framework']),
            models.Index(fields=['overall_status']),
            models.Index(fields=['generated_at']),
        ]
