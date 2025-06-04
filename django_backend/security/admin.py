"""
Admin configuration for security models.
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import (
    SecurityEvent, ThreatIntelligence, IPReputation, WAFRule,
    DDoSProtection, BotDetection, SSLCertificate, SSLVulnerability,
    SSLAuditLog, SSLMetrics, LoadBalancer, LoadBalancerServer,
    PerformanceMetrics, IncidentResponse, ComplianceReport
)


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'event_category', 'severity', 'ip_address', 'timestamp', 'risk_score', 'blocked')
    list_filter = ('event_category', 'severity', 'blocked', 'timestamp')
    search_fields = ('ip_address', 'event_type', 'request_url')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)


@admin.register(ThreatIntelligence)
class ThreatIntelligenceAdmin(admin.ModelAdmin):
    list_display = ('threat_type', 'threat_name', 'severity', 'confidence', 'is_active')
    list_filter = ('threat_type', 'severity', 'is_active')
    search_fields = ('threat_name', 'threat_description')
    ordering = ('-first_seen',)


@admin.register(IPReputation)
class IPReputationAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reputation_score', 'country_code', 'is_whitelisted')
    list_filter = ('is_whitelisted', 'country_code')
    search_fields = ('ip_address', 'organization')
    ordering = ('reputation_score',)


@admin.register(WAFRule)
class WAFRuleAdmin(admin.ModelAdmin):
    list_display = ('rule_name', 'rule_category', 'action', 'severity', 'is_active')
    list_filter = ('rule_category', 'action', 'severity', 'is_active')
    search_fields = ('rule_name', 'rule_description')
    ordering = ('priority',)


@admin.register(DDoSProtection)
class DDoSProtectionAdmin(admin.ModelAdmin):
    list_display = ('protection_level', 'attack_detected', 'current_rps', 'current_bandwidth_mbps')
    list_filter = ('protection_level', 'attack_detected')
    readonly_fields = ('current_rps', 'current_bandwidth_mbps', 'current_connections')


@admin.register(BotDetection)
class BotDetectionAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'bot_type', 'confidence_score', 'action', 'blocked')
    list_filter = ('bot_type', 'action', 'blocked')
    search_fields = ('ip_address', 'user_agent')
    ordering = ('-first_seen',)


@admin.register(SSLCertificate)
class SSLCertificateAdmin(admin.ModelAdmin):
    list_display = ('domain', 'issuer', 'valid_from', 'valid_to', 'ssl_grade', 'status')
    list_filter = ('ssl_grade', 'status', 'certificate_type')
    search_fields = ('domain', 'issuer')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('valid_to',)


@admin.register(SSLVulnerability)
class SSLVulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('certificate', 'vulnerability_type', 'severity', 'status')
    list_filter = ('vulnerability_type', 'severity', 'status')
    search_fields = ('certificate__domain', 'description')
    ordering = ('-detected_at',)


@admin.register(SSLAuditLog)
class SSLAuditLogAdmin(admin.ModelAdmin):
    list_display = ('certificate', 'event_type', 'timestamp')
    list_filter = ('event_type', 'timestamp')
    search_fields = ('certificate__domain', 'description')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)


@admin.register(SSLMetrics)
class SSLMetricsAdmin(admin.ModelAdmin):
    list_display = ('certificate', 'metric_type', 'value', 'unit', 'timestamp')
    list_filter = ('metric_type', 'unit')
    search_fields = ('certificate__domain',)
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)


@admin.register(LoadBalancer)
class LoadBalancerAdmin(admin.ModelAdmin):
    list_display = ('name', 'algorithm', 'status', 'active_servers', 'total_servers')
    list_filter = ('algorithm', 'status', 'session_affinity')
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')


@admin.register(LoadBalancerServer)
class LoadBalancerServerAdmin(admin.ModelAdmin):
    list_display = ('name', 'load_balancer', 'ip_address', 'port', 'status', 'enabled')
    list_filter = ('status', 'enabled')
    search_fields = ('name', 'ip_address')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(PerformanceMetrics)
class PerformanceMetricsAdmin(admin.ModelAdmin):
    list_display = ('metric_type', 'metric_name', 'value', 'unit', 'timestamp')
    list_filter = ('metric_type', 'unit')
    search_fields = ('metric_name', 'server_id')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)


@admin.register(IncidentResponse)
class IncidentResponseAdmin(admin.ModelAdmin):
    list_display = ('title', 'incident_type', 'severity', 'status', 'detected_at')
    list_filter = ('incident_type', 'severity', 'status')
    search_fields = ('title', 'description')
    readonly_fields = ('detected_at',)
    ordering = ('-detected_at',)


@admin.register(ComplianceReport)
class ComplianceReportAdmin(admin.ModelAdmin):
    list_display = ('framework', 'overall_status', 'compliance_score', 'report_period_start', 'report_period_end')
    list_filter = ('framework', 'overall_status')
    search_fields = ('framework',)
    readonly_fields = ('generated_at',)
    ordering = ('-report_period_end',) 