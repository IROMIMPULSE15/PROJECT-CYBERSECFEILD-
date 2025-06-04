"""
Security serializers for API endpoints.
"""

from rest_framework import serializers
from .models import (
    SecurityEvent, ThreatIntelligence, IPReputation, WAFRule,
    DDoSProtection, BotDetection, SSLCertificate, SSLVulnerability,
    SSLAuditLog, SSLMetrics, LoadBalancer, LoadBalancerServer,
    PerformanceMetrics, IncidentResponse, ComplianceReport
)


class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = '__all__'


class ThreatIntelligenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatIntelligence
        fields = '__all__'


class IPReputationSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPReputation
        fields = '__all__'


class WAFRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = WAFRule
        fields = '__all__'


class DDoSProtectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = DDoSProtection
        fields = '__all__'


class BotDetectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = BotDetection
        fields = '__all__'


class SSLCertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSLCertificate
        fields = '__all__'


class SSLVulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = SSLVulnerability
        fields = '__all__'


class SSLAuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSLAuditLog
        fields = '__all__'


class SSLMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSLMetrics
        fields = '__all__'


class LoadBalancerSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoadBalancer
        fields = '__all__'


class LoadBalancerServerSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoadBalancerServer
        fields = '__all__'


class PerformanceMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PerformanceMetrics
        fields = '__all__'


class IncidentResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = IncidentResponse
        fields = '__all__'


class ComplianceReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ComplianceReport
        fields = '__all__' 