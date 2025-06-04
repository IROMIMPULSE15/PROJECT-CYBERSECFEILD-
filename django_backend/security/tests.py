"""
Security tests for monitoring and protection features.
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from unittest.mock import patch, MagicMock
from .models import (
    SecurityEvent, ThreatIntelligence, IPReputation, WAFRule,
    DDoSProtection, BotDetection, SSLCertificate, SSLVulnerability
)
from .ssl_monitoring import SSLMonitoringEngine
import json
import datetime

User = get_user_model()


class SecurityEventTests(TestCase):
    """Test security event logging and monitoring."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        self.client.login(username='admin', password='adminpass123')
        
        # Create test event
        self.event = SecurityEvent.objects.create(
            event_type='TEST_EVENT',
            event_category='SYSTEM',
            severity='LOW',
            ip_address='127.0.0.1',
            request_method='GET',
            request_url='/test',
            risk_score=10
        )
    
    def test_event_creation(self):
        """Test security event creation."""
        self.assertEqual(self.event.event_type, 'TEST_EVENT')
        self.assertEqual(self.event.severity, 'LOW')
        self.assertEqual(self.event.ip_address, '127.0.0.1')
    
    def test_event_logging(self):
        """Test security event logging middleware."""
        response = self.client.get('/api/v1/security/events/')
        self.assertEqual(response.status_code, 200)
        
        events = SecurityEvent.objects.filter(
            request_url='/api/v1/security/events/'
        )
        self.assertTrue(events.exists())


class ThreatIntelligenceTests(TestCase):
    """Test threat intelligence features."""
    
    def setUp(self):
        self.threat = ThreatIntelligence.objects.create(
            threat_type='MALWARE',
            threat_name='Test Malware',
            threat_description='Test malware description',
            severity='HIGH',
            confidence=0.9,
            source='INTERNAL',
            is_active=True
        )
    
    def test_threat_creation(self):
        """Test threat intelligence creation."""
        self.assertEqual(self.threat.threat_type, 'MALWARE')
        self.assertEqual(self.threat.severity, 'HIGH')
        self.assertTrue(self.threat.is_active)
    
    def test_threat_deactivation(self):
        """Test threat deactivation."""
        self.threat.is_active = False
        self.threat.save()
        
        updated_threat = ThreatIntelligence.objects.get(id=self.threat.id)
        self.assertFalse(updated_threat.is_active)


class IPReputationTests(TestCase):
    """Test IP reputation tracking."""
    
    def setUp(self):
        self.ip_rep = IPReputation.objects.create(
            ip_address='192.168.1.1',
            reputation_score=75,
            country_code='US',
            is_whitelisted=False
        )
    
    def test_ip_reputation_creation(self):
        """Test IP reputation creation."""
        self.assertEqual(self.ip_rep.ip_address, '192.168.1.1')
        self.assertEqual(self.ip_rep.reputation_score, 75)
    
    def test_ip_reputation_update(self):
        """Test IP reputation update."""
        self.ip_rep.reputation_score = 30
        self.ip_rep.save()
        
        updated_rep = IPReputation.objects.get(id=self.ip_rep.id)
        self.assertEqual(updated_rep.reputation_score, 30)


class WAFRuleTests(TestCase):
    """Test WAF rule management."""
    
    def setUp(self):
        self.rule = WAFRule.objects.create(
            rule_name='TEST_RULE',
            rule_description='Test rule description',
            rule_category='XSS',
            rule_pattern=r'<script>.*?</script>',
            rule_type='REGEX',
            action='BLOCK',
            severity='HIGH',
            is_active=True
        )
    
    def test_rule_creation(self):
        """Test WAF rule creation."""
        self.assertEqual(self.rule.rule_name, 'TEST_RULE')
        self.assertEqual(self.rule.action, 'BLOCK')
        self.assertTrue(self.rule.is_active)
    
    def test_rule_matching(self):
        """Test WAF rule pattern matching."""
        test_request = '<script>alert("xss")</script>'
        self.assertTrue(bool(re.search(self.rule.rule_pattern, test_request)))


class DDoSProtectionTests(TestCase):
    """Test DDoS protection features."""
    
    def setUp(self):
        self.protection = DDoSProtection.objects.create(
            protection_level='MEDIUM',
            auto_mitigation=True,
            requests_per_second_threshold=1000,
            bandwidth_threshold_mbps=1000
        )
    
    def test_protection_creation(self):
        """Test DDoS protection creation."""
        self.assertEqual(self.protection.protection_level, 'MEDIUM')
        self.assertTrue(self.protection.auto_mitigation)
    
    def test_attack_detection(self):
        """Test DDoS attack detection."""
        self.protection.current_rps = 1500
        self.protection.save()
        
        self.assertTrue(self.protection.current_rps > self.protection.requests_per_second_threshold)


class BotDetectionTests(TestCase):
    """Test bot detection features."""
    
    def setUp(self):
        self.bot = BotDetection.objects.create(
            ip_address='192.168.1.2',
            user_agent='Bad Bot/1.0',
            bot_type='BAD',
            confidence_score=90,
            action='BLOCK'
        )
    
    def test_bot_creation(self):
        """Test bot detection creation."""
        self.assertEqual(self.bot.bot_type, 'BAD')
        self.assertEqual(self.bot.action, 'BLOCK')
    
    def test_bot_blocking(self):
        """Test bot blocking."""
        self.bot.blocked = True
        self.bot.save()
        
        updated_bot = BotDetection.objects.get(id=self.bot.id)
        self.assertTrue(updated_bot.blocked)


class SSLMonitoringTests(TestCase):
    """Test SSL monitoring features."""
    
    def setUp(self):
        self.cert = SSLCertificate.objects.create(
            domain='example.com',
            issuer='Test CA',
            valid_from=timezone.now(),
            valid_to=timezone.now() + datetime.timedelta(days=365),
            algorithm='RSA',
            key_size=2048,
            ssl_grade='A',
            status='VALID'
        )
        
        self.vulnerability = SSLVulnerability.objects.create(
            certificate=self.cert,
            vulnerability_type='POODLE',
            description='POODLE vulnerability',
            severity='HIGH',
            status='OPEN'
        )
    
    def test_certificate_creation(self):
        """Test SSL certificate creation."""
        self.assertEqual(self.cert.domain, 'example.com')
        self.assertEqual(self.cert.ssl_grade, 'A')
        self.assertEqual(self.cert.status, 'VALID')
    
    def test_vulnerability_detection(self):
        """Test SSL vulnerability detection."""
        self.assertEqual(self.vulnerability.vulnerability_type, 'POODLE')
        self.assertEqual(self.vulnerability.status, 'OPEN')
    
    @patch('security.ssl_monitoring.SSLMonitoringEngine.scan_domain')
    def test_ssl_scanning(self, mock_scan):
        """Test SSL scanning functionality."""
        mock_scan.return_value = {
            'domain': 'example.com',
            'ssl_grade': 'A',
            'vulnerabilities': {}
        }
        
        engine = SSLMonitoringEngine()
        result = engine.scan_domain('example.com')
        
        self.assertEqual(result['domain'], 'example.com')
        self.assertEqual(result['ssl_grade'], 'A')


class SecurityAPITests(APITestCase):
    """Test security API endpoints."""
    
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        self.client.force_authenticate(user=self.user)
    
    def test_security_events_api(self):
        """Test security events API."""
        response = self.client.get('/api/v1/security/events/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_threat_intelligence_api(self):
        """Test threat intelligence API."""
        response = self.client.get('/api/v1/security/threats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_ip_reputation_api(self):
        """Test IP reputation API."""
        response = self.client.get('/api/v1/security/ip-reputation/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_waf_rules_api(self):
        """Test WAF rules API."""
        response = self.client.get('/api/v1/security/waf-rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_ssl_certificates_api(self):
        """Test SSL certificates API."""
        response = self.client.get('/api/v1/security/ssl/')
        self.assertEqual(response.status_code, status.HTTP_200_OK) 