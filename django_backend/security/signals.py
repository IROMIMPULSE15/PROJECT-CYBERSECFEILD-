"""
Security signals for event handling.
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.cache import cache
from django.utils import timezone
from .models import (
    SecurityEvent, ThreatIntelligence, IPReputation, WAFRule,
    DDoSProtection, BotDetection, SSLCertificate, SSLVulnerability
)
import logging

logger = logging.getLogger('security')


@receiver(post_save, sender=SecurityEvent)
def handle_security_event(sender, instance, created, **kwargs):
    """Handle security event creation."""
    if created:
        # Update threat intelligence
        if instance.event_category == 'ATTACK':
            ThreatIntelligence.objects.get_or_create(
                threat_type='ATTACK',
                threat_name=instance.event_type,
                defaults={
                    'threat_description': instance.details.get('description', ''),
                    'severity': instance.severity,
                    'confidence': 0.8,
                    'source': 'INTERNAL',
                    'is_active': True
                }
            )

        # Update IP reputation
        IPReputation.objects.update_or_create(
            ip_address=instance.ip_address,
            defaults={
                'last_seen_malicious': timezone.now() if instance.risk_score > 70 else None,
                'risk_score': instance.risk_score
            }
        )

        # Clear relevant caches
        cache.delete(f'security_events_{instance.ip_address}')
        cache.delete('security_stats')


@receiver(post_save, sender=ThreatIntelligence)
def handle_threat_intelligence_update(sender, instance, created, **kwargs):
    """Handle threat intelligence updates."""
    # Update WAF rules if needed
    if instance.is_active and instance.confidence > 0.7:
        WAFRule.objects.get_or_create(
            rule_name=f'AUTO_{instance.threat_type}_{instance.id}',
            defaults={
                'rule_description': instance.threat_description,
                'rule_category': instance.threat_type,
                'severity': instance.severity,
                'action': 'BLOCK' if instance.severity in ['CRITICAL', 'HIGH'] else 'LOG',
                'is_active': True,
                'is_custom': False
            }
        )

    # Clear threat intelligence cache
    cache.delete('threat_intelligence_data')


@receiver(post_save, sender=IPReputation)
def handle_ip_reputation_update(sender, instance, created, **kwargs):
    """Handle IP reputation updates."""
    # Update blocked IPs cache if needed
    if instance.reputation_score < 30 and not instance.is_whitelisted:
        blocked_ips = cache.get('blocked_ips', set())
        blocked_ips.add(instance.ip_address)
        cache.set('blocked_ips', blocked_ips, 3600)  # Cache for 1 hour

    # Clear IP reputation cache
    cache.delete(f'ip_reputation_{instance.ip_address}')


@receiver(post_save, sender=DDoSProtection)
def handle_ddos_protection_update(sender, instance, created, **kwargs):
    """Handle DDoS protection updates."""
    if instance.attack_detected:
        # Create security event
        SecurityEvent.objects.create(
            event_type='DDOS_ATTACK',
            event_category='ATTACK',
            severity='CRITICAL',
            details={
                'attack_type': instance.attack_type,
                'rps': instance.current_rps,
                'bandwidth': instance.current_bandwidth_mbps
            }
        )

    # Update protection status cache
    cache.set('ddos_protection_status', {
        'level': instance.protection_level,
        'under_attack': instance.attack_detected,
        'rps': instance.current_rps,
        'bandwidth': instance.current_bandwidth_mbps
    }, 300)  # Cache for 5 minutes


@receiver(post_save, sender=BotDetection)
def handle_bot_detection(sender, instance, created, **kwargs):
    """Handle bot detection updates."""
    if instance.bot_type == 'BAD' and instance.confidence_score > 80:
        # Create security event
        SecurityEvent.objects.create(
            event_type='BOT_DETECTED',
            event_category='BOT',
            severity='HIGH',
            ip_address=instance.ip_address,
            details={
                'bot_type': instance.bot_type,
                'confidence': instance.confidence_score,
                'user_agent': instance.user_agent
            }
        )

    # Update bot detection cache
    cache.set(f'bot_detection_{instance.ip_address}', {
        'type': instance.bot_type,
        'confidence': instance.confidence_score,
        'blocked': instance.blocked
    }, 1800)  # Cache for 30 minutes


@receiver(post_save, sender=SSLCertificate)
def handle_ssl_certificate_update(sender, instance, created, **kwargs):
    """Handle SSL certificate updates."""
    # Check for certificate expiry
    if instance.status == 'EXPIRED':
        SecurityEvent.objects.create(
            event_type='SSL_CERTIFICATE_EXPIRED',
            event_category='SSL',
            severity='HIGH',
            details={
                'domain': instance.domain,
                'expired_at': instance.valid_to.isoformat()
            }
        )

    # Clear SSL certificate cache
    cache.delete(f'ssl_certificate_{instance.domain}')


@receiver(post_save, sender=SSLVulnerability)
def handle_ssl_vulnerability(sender, instance, created, **kwargs):
    """Handle SSL vulnerability detection."""
    if created:
        SecurityEvent.objects.create(
            event_type='SSL_VULNERABILITY_DETECTED',
            event_category='SSL',
            severity=instance.severity,
            details={
                'domain': instance.certificate.domain,
                'vulnerability_type': instance.vulnerability_type,
                'description': instance.description
            }
        )

    # Clear vulnerability cache
    cache.delete(f'ssl_vulnerabilities_{instance.certificate.domain}') 