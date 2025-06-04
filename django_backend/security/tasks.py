from celery import shared_task
from django.utils import timezone
from django.core.cache import cache
from .models import SSLCertificate, SSLVulnerability, SSLAuditLog, SSLMetrics
from .ssl_monitoring import SSLMonitoringEngine
from .ssl_config import SSL_CONFIG
import logging
import asyncio

logger = logging.getLogger('ssl_monitoring')

@shared_task(bind=True, max_retries=3)
def scan_ssl_certificate(self, domain, port=443):
    """Task to scan a single SSL certificate."""
    try:
        ssl_monitor = SSLMonitoringEngine()
        # Run async scan in event loop
        loop = asyncio.get_event_loop()
        scan_results = loop.run_until_complete(ssl_monitor.scan_domain(domain, port))
        
        # Update or create certificate record
        cert_info = scan_results['certificate_info']
        certificate, created = SSLCertificate.objects.update_or_create(
            domain=domain,
            defaults={
                'issuer': cert_info['issuer'],
                'subject': cert_info['subject'],
                'valid_from': cert_info['not_valid_before'],
                'valid_to': cert_info['not_valid_after'],
                'algorithm': cert_info['signature_algorithm'],
                'key_size': cert_info['public_key_size'],
                'san_domains': cert_info['san_domains'],
                'ssl_grade': scan_results['ssl_grade'],
                'vulnerabilities': scan_results['vulnerabilities'],
                'status': 'EXPIRED' if cert_info['is_expired'] else 'VALID'
            }
        )

        # Record vulnerabilities
        for vuln_name, vuln_info in scan_results['vulnerabilities'].items():
            if vuln_info['vulnerable']:
                SSLVulnerability.objects.create(
                    certificate=certificate,
                    vulnerability_type=vuln_name,
                    description=vuln_info['description'],
                    severity='HIGH' if vuln_name in ['heartbleed', 'poodle'] else 'MEDIUM',
                    status='OPEN'
                )

        # Record metrics
        for metric_name, value in scan_results['performance_metrics'].items():
            SSLMetrics.objects.create(
                certificate=certificate,
                metric_type=metric_name,
                value=value,
                unit='ms' if 'time' in metric_name else 'count'
            )

        # Audit logging
        SSLAuditLog.objects.create(
            certificate=certificate,
            event_type='SSL_SCAN',
            description=f'SSL scan completed for {domain}',
            new_value=scan_results
        )

        # Cache results
        cache_key = f"ssl_scan_{domain}_{port}"
        cache.set(cache_key, scan_results, SSL_CONFIG['cache']['timeout'])

        return True

    except Exception as e:
        logger.error(f"SSL scan failed for {domain}: {str(e)}")
        raise self.retry(exc=e)

@shared_task
def check_certificates_expiry():
    """Task to check for expiring certificates."""
    try:
        warning_days = SSL_CONFIG['monitoring']['expiry_warning_days']
        critical_days = SSL_CONFIG['monitoring']['critical_warning_days']
        now = timezone.now()

        # Check for expiring certificates
        expiring_certs = SSLCertificate.objects.filter(
            valid_to__gt=now,
            valid_to__lte=now + timezone.timedelta(days=warning_days)
        )

        for cert in expiring_certs:
            days_remaining = (cert.valid_to - now).days
            severity = 'CRITICAL' if days_remaining <= critical_days else 'HIGH'
            
            SSLAuditLog.objects.create(
                certificate=cert,
                event_type='CERTIFICATE_EXPIRING',
                description=f'Certificate expiring in {days_remaining} days',
                severity=severity
            )

        return True

    except Exception as e:
        logger.error(f"Certificate expiry check failed: {str(e)}")
        return False

@shared_task
def cleanup_old_records():
    """Task to clean up old SSL records."""
    try:
        retention_days = SSL_CONFIG['reporting']['retention_days']
        cutoff_date = timezone.now() - timezone.timedelta(days=retention_days)

        # Clean up old audit logs
        SSLAuditLog.objects.filter(timestamp__lt=cutoff_date).delete()

        # Clean up old metrics
        SSLMetrics.objects.filter(timestamp__lt=cutoff_date).delete()

        # Clean up resolved vulnerabilities
        SSLVulnerability.objects.filter(
            status='RESOLVED',
            resolved_at__lt=cutoff_date
        ).delete()

        return True

    except Exception as e:
        logger.error(f"Cleanup task failed: {str(e)}")
        return False

@shared_task
def generate_ssl_report():
    """Task to generate SSL security report."""
    try:
        now = timezone.now()
        report_data = {
            'timestamp': now.isoformat(),
            'certificates': {
                'total': SSLCertificate.objects.count(),
                'valid': SSLCertificate.objects.filter(status='VALID').count(),
                'expired': SSLCertificate.objects.filter(status='EXPIRED').count(),
                'expiring_soon': SSLCertificate.objects.filter(
                    valid_to__gt=now,
                    valid_to__lte=now + timezone.timedelta(days=30)
                ).count()
            },
            'vulnerabilities': {
                'total': SSLVulnerability.objects.filter(status='OPEN').count(),
                'high': SSLVulnerability.objects.filter(status='OPEN', severity='HIGH').count(),
                'medium': SSLVulnerability.objects.filter(status='OPEN', severity='MEDIUM').count(),
                'low': SSLVulnerability.objects.filter(status='OPEN', severity='LOW').count()
            },
            'grades': {
                'a_plus': SSLCertificate.objects.filter(ssl_grade='A+').count(),
                'a': SSLCertificate.objects.filter(ssl_grade='A').count(),
                'b': SSLCertificate.objects.filter(ssl_grade='B').count(),
                'c': SSLCertificate.objects.filter(ssl_grade='C').count(),
                'd': SSLCertificate.objects.filter(ssl_grade='D').count(),
                'f': SSLCertificate.objects.filter(ssl_grade='F').count()
            }
        }

        # Cache the report
        cache.set('ssl_latest_report', report_data, 86400)  # Cache for 24 hours
        return report_data

    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return None 