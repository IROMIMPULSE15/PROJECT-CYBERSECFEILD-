from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.core.cache import cache
from .models import SSLCertificate, SSLVulnerability, SSLAuditLog, SSLMetrics
from .tasks import scan_ssl_certificate, generate_ssl_report
from .ssl_config import SSL_CONFIG
import logging

logger = logging.getLogger('ssl_monitoring')

class SSLMonitoringViewSet(viewsets.ModelViewSet):
    """ViewSet for SSL monitoring operations."""
    permission_classes = [IsAuthenticated]
    queryset = SSLCertificate.objects.all()

    @action(detail=False, methods=['post'])
    def scan_domain(self, request):
        """Trigger SSL scan for a domain."""
        try:
            domain = request.data.get('domain')
            port = request.data.get('port', 443)

            if not domain:
                return Response(
                    {'error': 'Domain is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Trigger async scan
            task = scan_ssl_certificate.delay(domain, port)

            return Response({
                'message': f'SSL scan initiated for {domain}',
                'task_id': task.id
            })

        except Exception as e:
            logger.error(f"Scan request failed: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def dashboard_stats(self, request):
        """Get SSL monitoring dashboard statistics."""
        try:
            # Try to get cached report
            report = cache.get('ssl_latest_report')
            if not report:
                # Generate new report
                report = generate_ssl_report.delay().get()

            return Response(report)

        except Exception as e:
            logger.error(f"Dashboard stats failed: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['get'])
    def certificate_details(self, request, pk=None):
        """Get detailed information about a certificate."""
        try:
            certificate = self.get_object()
            
            # Get related data
            vulnerabilities = SSLVulnerability.objects.filter(
                certificate=certificate,
                status='OPEN'
            )
            
            metrics = SSLMetrics.objects.filter(
                certificate=certificate
            ).order_by('-timestamp')[:10]
            
            audit_logs = SSLAuditLog.objects.filter(
                certificate=certificate
            ).order_by('-timestamp')[:10]

            return Response({
                'certificate': {
                    'domain': certificate.domain,
                    'issuer': certificate.issuer,
                    'valid_from': certificate.valid_from,
                    'valid_to': certificate.valid_to,
                    'status': certificate.status,
                    'ssl_grade': certificate.ssl_grade,
                },
                'vulnerabilities': [
                    {
                        'type': v.vulnerability_type,
                        'severity': v.severity,
                        'description': v.description,
                        'detected_at': v.detected_at
                    } for v in vulnerabilities
                ],
                'metrics': [
                    {
                        'type': m.metric_type,
                        'value': m.value,
                        'unit': m.unit,
                        'timestamp': m.timestamp
                    } for m in metrics
                ],
                'audit_logs': [
                    {
                        'event_type': l.event_type,
                        'description': l.description,
                        'timestamp': l.timestamp
                    } for l in audit_logs
                ]
            })

        except Exception as e:
            logger.error(f"Certificate details failed: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def vulnerability_summary(self, request):
        """Get summary of SSL vulnerabilities."""
        try:
            now = timezone.now()
            summary = {
                'total_vulnerabilities': SSLVulnerability.objects.filter(
                    status='OPEN'
                ).count(),
                'by_severity': {
                    'critical': SSLVulnerability.objects.filter(
                        status='OPEN',
                        severity='CRITICAL'
                    ).count(),
                    'high': SSLVulnerability.objects.filter(
                        status='OPEN',
                        severity='HIGH'
                    ).count(),
                    'medium': SSLVulnerability.objects.filter(
                        status='OPEN',
                        severity='MEDIUM'
                    ).count(),
                    'low': SSLVulnerability.objects.filter(
                        status='OPEN',
                        severity='LOW'
                    ).count(),
                },
                'recent_detections': SSLVulnerability.objects.filter(
                    detected_at__gte=now - timezone.timedelta(days=7)
                ).count(),
                'by_type': {}
            }

            # Count vulnerabilities by type
            vulns_by_type = SSLVulnerability.objects.filter(
                status='OPEN'
            ).values('vulnerability_type').distinct()
            
            for vuln in vulns_by_type:
                vuln_type = vuln['vulnerability_type']
                count = SSLVulnerability.objects.filter(
                    status='OPEN',
                    vulnerability_type=vuln_type
                ).count()
                summary['by_type'][vuln_type] = count

            return Response(summary)

        except Exception as e:
            logger.error(f"Vulnerability summary failed: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def expiring_certificates(self, request):
        """Get list of expiring certificates."""
        try:
            warning_days = SSL_CONFIG['monitoring']['expiry_warning_days']
            now = timezone.now()
            
            expiring_certs = SSLCertificate.objects.filter(
                valid_to__gt=now,
                valid_to__lte=now + timezone.timedelta(days=warning_days)
            ).order_by('valid_to')

            return Response([
                {
                    'domain': cert.domain,
                    'valid_to': cert.valid_to,
                    'days_remaining': (cert.valid_to - now).days,
                    'ssl_grade': cert.ssl_grade,
                    'status': cert.status
                } for cert in expiring_certs
            ])

        except Exception as e:
            logger.error(f"Expiring certificates check failed: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            ) 