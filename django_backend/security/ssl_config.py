from django.conf import settings

# SSL Monitoring Configuration
SSL_CONFIG = {
    'monitoring': {
        'interval': getattr(settings, 'SSL_MONITORING_INTERVAL', 3600),  # Default 1 hour
        'grade_threshold': getattr(settings, 'SSL_GRADE_THRESHOLD', 'B'),
        'expiry_warning_days': getattr(settings, 'SSL_EXPIRY_WARNING_DAYS', 30),
        'critical_warning_days': getattr(settings, 'SSL_CRITICAL_WARNING_DAYS', 7),
    },
    'alerts': {
        'enabled': getattr(settings, 'SSL_ALERTS_ENABLED', True),
        'email': getattr(settings, 'SSL_ALERT_EMAIL', None),
        'slack_webhook': getattr(settings, 'SSL_SLACK_WEBHOOK', None),
        'alert_levels': {
            'CRITICAL': ['ssl_expiry_critical', 'vulnerability_critical', 'grade_f'],
            'HIGH': ['ssl_expiry_warning', 'vulnerability_high', 'grade_d'],
            'MEDIUM': ['vulnerability_medium', 'grade_c'],
            'LOW': ['vulnerability_low'],
        }
    },
    'security': {
        'min_key_size': {
            'RSA': 2048,
            'ECDSA': 256,
            'DSA': 2048,
        },
        'allowed_protocols': ['TLSv1.2', 'TLSv1.3'],
        'forbidden_protocols': ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
        'recommended_ciphers': [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
        ],
    },
    'performance': {
        'handshake_timeout': 10,  # seconds
        'connection_timeout': 5,   # seconds
        'max_redirects': 5,
        'verify_hostname': True,
        'verify_cert': True,
    },
    'cache': {
        'enabled': True,
        'timeout': 3600,  # 1 hour
        'prefix': 'ssl_monitor_',
    },
    'reporting': {
        'enabled': True,
        'retention_days': 90,
        'max_reports': 1000,
        'formats': ['json', 'pdf', 'csv'],
    },
    'compliance': {
        'check_pci_dss': True,
        'check_hipaa': True,
        'check_gdpr': True,
        'check_nist': True,
    }
} 