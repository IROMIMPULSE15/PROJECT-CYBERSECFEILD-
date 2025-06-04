import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberdefense.settings')

app = Celery('cyberdefense')

# Load task modules from all registered Django app configs
app.config_from_object('django.conf:settings', namespace='CELERY')

# Configure Celery beat schedule
app.conf.beat_schedule = {
    'scan-ssl-certificates': {
        'task': 'security.tasks.scan_ssl_certificate',
        'schedule': crontab(hour='*/6'),  # Every 6 hours
    },
    'check-certificates-expiry': {
        'task': 'security.tasks.check_certificates_expiry',
        'schedule': crontab(hour='0', minute='0'),  # Daily at midnight
    },
    'cleanup-old-records': {
        'task': 'security.tasks.cleanup_old_records',
        'schedule': crontab(hour='1', minute='0'),  # Daily at 1 AM
    },
    'generate-ssl-report': {
        'task': 'security.tasks.generate_ssl_report',
        'schedule': crontab(hour='*/12'),  # Every 12 hours
    },
}

# Auto-discover tasks in all installed apps
app.autodiscover_tasks() 