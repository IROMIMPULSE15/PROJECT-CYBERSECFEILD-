"""
Core views for the CyberDefense platform.
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

@require_http_methods(["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
def handler404(request, exception=None):
    """Handle 404 Not Found errors."""
    return JsonResponse({
        'error': 'Not Found',
        'message': 'The requested resource was not found.',
        'status_code': 404
    }, status=404)

@require_http_methods(["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
def handler500(request, exception=None):
    """Handle 500 Internal Server Error."""
    return JsonResponse({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred.',
        'status_code': 500
    }, status=500) 