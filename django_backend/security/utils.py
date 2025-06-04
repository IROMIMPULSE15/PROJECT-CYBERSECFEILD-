"""
Security utility functions for the cybersecurity platform.
"""

import re
import socket
import ipaddress
from typing import Dict, List, Optional, Union
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
import requests
import hashlib
import logging
from user_agents import parse

logger = logging.getLogger('security')

def get_geolocation(ip_address: str) -> Dict:
    """Get geolocation information for an IP address."""
    try:
        # Try to get from cache first
        cache_key = f"geolocation:{ip_address}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        # If not in cache, use a free IP geolocation service
        response = requests.get(f"https://ipapi.co/{ip_address}/json/")
        if response.status_code == 200:
            data = response.json()
            geo_data = {
                'country': data.get('country_name', ''),
                'country_code': data.get('country_code', ''),
                'region': data.get('region', ''),
                'city': data.get('city', ''),
                'latitude': data.get('latitude', 0),
                'longitude': data.get('longitude', 0),
                'timezone': data.get('timezone', ''),
                'isp': data.get('org', '')
            }
            # Cache for 24 hours
            cache.set(cache_key, geo_data, 86400)
            return geo_data
    except Exception as e:
        logger.error(f"Error getting geolocation for IP {ip_address}: {str(e)}")
    
    return {
        'country': '',
        'country_code': '',
        'region': '',
        'city': '',
        'latitude': 0,
        'longitude': 0,
        'timezone': '',
        'isp': ''
    }

def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))

def get_client_ip(request) -> str:
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_request_fingerprint(request) -> Dict:
    """Generate a fingerprint from request headers."""
    headers = request.META
    fingerprint = {
        'user_agent': headers.get('HTTP_USER_AGENT', ''),
        'accept_language': headers.get('HTTP_ACCEPT_LANGUAGE', ''),
        'accept_encoding': headers.get('HTTP_ACCEPT_ENCODING', ''),
        'accept': headers.get('HTTP_ACCEPT', ''),
        'connection': headers.get('HTTP_CONNECTION', ''),
        'host': headers.get('HTTP_HOST', ''),
        'referer': headers.get('HTTP_REFERER', ''),
        'origin': headers.get('HTTP_ORIGIN', ''),
        'ip': get_client_ip(request)
    }
    return fingerprint

def calculate_threat_score(indicators: Dict) -> int:
    """Calculate threat score based on various indicators."""
    score = 0
    weights = {
        'ip_reputation': 30,
        'domain_reputation': 25,
        'request_pattern': 20,
        'payload_analysis': 15,
        'historical_data': 10
    }
    
    for key, weight in weights.items():
        if key in indicators:
            score += indicators[key] * weight / 100
    
    return min(100, max(0, int(score)))

def hash_content(content: Union[str, bytes]) -> str:
    """Generate SHA-256 hash of content."""
    if isinstance(content, str):
        content = content.encode()
    return hashlib.sha256(content).hexdigest()

def is_request_rate_limited(request, key_prefix: str, limit: int, period: int) -> bool:
    """Check if request is rate limited."""
    client_ip = get_client_ip(request)
    cache_key = f"{key_prefix}:{client_ip}"
    
    try:
        request_count = cache.get(cache_key, 0)
        if request_count >= limit:
            return True
        
        cache.set(cache_key, request_count + 1, period)
        return False
    except Exception as e:
        logger.error(f"Rate limiting error: {str(e)}")
        return False

def analyze_request_payload(request) -> Dict:
    """Analyze request payload for potential threats."""
    analysis = {
        'contains_script': False,
        'contains_sql': False,
        'contains_path_traversal': False,
        'contains_command_injection': False,
        'risk_level': 'low'
    }
    
    # Get request data
    data = {}
    if request.method == 'GET':
        data = request.GET.dict()
    elif request.method in ['POST', 'PUT', 'PATCH']:
        data = request.POST.dict()
        if not data and request.content_type == 'application/json':
            try:
                data = request.json()
            except:
                pass
    
    # Check for common attack patterns
    patterns = {
        'script': r'<script|javascript:|vbscript:|onload=|onerror=',
        'sql': r'UNION.*SELECT|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM',
        'path': r'\.\./|\.\.|/etc/passwd|/etc/shadow',
        'command': r';\s*\w+|`.*`|\|\s*\w+|\$\(.*\)'
    }
    
    for key, value in data.items():
        if isinstance(value, str):
            if re.search(patterns['script'], value, re.I):
                analysis['contains_script'] = True
            if re.search(patterns['sql'], value, re.I):
                analysis['contains_sql'] = True
            if re.search(patterns['path'], value):
                analysis['contains_path_traversal'] = True
            if re.search(patterns['command'], value):
                analysis['contains_command_injection'] = True
    
    # Calculate risk level
    risk_score = sum([
        analysis['contains_script'],
        analysis['contains_sql'],
        analysis['contains_path_traversal'],
        analysis['contains_command_injection']
    ])
    
    if risk_score >= 2:
        analysis['risk_level'] = 'high'
    elif risk_score == 1:
        analysis['risk_level'] = 'medium'
    
    return analysis

def get_device_info(request) -> Dict:
    """Get device information from user agent string."""
    try:
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse(user_agent_string)
        
        device_info = {
            'browser': {
                'family': user_agent.browser.family,
                'version': user_agent.browser.version_string,
            },
            'os': {
                'family': user_agent.os.family,
                'version': user_agent.os.version_string,
            },
            'device': {
                'family': user_agent.device.family,
                'brand': user_agent.device.brand,
                'model': user_agent.device.model,
            },
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'is_bot': user_agent.is_bot,
            'raw_string': user_agent_string
        }
        return device_info
    except Exception as e:
        logger.error(f"Error getting device info: {str(e)}")
        return {
            'browser': {'family': 'Unknown', 'version': ''},
            'os': {'family': 'Unknown', 'version': ''},
            'device': {'family': 'Unknown', 'brand': '', 'model': ''},
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': False,
            'is_bot': False,
            'raw_string': ''
        } 