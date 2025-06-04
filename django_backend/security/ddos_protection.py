"""
Advanced DDoS Protection System
"""

import asyncio
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from django.core.cache import cache
from django.conf import settings
from django.http import JsonResponse
from .models import SecurityEvent, DDoSProtection, IPReputation
from .utils import get_client_ip, get_geo_info
import threading
import queue
import statistics

logger = logging.getLogger('ddos_protection')


class DDoSProtectionEngine:
    """Advanced DDoS protection engine with multiple detection methods."""
    
    def __init__(self):
        self.request_tracker = defaultdict(deque)
        self.connection_tracker = defaultdict(int)
        self.bandwidth_tracker = defaultdict(deque)
        self.attack_patterns = {}
        self.mitigation_active = False
        self.protection_config = self.load_protection_config()
        
        # Rate limiting windows
        self.rate_windows = {
            'second': 1,
            'minute': 60,
            'hour': 3600,
        }
        
        # Attack detection thresholds
        self.thresholds = {
            'requests_per_second': 100,
            'requests_per_minute': 1000,
            'bandwidth_mbps': 100,
            'connections_per_ip': 50,
            'new_connections_per_second': 20,
        }
        
        # Start background monitoring
        self.start_monitoring()
    
    def load_protection_config(self):
        """Load DDoS protection configuration."""
        try:
            config = DDoSProtection.objects.first()
            if not config:
                config = DDoSProtection.objects.create()
            return config
        except Exception as e:
            logger.error(f"Failed to load DDoS protection config: {e}")
            return None
    
    def analyze_request(self, request):
        """Analyze incoming request for DDoS patterns."""
        ip_address = get_client_ip(request)
        current_time = time.time()
        
        # Track request
        self.track_request(ip_address, current_time, request)
        
        # Analyze patterns
        threat_score = self.calculate_threat_score(ip_address, request)
        
        # Check if mitigation should be triggered
        if threat_score > 70:
            return self.trigger_mitigation(ip_address, request, threat_score)
        
        return {'allowed': True, 'threat_score': threat_score}
    
    def track_request(self, ip_address, timestamp, request):
        """Track request for pattern analysis."""
        # Track requests per IP
        self.request_tracker[ip_address].append(timestamp)
        
        # Clean old entries (keep last 5 minutes)
        cutoff_time = timestamp - 300
        while (self.request_tracker[ip_address] and 
               self.request_tracker[ip_address][0] < cutoff_time):
            self.request_tracker[ip_address].popleft()
        
        # Track bandwidth (estimate)
        content_length = int(request.META.get('CONTENT_LENGTH', 0))
        self.bandwidth_tracker[ip_address].append({
            'timestamp': timestamp,
            'bytes': content_length
        })
        
        # Clean old bandwidth entries
        while (self.bandwidth_tracker[ip_address] and 
               self.bandwidth_tracker[ip_address][0]['timestamp'] < cutoff_time):
            self.bandwidth_tracker[ip_address].popleft()
    
    def calculate_threat_score(self, ip_address, request):
        """Calculate threat score based on multiple factors."""
        score = 0
        current_time = time.time()
        
        # Requests per second analysis
        recent_requests = [t for t in self.request_tracker[ip_address] 
                          if current_time - t <= 1]
        rps = len(recent_requests)
        
        if rps > self.thresholds['requests_per_second']:
            score += min(50, rps - self.thresholds['requests_per_second'])
        
        # Requests per minute analysis
        minute_requests = [t for t in self.request_tracker[ip_address] 
                          if current_time - t <= 60]
        rpm = len(minute_requests)
        
        if rpm > self.thresholds['requests_per_minute']:
            score += min(30, (rpm - self.thresholds['requests_per_minute']) / 10)
        
        # Bandwidth analysis
        bandwidth_score = self.analyze_bandwidth(ip_address, current_time)
        score += bandwidth_score
        
        # Pattern analysis
        pattern_score = self.analyze_patterns(ip_address, request)
        score += pattern_score
        
        # IP reputation check
        reputation_score = self.check_ip_reputation(ip_address)
        score += reputation_score
        
        # Geographic analysis
        geo_score = self.analyze_geographic_risk(ip_address)
        score += geo_score
        
        return min(100, score)
    
    def analyze_bandwidth(self, ip_address, current_time):
        """Analyze bandwidth usage patterns."""
        if not self.bandwidth_tracker[ip_address]:
            return 0
        
        # Calculate bandwidth in last minute
        recent_bandwidth = [entry for entry in self.bandwidth_tracker[ip_address]
                           if current_time - entry['timestamp'] <= 60]
        
        if not recent_bandwidth:
            return 0
        
        total_bytes = sum(entry['bytes'] for entry in recent_bandwidth)
        mbps = (total_bytes * 8) / (1024 * 1024 * 60)  # Convert to Mbps
        
        if mbps > self.thresholds['bandwidth_mbps']:
            return min(25, mbps - self.thresholds['bandwidth_mbps'])
        
        return 0
    
    def analyze_patterns(self, ip_address, request):
        """Analyze request patterns for attack signatures."""
        score = 0
        
        # Check for common DDoS patterns
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Empty or suspicious user agents
        if not user_agent or len(user_agent) < 10:
            score += 10
        
        # Known attack tools
        attack_tools = ['hping', 'slowhttptest', 'slowloris', 'hulk', 'goldeneye']
        if any(tool in user_agent.lower() for tool in attack_tools):
            score += 30
        
        # Repetitive patterns
        if self.detect_repetitive_patterns(ip_address):
            score += 20
        
        # HTTP method analysis
        if request.method in ['POST', 'PUT', 'DELETE'] and not request.user.is_authenticated:
            score += 5
        
        return score
    
    def detect_repetitive_patterns(self, ip_address):
        """Detect repetitive request patterns."""
        if len(self.request_tracker[ip_address]) < 10:
            return False
        
        # Check for very regular intervals (bot-like behavior)
        intervals = []
        requests = list(self.request_tracker[ip_address])
        
        for i in range(1, len(requests)):
            intervals.append(requests[i] - requests[i-1])
        
        if len(intervals) < 5:
            return False
        
        # Check if intervals are suspiciously regular
        avg_interval = statistics.mean(intervals)
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # If standard deviation is very low, it's likely automated
        return std_dev < avg_interval * 0.1 and avg_interval < 1.0
    
    def check_ip_reputation(self, ip_address):
        """Check IP reputation for known bad actors."""
        try:
            ip_rep = IPReputation.objects.get(ip_address=ip_address)
            if ip_rep.is_blacklisted:
                return 40
            elif ip_rep.reputation_score < 30:
                return 20
            elif ip_rep.reputation_score < 50:
                return 10
        except IPReputation.DoesNotExist:
            pass
        
        return 0
    
    def analyze_geographic_risk(self, ip_address):
        """Analyze geographic risk factors."""
        geo_info = get_geo_info(ip_address)
        if not geo_info:
            return 0
        
        # High-risk countries (configurable)
        high_risk_countries = getattr(settings, 'HIGH_RISK_COUNTRIES', [])
        if geo_info.get('country_code') in high_risk_countries:
            return 15
        
        # Known hosting providers / VPS (higher risk for attacks)
        hosting_asns = getattr(settings, 'HOSTING_ASNS', [])
        if geo_info.get('asn') in hosting_asns:
            return 10
        
        return 0
    
    def trigger_mitigation(self, ip_address, request, threat_score):
        """Trigger DDoS mitigation measures."""
        logger.warning(f"DDoS mitigation triggered for {ip_address}, threat score: {threat_score}")
        
        # Log security event
        SecurityEvent.objects.create(
            event_type='DDOS_ATTACK_DETECTED',
            event_category='DDOS',
            severity='CRITICAL',
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            request_method=request.method,
            request_url=request.get_full_path(),
            risk_score=threat_score,
            blocked=True,
            action_taken='DDoS mitigation activated',
            details={
                'requests_per_second': len([t for t in self.request_tracker[ip_address] 
                                          if time.time() - t <= 1]),
                'total_requests': len(self.request_tracker[ip_address]),
                'mitigation_level': self.determine_mitigation_level(threat_score)
            }
        )
        
        # Apply mitigation
        mitigation_level = self.determine_mitigation_level(threat_score)
        self.apply_mitigation(ip_address, mitigation_level)
        
        return {
            'allowed': False,
            'threat_score': threat_score,
            'mitigation_level': mitigation_level,
            'reason': 'DDoS attack detected'
        }
    
    def determine_mitigation_level(self, threat_score):
        """Determine appropriate mitigation level."""
        if threat_score >= 90:
            return 'BLOCK'
        elif threat_score >= 80:
            return 'CHALLENGE'
        elif threat_score >= 70:
            return 'RATE_LIMIT'
        else:
            return 'MONITOR'
    
    def apply_mitigation(self, ip_address, level):
        """Apply mitigation measures."""
        cache_key = f'ddos_mitigation_{ip_address}'
        
        if level == 'BLOCK':
            # Block IP for 1 hour
            cache.set(f'blocked_ip_{ip_address}', True, 3600)
            cache.set(cache_key, {'level': 'BLOCK', 'expires': time.time() + 3600}, 3600)
            
        elif level == 'CHALLENGE':
            # Require challenge for 30 minutes
            cache.set(f'challenge_ip_{ip_address}', True, 1800)
            cache.set(cache_key, {'level': 'CHALLENGE', 'expires': time.time() + 1800}, 1800)
            
        elif level == 'RATE_LIMIT':
            # Apply strict rate limiting for 15 minutes
            cache.set(f'rate_limit_{ip_address}', {'limit': 10, 'window': 60}, 900)
            cache.set(cache_key, {'level': 'RATE_LIMIT', 'expires': time.time() + 900}, 900)
    
    def start_monitoring(self):
        """Start background monitoring thread."""
        def monitor():
            while True:
                try:
                    self.cleanup_old_data()
                    self.update_metrics()
                    self.detect_global_attacks()
                    time.sleep(30)  # Run every 30 seconds
                except Exception as e:
                    logger.error(f"DDoS monitoring error: {e}")
                    time.sleep(60)
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def cleanup_old_data(self):
        """Clean up old tracking data."""
        current_time = time.time()
        cutoff_time = current_time - 3600  # Keep last hour
        
        # Clean request tracker
        for ip in list(self.request_tracker.keys()):
            while (self.request_tracker[ip] and 
                   self.request_tracker[ip][0] < cutoff_time):
                self.request_tracker[ip].popleft()
            
            # Remove empty entries
            if not self.request_tracker[ip]:
                del self.request_tracker[ip]
        
        # Clean bandwidth tracker
        for ip in list(self.bandwidth_tracker.keys()):
            while (self.bandwidth_tracker[ip] and 
                   self.bandwidth_tracker[ip][0]['timestamp'] < cutoff_time):
                self.bandwidth_tracker[ip].popleft()
            
            if not self.bandwidth_tracker[ip]:
                del self.bandwidth_tracker[ip]
    
    def update_metrics(self):
        """Update DDoS protection metrics."""
        try:
            current_time = time.time()
            
            # Calculate current RPS
            total_rps = 0
            for ip_requests in self.request_tracker.values():
                recent_requests = [t for t in ip_requests if current_time - t <= 1]
                total_rps += len(recent_requests)
            
            # Calculate current bandwidth
            total_bandwidth = 0
            for ip_bandwidth in self.bandwidth_tracker.values():
                recent_bandwidth = [entry for entry in ip_bandwidth
                                  if current_time - entry['timestamp'] <= 60]
                if recent_bandwidth:
                    bytes_per_minute = sum(entry['bytes'] for entry in recent_bandwidth)
                    mbps = (bytes_per_minute * 8) / (1024 * 1024 * 60)
                    total_bandwidth += mbps
            
            # Update protection config
            if self.protection_config:
                self.protection_config.current_rps = total_rps
                self.protection_config.current_bandwidth_mbps = int(total_bandwidth)
                self.protection_config.current_connections = len(self.request_tracker)
                self.protection_config.save()
                
        except Exception as e:
            logger.error(f"Failed to update DDoS metrics: {e}")
    
    def detect_global_attacks(self):
        """Detect global attack patterns."""
        current_time = time.time()
        
        # Check for coordinated attacks
        active_ips = len(self.request_tracker)
        total_rps = sum(len([t for t in requests if current_time - t <= 1]) 
                       for requests in self.request_tracker.values())
        
        # If we have many IPs with high RPS, it might be a coordinated attack
        if active_ips > 100 and total_rps > 1000:
            self.handle_coordinated_attack(active_ips, total_rps)
    
    def handle_coordinated_attack(self, active_ips, total_rps):
        """Handle coordinated DDoS attacks."""
        logger.critical(f"Coordinated DDoS attack detected: {active_ips} IPs, {total_rps} RPS")
        
        # Activate global mitigation
        cache.set('global_ddos_mitigation', {
            'active': True,
            'level': 'HIGH',
            'started_at': time.time(),
            'active_ips': active_ips,
            'total_rps': total_rps
        }, 3600)
        
        # Log global attack event
        SecurityEvent.objects.create(
            event_type='COORDINATED_DDOS_ATTACK',
            event_category='DDOS',
            severity='CRITICAL',
            ip_address='0.0.0.0',  # Global attack
            risk_score=100,
            blocked=True,
            action_taken='Global DDoS mitigation activated',
            details={
                'active_ips': active_ips,
                'total_rps': total_rps,
                'mitigation_level': 'HIGH'
            }
        )


class LayerProtection:
    """Multi-layer DDoS protection system."""
    
    def __init__(self):
        self.layer3_protection = Layer3Protection()
        self.layer4_protection = Layer4Protection()
        self.layer7_protection = Layer7Protection()
    
    def analyze_traffic(self, request, connection_info=None):
        """Analyze traffic through all protection layers."""
        results = {}
        
        # Layer 3 (Network) protection
        if connection_info:
            results['layer3'] = self.layer3_protection.analyze(connection_info)
        
        # Layer 4 (Transport) protection
        results['layer4'] = self.layer4_protection.analyze(request, connection_info)
        
        # Layer 7 (Application) protection
        results['layer7'] = self.layer7_protection.analyze(request)
        
        # Combine results
        max_threat_score = max(
            results.get('layer3', {}).get('threat_score', 0),
            results.get('layer4', {}).get('threat_score', 0),
            results.get('layer7', {}).get('threat_score', 0)
        )
        
        return {
            'threat_score': max_threat_score,
            'layer_results': results,
            'action': self.determine_action(max_threat_score)
        }
    
    def determine_action(self, threat_score):
        """Determine action based on threat score."""
        if threat_score >= 90:
            return 'BLOCK'
        elif threat_score >= 80:
            return 'CHALLENGE'
        elif threat_score >= 70:
            return 'RATE_LIMIT'
        elif threat_score >= 50:
            return 'MONITOR'
        else:
            return 'ALLOW'


class Layer3Protection:
    """Layer 3 (Network) DDoS protection."""
    
    def __init__(self):
        self.packet_tracker = defaultdict(deque)
        self.bandwidth_tracker = defaultdict(deque)
    
    def analyze(self, connection_info):
        """Analyze Layer 3 traffic patterns."""
        if not connection_info:
            return {'threat_score': 0}
        
        ip_address = connection_info.get('remote_addr')
        packet_size = connection_info.get('packet_size', 0)
        protocol = connection_info.get('protocol', 'TCP')
        
        current_time = time.time()
        
        # Track packets
        self.packet_tracker[ip_address].append({
            'timestamp': current_time,
            'size': packet_size,
            'protocol': protocol
        })
        
        # Analyze patterns
        threat_score = 0
        
        # Check packet rate
        recent_packets = [p for p in self.packet_tracker[ip_address] 
                         if current_time - p['timestamp'] <= 1]
        pps = len(recent_packets)
        
        if pps > 1000:  # High packet rate
            threat_score += min(50, pps / 100)
        
        # Check for amplification attacks
        if self.detect_amplification(ip_address):
            threat_score += 40
        
        return {'threat_score': threat_score, 'packets_per_second': pps}
    
    def detect_amplification(self, ip_address):
        """Detect DNS/NTP amplification attacks."""
        recent_packets = [p for p in self.packet_tracker[ip_address] 
                         if time.time() - p['timestamp'] <= 60]
        
        if not recent_packets:
            return False
        
        # Check for large response packets (amplification indicator)
        large_packets = [p for p in recent_packets if p['size'] > 1000]
        
        return len(large_packets) > len(recent_packets) * 0.8


class Layer4Protection:
    """Layer 4 (Transport) DDoS protection."""
    
    def __init__(self):
        self.connection_tracker = defaultdict(deque)
        self.syn_tracker = defaultdict(deque)
    
    def analyze(self, request, connection_info=None):
        """Analyze Layer 4 traffic patterns."""
        ip_address = get_client_ip(request)
        current_time = time.time()
        
        threat_score = 0
        
        # Track connections
        self.connection_tracker[ip_address].append(current_time)
        
        # Clean old entries
        cutoff_time = current_time - 60
        while (self.connection_tracker[ip_address] and 
               self.connection_tracker[ip_address][0] < cutoff_time):
            self.connection_tracker[ip_address].popleft()
        
        # Check connection rate
        connections_per_minute = len(self.connection_tracker[ip_address])
        if connections_per_minute > 100:
            threat_score += min(30, connections_per_minute / 10)
        
        # Check for SYN flood patterns
        if self.detect_syn_flood(ip_address, connection_info):
            threat_score += 40
        
        return {'threat_score': threat_score, 'connections_per_minute': connections_per_minute}
    
    def detect_syn_flood(self, ip_address, connection_info):
        """Detect SYN flood attacks."""
        if not connection_info or connection_info.get('protocol') != 'TCP':
            return False
        
        # In a real implementation, this would check for incomplete TCP handshakes
        # For now, we'll use connection rate as a proxy
        recent_connections = [t for t in self.connection_tracker[ip_address] 
                            if time.time() - t <= 10]
        
        return len(recent_connections) > 50


class Layer7Protection:
    """Layer 7 (Application) DDoS protection."""
    
    def __init__(self):
        self.request_tracker = defaultdict(deque)
        self.slowloris_tracker = defaultdict(list)
    
    def analyze(self, request):
        """Analyze Layer 7 application patterns."""
        ip_address = get_client_ip(request)
        current_time = time.time()
        
        threat_score = 0
        
        # Track HTTP requests
        self.request_tracker[ip_address].append({
            'timestamp': current_time,
            'method': request.method,
            'path': request.path,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'content_length': int(request.META.get('CONTENT_LENGTH', 0))
        })
        
        # Check HTTP flood
        recent_requests = [r for r in self.request_tracker[ip_address] 
                          if current_time - r['timestamp'] <= 60]
        
        if len(recent_requests) > 200:  # High request rate
            threat_score += min(40, len(recent_requests) / 10)
        
        # Check for slowloris attacks
        if self.detect_slowloris(ip_address, request):
            threat_score += 35
        
        # Check for HTTP method abuse
        if self.detect_method_abuse(recent_requests):
            threat_score += 25
        
        return {'threat_score': threat_score, 'requests_per_minute': len(recent_requests)}
    
    def detect_slowloris(self, ip_address, request):
        """Detect Slowloris attacks."""
        # Check for slow, incomplete requests
        content_length = int(request.META.get('CONTENT_LENGTH', 0))
        
        if content_length > 0 and content_length < 100:
            # Track slow requests
            self.slowloris_tracker[ip_address].append(time.time())
            
            # Clean old entries
            cutoff_time = time.time() - 300  # 5 minutes
            self.slowloris_tracker[ip_address] = [
                t for t in self.slowloris_tracker[ip_address] if t > cutoff_time
            ]
            
            # If many slow requests, it might be Slowloris
            return len(self.slowloris_tracker[ip_address]) > 20
        
        return False
    
    def detect_method_abuse(self, recent_requests):
        """Detect HTTP method abuse."""
        if not recent_requests:
            return False
        
        # Check for excessive POST/PUT requests
        write_methods = [r for r in recent_requests if r['method'] in ['POST', 'PUT', 'DELETE']]
        
        return len(write_methods) > len(recent_requests) * 0.8 and len(write_methods) > 50


# Global DDoS protection instance
ddos_engine = DDoSProtectionEngine()
layer_protection = LayerProtection()
