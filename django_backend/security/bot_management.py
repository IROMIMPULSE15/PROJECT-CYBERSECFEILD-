"""
Advanced Bot Detection and Management System
"""

import time
import json
import hashlib
import logging
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone
from .models import BotDetection, SecurityEvent, IPReputation
from .utils import get_client_ip, get_geo_info
import re
import statistics
from datetime import datetime, timedelta

logger = logging.getLogger('bot_management')


class BotDetectionEngine:
    """Advanced bot detection engine with multiple detection methods."""
    
    def __init__(self):
        self.behavior_tracker = defaultdict(lambda: {
            'requests': deque(),
            'user_agents': set(),
            'paths': deque(),
            'intervals': deque(),
            'session_data': {}
        })
        
        # Known bot patterns
        self.good_bot_patterns = [
            (r'googlebot', 'Googlebot'),
            (r'bingbot', 'Bingbot'),
            (r'slurp', 'Yahoo Slurp'),
            (r'duckduckbot', 'DuckDuckBot'),
            (r'baiduspider', 'Baiduspider'),
            (r'yandexbot', 'YandexBot'),
            (r'facebookexternalhit', 'Facebook Bot'),
            (r'twitterbot', 'Twitterbot'),
            (r'linkedinbot', 'LinkedIn Bot'),
            (r'whatsapp', 'WhatsApp Bot'),
            (r'telegrambot', 'Telegram Bot'),
            (r'applebot', 'Applebot'),
            (r'amazonbot', 'Amazon Bot')
        ]
        
        self.bad_bot_patterns = [
            (r'scrapy', 'Scrapy'),
            (r'selenium', 'Selenium'),
            (r'phantomjs', 'PhantomJS'),
            (r'headlesschrome', 'Headless Chrome'),
            (r'python-requests', 'Python Requests'),
            (r'curl', 'cURL'),
            (r'wget', 'wget'),
            (r'httpie', 'HTTPie'),
            (r'postman', 'Postman'),
            (r'insomnia', 'Insomnia'),
            (r'bot\.py', 'Python Bot'),
            (r'spider', 'Generic Spider'),
            (r'crawler', 'Generic Crawler'),
            (r'scraper', 'Generic Scraper')
        ]
        
        self.suspicious_patterns = [
            r'sqlmap',
            r'nikto',
            r'nmap',
            r'masscan',
            r'zap',
            r'burp',
            r'w3af',
            r'acunetix',
            r'netsparker',
            r'metasploit'
        ]
        
        # Browser fingerprinting
        self.browser_signatures = self.load_browser_signatures()
        
        # Start cleanup thread
        self.start_cleanup_thread()
    
    def load_browser_signatures(self) -> Dict:
        """Load known browser signatures for fingerprinting."""
        return {
            'chrome': {
                'headers': ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-fetch-site'],
                'js_features': ['chrome', 'webkitRequestAnimationFrame'],
                'typical_order': ['host', 'connection', 'sec-ch-ua', 'sec-ch-ua-mobile']
            },
            'firefox': {
                'headers': ['accept', 'accept-language', 'accept-encoding'],
                'js_features': ['mozRequestAnimationFrame', 'InstallTrigger'],
                'typical_order': ['host', 'user-agent', 'accept', 'accept-language']
            },
            'safari': {
                'headers': ['accept', 'accept-language', 'accept-encoding'],
                'js_features': ['safari', 'webkitRequestAnimationFrame'],
                'typical_order': ['host', 'accept', 'user-agent', 'accept-language']
            }
        }
    
    def analyze_request(self, request) -> Dict:
        """Analyze request for bot characteristics."""
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        current_time = time.time()
        
        # Track request
        self.track_request(ip_address, request, current_time)
        
        # Run detection methods
        detection_results = {
            'user_agent_analysis': self.analyze_user_agent(user_agent),
            'behavioral_analysis': self.analyze_behavior(ip_address, current_time),
            'fingerprint_analysis': self.analyze_fingerprint(request),
            'pattern_analysis': self.analyze_patterns(request),
            'reputation_analysis': self.analyze_reputation(ip_address)
        }
        
        # Calculate overall bot score
        bot_score = self.calculate_bot_score(detection_results)
        
        # Determine bot type and action
        bot_type, confidence = self.classify_bot(detection_results, bot_score)
        action = self.determine_action(bot_type, confidence, bot_score)
        
        # Update or create bot detection record
        self.update_bot_record(ip_address, user_agent, bot_type, confidence, action)
        
        # Log if significant bot activity detected
        if confidence > 70 or bot_type in ['BAD', 'SUSPICIOUS']:
            self.log_bot_detection(request, detection_results, bot_type, confidence, action)
        
        return {
            'bot_detected': confidence > 50,
            'bot_type': bot_type,
            'confidence': confidence,
            'bot_score': bot_score,
            'action': action,
            'detection_methods': detection_results
        }
    
    def track_request(self, ip_address: str, request, timestamp: float):
        """Track request for behavioral analysis."""
        tracker = self.behavior_tracker[ip_address]
        
        # Track request timing
        tracker['requests'].append(timestamp)
        
        # Track user agents
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        tracker['user_agents'].add(user_agent)
        
        # Track paths
        tracker['paths'].append(request.path)
        
        # Calculate intervals
        if len(tracker['requests']) > 1:
            interval = timestamp - tracker['requests'][-2]
            tracker['intervals'].append(interval)
        
        # Clean old data (keep last 10 minutes)
        cutoff_time = timestamp - 600
        while tracker['requests'] and tracker['requests'][0] < cutoff_time:
            tracker['requests'].popleft()
        
        while tracker['paths'] and len(tracker['paths']) > 100:
            tracker['paths'].popleft()
        
        while tracker['intervals'] and len(tracker['intervals']) > 50:
            tracker['intervals'].popleft()
        
        # Update session data
        tracker['session_data'].update({
            'last_seen': timestamp,
            'total_requests': len(tracker['requests']),
            'unique_paths': len(set(tracker['paths'])),
            'session_duration': timestamp - tracker['requests'][0] if tracker['requests'] else 0
        })
    
    def analyze_user_agent(self, user_agent: str) -> Dict:
        """Analyze user agent for bot indicators."""
        if not user_agent:
            return {
                'score': 80,
                'indicators': ['missing_user_agent'],
                'bot_name': 'Unknown',
                'classification': 'SUSPICIOUS'
            }
        
        ua_lower = user_agent.lower()
        
        # Check for good bots
        for pattern, name in self.good_bot_patterns:
            if re.search(pattern, ua_lower):
                return {
                    'score': 95,
                    'indicators': ['known_good_bot'],
                    'bot_name': name,
                    'classification': 'GOOD'
                }
        
        # Check for bad bots
        for pattern, name in self.bad_bot_patterns:
            if re.search(pattern, ua_lower):
                return {
                    'score': 90,
                    'indicators': ['known_bad_bot'],
                    'bot_name': name,
                    'classification': 'BAD'
                }
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, ua_lower):
                return {
                    'score': 95,
                    'indicators': ['malicious_tool'],
                    'bot_name': 'Malicious Tool',
                    'classification': 'BAD'
                }
        
        # Analyze user agent structure
        indicators = []
        score = 0
        
        # Check length
        if len(user_agent) < 20:
            indicators.append('short_user_agent')
            score += 30
        elif len(user_agent) > 500:
            indicators.append('long_user_agent')
            score += 20
        
        # Check for missing browser info
        if not any(browser in ua_lower for browser in ['chrome', 'firefox', 'safari', 'edge']):
            indicators.append('no_browser_info')
            score += 25
        
        # Check for programming language indicators
        if any(lang in ua_lower for lang in ['python', 'java', 'go', 'ruby', 'php']):
            indicators.append('programming_language')
            score += 40
        
        # Check for version inconsistencies
        if self.detect_version_inconsistencies(user_agent):
            indicators.append('version_inconsistency')
            score += 30
        
        classification = 'SUSPICIOUS' if score > 50 else 'UNKNOWN'
        
        return {
            'score': min(score, 100),
            'indicators': indicators,
            'bot_name': 'Unknown Bot' if score > 50 else 'Potential Human',
            'classification': classification
        }
    
    def detect_version_inconsistencies(self, user_agent: str) -> bool:
        """Detect version inconsistencies in user agent."""
        # This is a simplified check - in practice, you'd have more sophisticated validation
        
        # Check for impossible combinations
        impossible_combinations = [
            (r'chrome/(\d+)', r'safari/(\d+)', lambda c, s: int(c) > 100 and int(s) < 500),
            (r'firefox/(\d+)', r'chrome/(\d+)', lambda f, c: True),  # Firefox and Chrome together
        ]
        
        for pattern1, pattern2, validator in impossible_combinations:
            match1 = re.search(pattern1, user_agent.lower())
            match2 = re.search(pattern2, user_agent.lower())
            
            if match1 and match2:
                try:
                    if validator(match1.group(1), match2.group(1)):
                        return True
                except (ValueError, IndexError):
                    continue
        
        return False
    
    def analyze_behavior(self, ip_address: str, current_time: float) -> Dict:
        """Analyze behavioral patterns."""
        tracker = self.behavior_tracker[ip_address]
        
        if not tracker['requests']:
            return {'score': 0, 'indicators': []}
        
        indicators = []
        score = 0
        
        # Analyze request frequency
        recent_requests = [t for t in tracker['requests'] if current_time - t <= 60]
        requests_per_minute = len(recent_requests)
        
        if requests_per_minute > 60:
            indicators.append('high_request_rate')
            score += min(40, requests_per_minute - 60)
        
        # Analyze request intervals
        if len(tracker['intervals']) > 5:
            intervals = list(tracker['intervals'])
            
            # Check for very regular intervals (bot-like)
            if self.detect_regular_intervals(intervals):
                indicators.append('regular_intervals')
                score += 35
            
            # Check for very fast intervals
            avg_interval = statistics.mean(intervals)
            if avg_interval < 0.1:  # Less than 100ms between requests
                indicators.append('very_fast_requests')
                score += 30
        
        # Analyze path patterns
        if len(tracker['paths']) > 10:
            unique_paths = len(set(tracker['paths']))
            path_diversity = unique_paths / len(tracker['paths'])
            
            if path_diversity < 0.1:  # Very repetitive paths
                indicators.append('repetitive_paths')
                score += 25
            
            # Check for systematic crawling patterns
            if self.detect_crawling_pattern(list(tracker['paths'])):
                indicators.append('crawling_pattern')
                score += 30
        
        # Analyze user agent consistency
        if len(tracker['user_agents']) > 3:
            indicators.append('multiple_user_agents')
            score += 20
        
        # Analyze session characteristics
        session_data = tracker['session_data']
        if session_data.get('session_duration', 0) > 3600:  # More than 1 hour
            if session_data.get('total_requests', 0) > 1000:
                indicators.append('long_high_volume_session')
                score += 25
        
        return {
            'score': min(score, 100),
            'indicators': indicators,
            'requests_per_minute': requests_per_minute,
            'avg_interval': statistics.mean(tracker['intervals']) if tracker['intervals'] else 0,
            'path_diversity': unique_paths / len(tracker['paths']) if len(tracker['paths']) > 0 else 0
        }
    
    def detect_regular_intervals(self, intervals: List[float]) -> bool:
        """Detect suspiciously regular request intervals."""
        if len(intervals) < 5:
            return False
        
        # Calculate coefficient of variation
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return True  # All intervals are 0 - very suspicious
        
        std_dev = statistics.stdev(intervals)
        cv = std_dev / mean_interval
        
        # If coefficient of variation is very low, intervals are very regular
        return cv < 0.1 and mean_interval < 5.0
    
    def detect_crawling_pattern(self, paths: List[str]) -> bool:
        """Detect systematic crawling patterns."""
        if len(paths) < 10:
            return False
        
        # Check for sequential numeric patterns
        numeric_paths = []
        for path in paths:
            numbers = re.findall(r'\d+', path)
            if numbers:
                try:
                    numeric_paths.append(int(numbers[-1]))  # Take last number
                except ValueError:
                    continue
        
        if len(numeric_paths) > 5:
            # Check if numbers are mostly sequential
            sorted_numbers = sorted(numeric_paths)
            sequential_count = 0
            
            for i in range(1, len(sorted_numbers)):
                if sorted_numbers[i] - sorted_numbers[i-1] <= 2:
                    sequential_count += 1
            
            if sequential_count / len(sorted_numbers) > 0.7:
                return True
        
        # Check for alphabetical patterns
        path_endings = [path.split('/')[-1] for path in paths if '/' in path]
        if len(path_endings) > 10:
            sorted_endings = sorted(path_endings)
            if sorted_endings == path_endings[-len(sorted_endings):]:
                return True
        
        return False
    
    def analyze_fingerprint(self, request) -> Dict:
        """Analyze browser fingerprint characteristics."""
        headers = dict(request.headers)
        indicators = []
        score = 0
        
        # Check for missing common headers
        common_headers = [
            'accept', 'accept-language', 'accept-encoding',
            'connection', 'upgrade-insecure-requests'
        ]
        
        missing_headers = []
        for header in common_headers:
            if header not in [h.lower() for h in headers.keys()]:
                missing_headers.append(header)
        
        if missing_headers:
            indicators.append(f'missing_headers: {", ".join(missing_headers)}')
            score += len(missing_headers) * 10
        
        # Check header order (simplified)
        header_keys = [k.lower() for k in headers.keys()]
        if header_keys and header_keys[0] != 'host':
            indicators.append('unusual_header_order')
            score += 15
        
        # Check for automation-specific headers
        automation_headers = [
            'x-requested-with', 'x-automation', 'x-test',
            'selenium-remote-control', 'webdriver'
        ]
        
        for header in automation_headers:
            if header in [h.lower() for h in headers.keys()]:
                indicators.append(f'automation_header: {header}')
                score += 30
        
        # Check Accept header
        accept_header = headers.get('Accept', headers.get('accept', ''))
        if not accept_header:
            indicators.append('missing_accept_header')
            score += 20
        elif accept_header == '*/*':
            indicators.append('generic_accept_header')
            score += 15
        
        # Check for browser-specific header patterns
        browser_score = self.analyze_browser_consistency(headers)
        score += browser_score
        if browser_score > 20:
            indicators.append('browser_inconsistency')
        
        return {
            'score': min(score, 100),
            'indicators': indicators,
            'missing_headers': missing_headers
        }
    
    def analyze_browser_consistency(self, headers: Dict) -> int:
        """Analyze browser header consistency."""
        user_agent = headers.get('User-Agent', headers.get('user-agent', ''))
        if not user_agent:
            return 30
        
        ua_lower = user_agent.lower()
        score = 0
        
        # Check Chrome consistency
        if 'chrome' in ua_lower:
            expected_headers = ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-fetch-site']
            missing = sum(1 for h in expected_headers if h not in [k.lower() for k in headers.keys()])
            score += missing * 10
        
        # Check Firefox consistency
        elif 'firefox' in ua_lower:
            # Firefox typically doesn't send sec-ch-* headers
            sec_headers = [k for k in headers.keys() if k.lower().startswith('sec-ch-')]
            if sec_headers:
                score += 20
        
        return score
    
    def analyze_patterns(self, request) -> Dict:
        """Analyze request patterns for bot indicators."""
        indicators = []
        score = 0
        
        # Check request method patterns
        if request.method in ['HEAD', 'OPTIONS'] and not request.user.is_authenticated:
            indicators.append('unusual_method_unauthenticated')
            score += 15
        
        # Check for automation in URL patterns
        path = request.path.lower()
        automation_paths = [
            '/robots.txt', '/sitemap.xml', '/.well-known/',
            '/wp-admin/', '/admin/', '/api/v1/', '/graphql'
        ]
        
        if any(auto_path in path for auto_path in automation_paths):
            indicators.append('automation_target_path')
            score += 10
        
        # Check query parameters for automation
        query_params = request.GET
        automation_params = ['debug', 'test', 'automation', 'bot', 'crawler']
        
        for param in automation_params:
            if param in [p.lower() for p in query_params.keys()]:
                indicators.append(f'automation_parameter: {param}')
                score += 20
        
        # Check for rapid sequential requests to different endpoints
        # (This would require session tracking in a real implementation)
        
        return {
            'score': min(score, 100),
            'indicators': indicators
        }
    
    def analyze_reputation(self, ip_address: str) -> Dict:
        """Analyze IP reputation for bot indicators."""
        try:
            ip_rep = IPReputation.objects.get(ip_address=ip_address)
            
            score = 0
            indicators = []
            
            if ip_rep.is_blacklisted:
                score += 50
                indicators.append('blacklisted_ip')
            
            if ip_rep.reputation_score < 30:
                score += 30
                indicators.append('poor_reputation')
            
            # Check for hosting/VPS providers (more likely to host bots)
            if 'hosting' in ip_rep.organization.lower() or 'vps' in ip_rep.organization.lower():
                score += 20
                indicators.append('hosting_provider')
            
            return {
                'score': score,
                'indicators': indicators,
                'reputation_score': ip_rep.reputation_score
            }
            
        except IPReputation.DoesNotExist:
            return {
                'score': 10,  # Unknown IP gets small penalty
                'indicators': ['unknown_ip'],
                'reputation_score': 50
            }
    
    def calculate_bot_score(self, detection_results: Dict) -> int:
        """Calculate overall bot score from all detection methods."""
        # Weight different detection methods
        weights = {
            'user_agent_analysis': 0.3,
            'behavioral_analysis': 0.25,
            'fingerprint_analysis': 0.2,
            'pattern_analysis': 0.15,
            'reputation_analysis': 0.1
        }
        
        total_score = 0
        for method, result in detection_results.items():
            if method in weights:
                total_score += result.get('score', 0) * weights[method]
        
        return min(int(total_score), 100)
    
    def classify_bot(self, detection_results: Dict, bot_score: int) -> Tuple[str, int]:
        """Classify bot type and confidence."""
        ua_analysis = detection_results.get('user_agent_analysis', {})
        ua_classification = ua_analysis.get('classification', 'UNKNOWN')
        
        # If user agent analysis is confident, use that
        if ua_analysis.get('score', 0) > 90:
            return ua_classification, ua_analysis.get('score', 0)
        
        # Otherwise, use combined score
        if bot_score >= 80:
            confidence = bot_score
            if any('malicious' in str(indicators) for indicators in 
                   [r.get('indicators', []) for r in detection_results.values()]):
                return 'BAD', confidence
            else:
                return 'SUSPICIOUS', confidence
        elif bot_score >= 60:
            return 'SUSPICIOUS', bot_score
        elif bot_score >= 40:
            return 'UNKNOWN', bot_score
        else:
            return 'GOOD', 100 - bot_score
    
    def determine_action(self, bot_type: str, confidence: int, bot_score: int) -> str:
        """Determine action to take based on bot classification."""
        if bot_type == 'BAD' and confidence > 80:
            return 'BLOCK'
        elif bot_type == 'BAD' and confidence > 60:
            return 'CHALLENGE'
        elif bot_type == 'SUSPICIOUS' and confidence > 70:
            return 'CHALLENGE'
        elif bot_type == 'SUSPICIOUS' and confidence > 50:
            return 'RATE_LIMIT'
        elif bot_type == 'GOOD':
            return 'ALLOW'
        else:
            return 'MONITOR'
    
    def update_bot_record(self, ip_address: str, user_agent: str, bot_type: str, 
                         confidence: int, action: str):
        """Update or create bot detection record."""
        try:
            bot_record, created = BotDetection.objects.get_or_create(
                ip_address=ip_address,
                user_agent=user_agent,
                defaults={
                    'bot_type': bot_type,
                    'confidence_score': confidence,
                    'detection_method': 'multi_factor_analysis',
                    'action': action,
                    'request_count': 1
                }
            )
            
            if not created:
                bot_record.bot_type = bot_type
                bot_record.confidence_score = confidence
                bot_record.action = action
                bot_record.request_count += 1
                bot_record.last_seen = timezone.now()
                bot_record.save()
                
        except Exception as e:
            logger.error(f"Failed to update bot record: {e}")
    
    def log_bot_detection(self, request, detection_results: Dict, bot_type: str, 
                         confidence: int, action: str):
        """Log bot detection event."""
        try:
            SecurityEvent.objects.create(
                event_type='BOT_DETECTED',
                event_category='BOT',
                severity='HIGH' if bot_type == 'BAD' else 'MEDIUM',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_method=request.method,
                request_url=request.get_full_path(),
                user_id=request.user.id if request.user.is_authenticated else None,
                blocked=action in ['BLOCK', 'CHALLENGE'],
                action_taken=f'Bot management action: {action}',
                risk_score=confidence,
                details={
                    'bot_type': bot_type,
                    'confidence': confidence,
                    'action': action,
                    'detection_results': detection_results
                }
            )
        except Exception as e:
            logger.error(f"Failed to log bot detection: {e}")
    
    def start_cleanup_thread(self):
        """Start background cleanup thread."""
        import threading
        
        def cleanup():
            while True:
                try:
                    current_time = time.time()
                    cutoff_time = current_time - 3600  # Keep last hour
                    
                    # Clean up old tracking data
                    for ip in list(self.behavior_tracker.keys()):
                        tracker = self.behavior_tracker[ip]
                        
                        # Remove old requests
                        while tracker['requests'] and tracker['requests'][0] < cutoff_time:
                            tracker['requests'].popleft()
                        
                        # Remove empty trackers
                        if not tracker['requests']:
                            del self.behavior_tracker[ip]
                    
                    time.sleep(300)  # Run every 5 minutes
                    
                except Exception as e:
                    logger.error(f"Bot detection cleanup error: {e}")
                    time.sleep(600)  # Wait 10 minutes on error
        
        thread = threading.Thread(target=cleanup, daemon=True)
        thread.start()


class ChallengeSystem:
    """Bot challenge system with multiple challenge types."""
    
    def __init__(self):
        self.active_challenges = {}
        self.challenge_types = {
            'javascript': JavaScriptChallenge(),
            'captcha': CaptchaChallenge(),
            'proof_of_work': ProofOfWorkChallenge(),
            'behavioral': BehavioralChallenge()
        }
    
    def issue_challenge(self, ip_address: str, challenge_type: str = 'javascript') -> Dict:
        """Issue a challenge to the client."""
        if challenge_type not in self.challenge_types:
            challenge_type = 'javascript'
        
        challenge = self.challenge_types[challenge_type].generate_challenge()
        challenge_id = hashlib.md5(f"{ip_address}_{time.time()}".encode()).hexdigest()
        
        self.active_challenges[challenge_id] = {
            'ip_address': ip_address,
            'challenge_type': challenge_type,
            'challenge_data': challenge,
            'created_at': time.time(),
            'attempts': 0
        }
        
        return {
            'challenge_id': challenge_id,
            'challenge_type': challenge_type,
            'challenge_data': challenge,
            'expires_in': 300  # 5 minutes
        }
    
    def verify_challenge(self, challenge_id: str, response: Dict) -> Dict:
        """Verify challenge response."""
        if challenge_id not in self.active_challenges:
            return {'success': False, 'error': 'Invalid or expired challenge'}
        
        challenge_info = self.active_challenges[challenge_id]
        challenge_info['attempts'] += 1
        
        # Check expiration
        if time.time() - challenge_info['created_at'] > 300:
            del self.active_challenges[challenge_id]
            return {'success': False, 'error': 'Challenge expired'}
        
        # Check attempt limit
        if challenge_info['attempts'] > 3:
            del self.active_challenges[challenge_id]
            return {'success': False, 'error': 'Too many attempts'}
        
        # Verify response
        challenge_type = challenge_info['challenge_type']
        challenge_data = challenge_info['challenge_data']
        
        success = self.challenge_types[challenge_type].verify_response(
            challenge_data, response
        )
        
        if success:
            # Mark IP as verified
            ip_address = challenge_info['ip_address']
            cache.set(f'challenge_passed_{ip_address}', True, 3600)  # Valid for 1 hour
            del self.active_challenges[challenge_id]
            
            return {'success': True, 'message': 'Challenge passed'}
        else:
            return {'success': False, 'error': 'Invalid response'}


class JavaScriptChallenge:
    """JavaScript-based bot challenge."""
    
    def generate_challenge(self) -> Dict:
        """Generate JavaScript challenge."""
        # Simple math problem that requires JS execution
        import random
        
        a = random.randint(10, 99)
        b = random.randint(10, 99)
        operation = random.choice(['+', '-', '*'])
        
        if operation == '+':
            answer = a + b
        elif operation == '-':
            answer = a - b
        else:
            answer = a * b
        
        challenge_code = f"""
        function solveChallenge() {{
            var result = {a} {operation} {b};
            return result;
        }}
        """
        
        return {
            'code': challenge_code,
            'expected_answer': answer,
            'timeout': 10000  # 10 seconds
        }
    
    def verify_response(self, challenge_data: Dict, response: Dict) -> bool:
        """Verify JavaScript challenge response."""
        expected = challenge_data['expected_answer']
        provided = response.get('answer')
        
        try:
            return int(provided) == expected
        except (ValueError, TypeError):
            return False


class CaptchaChallenge:
    """CAPTCHA-based challenge."""
    
    def generate_challenge(self) -> Dict:
        """Generate CAPTCHA challenge."""
        # In a real implementation, you'd generate an actual CAPTCHA image
        # For now, we'll use a simple text-based challenge
        
        import random
        import string
        
        challenge_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        return {
            'challenge_text': challenge_text,
            'image_url': f'/captcha/{hashlib.md5(challenge_text.encode()).hexdigest()}.png'
        }
    
    def verify_response(self, challenge_data: Dict, response: Dict) -> bool:
        """Verify CAPTCHA response."""
        expected = challenge_data['challenge_text']
        provided = response.get('captcha_response', '').upper()
        
        return provided == expected


class ProofOfWorkChallenge:
    """Proof of work challenge."""
    
    def generate_challenge(self) -> Dict:
        """Generate proof of work challenge."""
        import random
        
        target = random.randint(1000000, 9999999)
        difficulty = 4  # Number of leading zeros required
        
        return {
            'target': target,
            'difficulty': difficulty,
            'algorithm': 'sha256'
        }
    
    def verify_response(self, challenge_data: Dict, response: Dict) -> bool:
        """Verify proof of work response."""
        target = challenge_data['target']
        difficulty = challenge_data['difficulty']
        nonce = response.get('nonce')
        
        if not nonce:
            return False
        
        try:
            # Verify the proof of work
            combined = f"{target}{nonce}"
            hash_result = hashlib.sha256(combined.encode()).hexdigest()
            
            return hash_result.startswith('0' * difficulty)
        except Exception:
            return False


class BehavioralChallenge:
    """Behavioral analysis challenge."""
    
    def generate_challenge(self) -> Dict:
        """Generate behavioral challenge."""
        return {
            'type': 'mouse_movement',
            'required_events': ['mousemove', 'click'],
            'min_events': 5,
            'timeout': 30000  # 30 seconds
        }
    
    def verify_response(self, challenge_data: Dict, response: Dict) -> bool:
        """Verify behavioral challenge response."""
        events = response.get('events', [])
        required_events = challenge_data['required_events']
        min_events = challenge_data['min_events']
        
        if len(events) < min_events:
            return False
        
        # Check if required event types are present
        event_types = [event.get('type') for event in events]
        
        for required_type in required_events:
            if required_type not in event_types:
                return False
        
        # Additional behavioral analysis could be added here
        # (e.g., mouse movement patterns, timing analysis)
        
        return True


# Global bot detection engine
bot_engine = BotDetectionEngine()
challenge_system = ChallengeSystem()
