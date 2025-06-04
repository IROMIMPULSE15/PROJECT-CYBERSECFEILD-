"""
Advanced Web Application Firewall (WAF) Engine
"""

import re
import json
import time
import logging
from typing import Dict, List, Tuple, Optional
from django.core.cache import cache
from django.http import JsonResponse
from .models import WAFRule, SecurityEvent, ThreatIntelligence
from .utils import get_client_ip
import hashlib
import base64
from urllib.parse import unquote, unquote_plus

logger = logging.getLogger('waf_engine')


class WAFEngine:
    """Advanced Web Application Firewall Engine with ML-based detection."""
    
    def __init__(self):
        self.rules_cache = {}
        self.pattern_cache = {}
        self.load_rules()
        self.ml_detector = MLThreatDetector()
        
        # Attack pattern signatures
        self.attack_signatures = {
            'sql_injection': [
                r"('|(\\')|(;|(\s*;\s*))|(--)|(/\*.*\*/))",
                r"((\s+)or(\s+).*=.*)|((\s+)or(\s+).*<.*)|((\s+)or(\s+).*>.*)|((\s+)or(\s+).*\sis\s*.*)|((\s+)or(\s+).*\s(not\s+)?like\s*.*)",
                r"(union\s*select)|(union\s*all\s*select)",
                r"(insert\s+into)|(delete\s+from)|(update\s+.+\s+set)|(create\s+table)|(drop\s+table)|(alter\s+table)",
                r"(exec(\s|\+)+(s|x)p\w+)|(sp_\w+)",
                r"(\bselect\b.*\bfrom\b.*\bwhere\b)",
                r"(\bunion\b.*\bselect\b)",
                r"(load_file|into\s+outfile|into\s+dumpfile)",
                r"(benchmark|sleep|waitfor\s+delay)",
                r"(information_schema|mysql\.user|pg_user)"
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'<iframe[^>]*>.*?</iframe>',
                r'<object[^>]*>.*?</object>',
                r'<embed[^>]*>.*?</embed>',
                r'<link[^>]*>',
                r'<meta[^>]*>',
                r'<style[^>]*>.*?</style>',
                r'expression\s*\(',
                r'url\s*\(',
                r'@import',
                r'<svg[^>]*>.*?</svg>',
                r'<img[^>]*onerror[^>]*>',
                r'<body[^>]*onload[^>]*>',
                r'eval\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\('
            ],
            'lfi': [
                r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)',
                r'(file://|php://)',
                r'(/etc/passwd|/etc/shadow|/etc/hosts)',
                r'(\.\.[\\/]){3,}',
                r'%252e%252e%252f',
                r'%c0%ae%c0%ae%c0%af',
                r'(proc/self/environ|proc/version|proc/cmdline)'
            ],
            'rfi': [
                r'(http://|https://|ftp://|ftps://)',
                r'(include|require)(_once)?\s*\(\s*["\']?(http|ftp)',
                r'(allow_url_include|allow_url_fopen)',
                r'data:text/plain',
                r'php://input',
                r'php://filter'
            ],
            'command_injection': [
                r';.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
                r'\|.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
                r'&.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
                r'`.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
                r'\$\(.*?(whoami|id|pwd|ls|dir|cat|type|echo|ping|wget|curl)',
                r'(nc|netcat|ncat).*?-[lp]',
                r'/bin/(sh|bash|csh|tcsh|zsh)',
                r'cmd\.exe',
                r'powershell\.exe',
                r'(system|exec|shell_exec|passthru|eval)\s*\(',
                r'(&&|\|\|)\s*(cat|ls|pwd|whoami)'
            ],
            'path_traversal': [
                r'(\.\./|\.\.\\)',
                r'(%2e%2e%2f|%2e%2e%5c)',
                r'(%252e%252e%252f|%252e%252e%255c)',
                r'(\.\.[\\/]){2,}',
                r'%c0%ae%c0%ae%c0%af',
                r'%c1%9c',
                r'\.\.%u002f',
                r'\.\.%u005c'
            ],
            'protocol_attack': [
                r'(HTTP/[0-9]\.[0-9].*\r\n.*\r\n)',
                r'(GET.*HTTP/1\.[01].*Host:.*){2,}',
                r'Content-Length:\s*-\d+',
                r'Transfer-Encoding:\s*chunked.*Content-Length:',
                r'Expect:\s*100-continue.*Content-Length:\s*0'
            ]
        }
    
    def load_rules(self):
        """Load WAF rules from database."""
        try:
            rules = WAFRule.objects.filter(is_active=True).order_by('priority')
            self.rules_cache = {}
            
            for rule in rules:
                if rule.rule_category not in self.rules_cache:
                    self.rules_cache[rule.rule_category] = []
                
                # Compile regex patterns for better performance
                if rule.rule_type == 'REGEX':
                    try:
                        flags = 0 if rule.case_sensitive else re.IGNORECASE
                        compiled_pattern = re.compile(rule.rule_pattern, flags)
                        self.pattern_cache[rule.id] = compiled_pattern
                    except re.error as e:
                        logger.error(f"Invalid regex pattern in rule {rule.id}: {e}")
                        continue
                
                self.rules_cache[rule.rule_category].append(rule)
                
            logger.info(f"Loaded {sum(len(rules) for rules in self.rules_cache.values())} WAF rules")
            
        except Exception as e:
            logger.error(f"Failed to load WAF rules: {e}")
    
    def analyze_request(self, request) -> Dict:
        """Analyze request through WAF engine."""
        start_time = time.time()
        ip_address = get_client_ip(request)
        
        # Extract request data
        request_data = self.extract_request_data(request)
        
        # Run through rule engine
        rule_results = self.evaluate_rules(request_data)
        
        # Run through ML detector
        ml_results = self.ml_detector.analyze(request_data)
        
        # Combine results
        combined_score = max(rule_results['threat_score'], ml_results['threat_score'])
        
        # Determine action
        action = self.determine_action(combined_score, rule_results, ml_results)
        
        # Log if threat detected
        if combined_score > 30:
            self.log_threat_detection(request, request_data, rule_results, ml_results, action)
        
        processing_time = int((time.time() - start_time) * 1000)
        
        return {
            'threat_score': combined_score,
            'action': action,
            'rule_matches': rule_results['matches'],
            'ml_prediction': ml_results.get('prediction'),
            'processing_time_ms': processing_time,
            'blocked': action in ['BLOCK', 'CHALLENGE']
        }
    
    def extract_request_data(self, request) -> Dict:
        """Extract relevant data from request for analysis."""
        data = {
            'method': request.method,
            'path': request.path,
            'query_string': request.META.get('QUERY_STRING', ''),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'referer': request.META.get('HTTP_REFERER', ''),
            'content_type': request.META.get('CONTENT_TYPE', ''),
            'headers': dict(request.headers),
            'cookies': dict(request.COOKIES),
            'get_params': dict(request.GET),
            'post_params': {},
            'body': '',
            'files': []
        }
        
        # Extract POST data safely
        if request.method == 'POST':
            try:
                data['post_params'] = dict(request.POST)
                if hasattr(request, 'body'):
                    data['body'] = request.body.decode('utf-8', errors='ignore')[:10000]  # Limit size
            except Exception as e:
                logger.warning(f"Failed to extract POST data: {e}")
        
        # Extract file upload info
        if request.FILES:
            for field_name, file_obj in request.FILES.items():
                data['files'].append({
                    'field_name': field_name,
                    'filename': file_obj.name,
                    'content_type': file_obj.content_type,
                    'size': file_obj.size
                })
        
        return data
    
    def evaluate_rules(self, request_data: Dict) -> Dict:
        """Evaluate request against WAF rules."""
        matches = []
        max_score = 0
        
        # Check each rule category
        for category, rules in self.rules_cache.items():
            for rule in rules:
                match_result = self.evaluate_single_rule(rule, request_data)
                if match_result['matched']:
                    matches.append({
                        'rule_id': str(rule.id),
                        'rule_name': rule.rule_name,
                        'category': rule.rule_category,
                        'severity': rule.severity,
                        'action': rule.action,
                        'matched_value': match_result['matched_value'],
                        'location': match_result['location']
                    })
                    
                    # Update rule statistics
                    self.update_rule_stats(rule)
                    
                    # Calculate score based on severity
                    score = self.get_severity_score(rule.severity)
                    max_score = max(max_score, score)
        
        return {
            'threat_score': max_score,
            'matches': matches
        }
    
    def evaluate_single_rule(self, rule: WAFRule, request_data: Dict) -> Dict:
        """Evaluate a single WAF rule against request data."""
        # Get all testable values from request
        test_values = self.get_test_values(request_data, rule.rule_type)
        
        for location, value in test_values:
            if self.test_pattern_match(rule, value):
                return {
                    'matched': True,
                    'matched_value': value[:500],  # Limit logged value size
                    'location': location
                }
        
        return {'matched': False}
    
    def get_test_values(self, request_data: Dict, rule_type: str) -> List[Tuple[str, str]]:
        """Get values to test based on rule type."""
        values = []
        
        if rule_type in ['REGEX', 'STRING']:
            # Test all request components
            values.extend([
                ('url', request_data['path']),
                ('query_string', request_data['query_string']),
                ('user_agent', request_data['user_agent']),
                ('referer', request_data['referer']),
                ('body', request_data['body'])
            ])
            
            # Test GET parameters
            for key, value in request_data['get_params'].items():
                values.append((f'get_param_{key}', str(value)))
            
            # Test POST parameters
            for key, value in request_data['post_params'].items():
                values.append((f'post_param_{key}', str(value)))
            
            # Test headers
            for key, value in request_data['headers'].items():
                values.append((f'header_{key}', str(value)))
            
            # Test cookies
            for key, value in request_data['cookies'].items():
                values.append((f'cookie_{key}', str(value)))
        
        elif rule_type == 'HEADER':
            for key, value in request_data['headers'].items():
                values.append((f'header_{key}', f'{key}: {value}'))
        
        elif rule_type == 'BODY':
            values.append(('body', request_data['body']))
        
        elif rule_type == 'URL':
            values.append(('url', request_data['path']))
            values.append(('query_string', request_data['query_string']))
        
        return values
    
    def test_pattern_match(self, rule: WAFRule, value: str) -> bool:
        """Test if value matches rule pattern."""
        if not value:
            return False
        
        try:
            if rule.rule_type == 'REGEX':
                pattern = self.pattern_cache.get(rule.id)
                if pattern:
                    return bool(pattern.search(value))
                else:
                    flags = 0 if rule.case_sensitive else re.IGNORECASE
                    return bool(re.search(rule.rule_pattern, value, flags))
            
            elif rule.rule_type == 'STRING':
                if rule.case_sensitive:
                    return rule.rule_pattern in value
                else:
                    return rule.rule_pattern.lower() in value.lower()
            
            # Add other rule types as needed
            
        except Exception as e:
            logger.error(f"Error testing rule {rule.id}: {e}")
        
        return False
    
    def get_severity_score(self, severity: str) -> int:
        """Convert severity to numeric score."""
        severity_scores = {
            'LOW': 25,
            'MEDIUM': 50,
            'HIGH': 75,
            'CRITICAL': 100
        }
        return severity_scores.get(severity, 0)
    
    def update_rule_stats(self, rule: WAFRule):
        """Update rule match statistics."""
        try:
            rule.match_count += 1
            rule.last_triggered = timezone.now()
            rule.save(update_fields=['match_count', 'last_triggered'])
        except Exception as e:
            logger.error(f"Failed to update rule stats: {e}")
    
    def determine_action(self, threat_score: int, rule_results: Dict, ml_results: Dict) -> str:
        """Determine action based on analysis results."""
        # Check for critical rule matches
        critical_matches = [m for m in rule_results['matches'] if m['severity'] == 'CRITICAL']
        if critical_matches:
            return critical_matches[0]['action']
        
        # Check for high severity matches
        high_matches = [m for m in rule_results['matches'] if m['severity'] == 'HIGH']
        if high_matches:
            return high_matches[0]['action']
        
        # Use threat score for general decision
        if threat_score >= 90:
            return 'BLOCK'
        elif threat_score >= 70:
            return 'CHALLENGE'
        elif threat_score >= 50:
            return 'LOG'
        else:
            return 'ALLOW'
    
    def log_threat_detection(self, request, request_data: Dict, rule_results: Dict, 
                           ml_results: Dict, action: str):
        """Log threat detection event."""
        try:
            SecurityEvent.objects.create(
                event_type='WAF_THREAT_DETECTED',
                event_category='WAF',
                severity=self.get_event_severity(rule_results, ml_results),
                ip_address=get_client_ip(request),
                user_agent=request_data['user_agent'],
                request_method=request_data['method'],
                request_url=request_data['path'],
                request_headers=request_data['headers'],
                request_body=request_data.get('body', ''),
                user_id=request.user.id if request.user.is_authenticated else None,
                blocked=action in ['BLOCK', 'CHALLENGE'],
                action_taken=f'WAF action: {action}',
                risk_score=max(rule_results['threat_score'], ml_results['threat_score']),
                details={
                    'rule_matches': rule_results['matches'],
                    'ml_prediction': ml_results.get('prediction'),
                    'ml_confidence': ml_results.get('confidence'),
                    'action': action
                }
            )
        except Exception as e:
            logger.error(f"Failed to log WAF threat detection: {e}")
    
    def get_event_severity(self, rule_results: Dict, ml_results: Dict) -> str:
        """Determine event severity based on results."""
        if rule_results['matches']:
            severities = [m['severity'] for m in rule_results['matches']]
            if 'CRITICAL' in severities:
                return 'CRITICAL'
            elif 'HIGH' in severities:
                return 'HIGH'
            elif 'MEDIUM' in severities:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        # Use ML confidence for severity
        ml_confidence = ml_results.get('confidence', 0)
        if ml_confidence > 0.9:
            return 'HIGH'
        elif ml_confidence > 0.7:
            return 'MEDIUM'
        else:
            return 'LOW'


class MLThreatDetector:
    """Machine Learning-based threat detection."""
    
    def __init__(self):
        self.feature_extractors = {
            'url_features': URLFeatureExtractor(),
            'payload_features': PayloadFeatureExtractor(),
            'behavioral_features': BehavioralFeatureExtractor()
        }
        
        # Load pre-trained models (in production, load actual ML models)
        self.models = {
            'sql_injection': SQLInjectionDetector(),
            'xss': XSSDetector(),
            'anomaly': AnomalyDetector()
        }
    
    def analyze(self, request_data: Dict) -> Dict:
        """Analyze request using ML models."""
        # Extract features
        features = {}
        for name, extractor in self.feature_extractors.items():
            features[name] = extractor.extract(request_data)
        
        # Run through models
        predictions = {}
        max_confidence = 0
        best_prediction = 'benign'
        
        for model_name, model in self.models.items():
            result = model.predict(features)
            predictions[model_name] = result
            
            if result['confidence'] > max_confidence:
                max_confidence = result['confidence']
                best_prediction = result['prediction']
        
        # Calculate threat score
        threat_score = int(max_confidence * 100)
        
        return {
            'threat_score': threat_score,
            'prediction': best_prediction,
            'confidence': max_confidence,
            'model_predictions': predictions,
            'features': features
        }


class URLFeatureExtractor:
    """Extract features from URL components."""
    
    def extract(self, request_data: Dict) -> Dict:
        """Extract URL-based features."""
        url = request_data['path']
        query = request_data['query_string']
        
        features = {
            'url_length': len(url),
            'query_length': len(query),
            'param_count': len(request_data['get_params']),
            'special_char_ratio': self.calculate_special_char_ratio(url + query),
            'entropy': self.calculate_entropy(url + query),
            'suspicious_keywords': self.count_suspicious_keywords(url + query),
            'encoded_chars': self.count_encoded_chars(url + query),
            'path_depth': url.count('/'),
            'has_extension': '.' in url.split('/')[-1] if '/' in url else False
        }
        
        return features
    
    def calculate_special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters."""
        if not text:
            return 0.0
        
        special_chars = set('!@#$%^&*()[]{}|\\:";\'<>?,./`~')
        special_count = sum(1 for char in text if char in special_chars)
        
        return special_count / len(text)
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        from collections import Counter
        import math
        
        counts = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def count_suspicious_keywords(self, text: str) -> int:
        """Count suspicious keywords in text."""
        keywords = [
            'union', 'select', 'insert', 'delete', 'update', 'drop',
            'script', 'alert', 'eval', 'exec', 'system',
            '../', '..\\', 'etc/passwd', 'cmd.exe'
        ]
        
        text_lower = text.lower()
        return sum(1 for keyword in keywords if keyword in text_lower)
    
    def count_encoded_chars(self, text: str) -> int:
        """Count URL-encoded characters."""
        return text.count('%')


class PayloadFeatureExtractor:
    """Extract features from request payload."""
    
    def extract(self, request_data: Dict) -> Dict:
        """Extract payload-based features."""
        body = request_data.get('body', '')
        all_params = {**request_data['get_params'], **request_data['post_params']}
        
        features = {
            'body_length': len(body),
            'param_count': len(all_params),
            'avg_param_length': self.calculate_avg_param_length(all_params),
            'max_param_length': self.calculate_max_param_length(all_params),
            'sql_keywords': self.count_sql_keywords(body),
            'html_tags': self.count_html_tags(body),
            'javascript_keywords': self.count_javascript_keywords(body),
            'base64_patterns': self.count_base64_patterns(body),
            'binary_content': self.detect_binary_content(body)
        }
        
        return features
    
    def calculate_avg_param_length(self, params: Dict) -> float:
        """Calculate average parameter length."""
        if not params:
            return 0.0
        
        total_length = sum(len(str(value)) for value in params.values())
        return total_length / len(params)
    
    def calculate_max_param_length(self, params: Dict) -> int:
        """Calculate maximum parameter length."""
        if not params:
            return 0
        
        return max(len(str(value)) for value in params.values())
    
    def count_sql_keywords(self, text: str) -> int:
        """Count SQL keywords in text."""
        keywords = [
            'select', 'union', 'insert', 'update', 'delete', 'drop',
            'create', 'alter', 'exec', 'execute', 'sp_', 'xp_'
        ]
        
        text_lower = text.lower()
        return sum(text_lower.count(keyword) for keyword in keywords)
    
    def count_html_tags(self, text: str) -> int:
        """Count HTML tags in text."""
        return len(re.findall(r'<[^>]+>', text))
    
    def count_javascript_keywords(self, text: str) -> int:
        """Count JavaScript keywords in text."""
        keywords = [
            'javascript:', 'eval(', 'alert(', 'confirm(', 'prompt(',
            'setTimeout(', 'setInterval(', 'document.', 'window.'
        ]
        
        text_lower = text.lower()
        return sum(text_lower.count(keyword) for keyword in keywords)
    
    def count_base64_patterns(self, text: str) -> int:
        """Count potential base64 encoded content."""
        # Simple heuristic: look for base64-like patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        return len(re.findall(base64_pattern, text))
    
    def detect_binary_content(self, text: str) -> bool:
        """Detect binary content in text."""
        if not text:
            return False
        
        # Check for non-printable characters
        non_printable = sum(1 for char in text if ord(char) < 32 and char not in '\t\n\r')
        return non_printable > len(text) * 0.1


class BehavioralFeatureExtractor:
    """Extract behavioral features from request patterns."""
    
    def extract(self, request_data: Dict) -> Dict:
        """Extract behavioral features."""
        user_agent = request_data['user_agent']
        headers = request_data['headers']
        
        features = {
            'user_agent_length': len(user_agent),
            'missing_headers': self.count_missing_headers(headers),
            'suspicious_headers': self.count_suspicious_headers(headers),
            'header_order_anomaly': self.detect_header_order_anomaly(headers),
            'automation_indicators': self.detect_automation_indicators(user_agent, headers)
        }
        
        return features
    
    def count_missing_headers(self, headers: Dict) -> int:
        """Count missing common headers."""
        common_headers = [
            'accept', 'accept-language', 'accept-encoding',
            'connection', 'upgrade-insecure-requests'
        ]
        
        header_keys_lower = [key.lower() for key in headers.keys()]
        missing = sum(1 for header in common_headers if header not in header_keys_lower)
        
        return missing
    
    def count_suspicious_headers(self, headers: Dict) -> int:
        """Count suspicious headers."""
        suspicious = 0
        
        for key, value in headers.items():
            key_lower = key.lower()
            value_lower = str(value).lower()
            
            # Check for suspicious header names
            if any(sus in key_lower for sus in ['x-forwarded', 'x-real-ip', 'x-originating']):
                suspicious += 1
            
            # Check for suspicious values
            if any(sus in value_lower for sus in ['sqlmap', 'nikto', 'nmap', 'scanner']):
                suspicious += 1
        
        return suspicious
    
    def detect_header_order_anomaly(self, headers: Dict) -> bool:
        """Detect anomalous header ordering."""
        # This is a simplified check - in practice, you'd compare against
        # known browser header ordering patterns
        header_keys = list(headers.keys())
        
        # Check if Host header is not first (common anomaly)
        if header_keys and header_keys[0].lower() != 'host':
            return True
        
        return False
    
    def detect_automation_indicators(self, user_agent: str, headers: Dict) -> int:
        """Detect indicators of automated tools."""
        indicators = 0
        
        # Check user agent for automation tools
        automation_tools = [
            'python', 'curl', 'wget', 'httpie', 'postman',
            'insomnia', 'selenium', 'phantomjs', 'headless'
        ]
        
        ua_lower = user_agent.lower()
        indicators += sum(1 for tool in automation_tools if tool in ua_lower)
        
        # Check for missing browser-specific headers
        if 'accept-language' not in [k.lower() for k in headers.keys()]:
            indicators += 1
        
        return indicators


class SQLInjectionDetector:
    """ML-based SQL injection detector."""
    
    def predict(self, features: Dict) -> Dict:
        """Predict if request contains SQL injection."""
        # This is a simplified rule-based approach
        # In production, use actual ML models
        
        score = 0
        
        # URL features
        url_features = features.get('url_features', {})
        if url_features.get('suspicious_keywords', 0) > 2:
            score += 0.4
        if url_features.get('special_char_ratio', 0) > 0.3:
            score += 0.3
        
        # Payload features
        payload_features = features.get('payload_features', {})
        if payload_features.get('sql_keywords', 0) > 3:
            score += 0.5
        if payload_features.get('max_param_length', 0) > 1000:
            score += 0.2
        
        prediction = 'sql_injection' if score > 0.6 else 'benign'
        
        return {
            'prediction': prediction,
            'confidence': min(score, 1.0)
        }


class XSSDetector:
    """ML-based XSS detector."""
    
    def predict(self, features: Dict) -> Dict:
        """Predict if request contains XSS."""
        score = 0
        
        # Payload features
        payload_features = features.get('payload_features', {})
        if payload_features.get('html_tags', 0) > 0:
            score += 0.4
        if payload_features.get('javascript_keywords', 0) > 0:
            score += 0.5
        
        # URL features
        url_features = features.get('url_features', {})
        if url_features.get('encoded_chars', 0) > 5:
            score += 0.3
        
        prediction = 'xss' if score > 0.6 else 'benign'
        
        return {
            'prediction': prediction,
            'confidence': min(score, 1.0)
        }


class AnomalyDetector:
    """ML-based anomaly detector."""
    
    def predict(self, features: Dict) -> Dict:
        """Predict if request is anomalous."""
        score = 0
        
        # Behavioral features
        behavioral_features = features.get('behavioral_features', {})
        if behavioral_features.get('missing_headers', 0) > 3:
            score += 0.3
        if behavioral_features.get('automation_indicators', 0) > 2:
            score += 0.4
        
        # URL features
        url_features = features.get('url_features', {})
        if url_features.get('entropy', 0) > 4.5:
            score += 0.3
        
        prediction = 'anomaly' if score > 0.5 else 'benign'
        
        return {
            'prediction': prediction,
            'confidence': min(score, 1.0)
        }


# Global WAF engine instance
waf_engine = WAFEngine()
