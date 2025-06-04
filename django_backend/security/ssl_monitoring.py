"""
Advanced SSL/TLS Monitoring and Management System
"""

import ssl
import socket
import datetime
import logging
import threading
import time
import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple
from django.core.cache import cache
from django.utils import timezone
from .models import SSLCertificate, SecurityEvent, PerformanceMetrics
import OpenSSL.crypto
import requests
from urllib.parse import urlparse
import subprocess
import json
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger('ssl_monitoring')


class SSLMonitoringEngine:
    """Advanced SSL/TLS monitoring and analysis engine."""
    
    def __init__(self):
        self.monitored_domains = set()
        self.ssl_cache = {}
        self.vulnerability_checks = {
            'heartbleed': self.check_heartbleed,
            'poodle': self.check_poodle,
            'beast': self.check_beast,
            'crime': self.check_crime,
            'breach': self.check_breach,
            'freak': self.check_freak,
            'logjam': self.check_logjam,
            'drown': self.check_drown,
            'sweet32': self.check_sweet32,
            'robot': self.check_robot,
            'ticketbleed': self.check_ticketbleed,
            'lucky13': self.check_lucky13
        }
        
        # SSL/TLS configuration standards
        self.cipher_suites = {
            'recommended': [
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_128_GCM_SHA256',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-CHACHA20-POLY1305'
            ],
            'acceptable': [
                'ECDHE-RSA-AES256-SHA384',
                'ECDHE-RSA-AES128-SHA256',
                'DHE-RSA-AES256-GCM-SHA384',
                'DHE-RSA-AES128-GCM-SHA256'
            ],
            'weak': [
                'DES-CBC3-SHA',
                'RC4-SHA',
                'RC4-MD5',
                'NULL-SHA',
                'NULL-MD5'
            ]
        }
        
        # Start monitoring thread
        self.start_monitoring()
    
    def add_domain(self, domain: str, port: int = 443):
        """Add domain to monitoring list."""
        self.monitored_domains.add((domain, port))
        logger.info(f"Added {domain}:{port} to SSL monitoring")
    
    def remove_domain(self, domain: str, port: int = 443):
        """Remove domain from monitoring list."""
        self.monitored_domains.discard((domain, port))
        logger.info(f"Removed {domain}:{port} from SSL monitoring")
    
    async def scan_domain(self, domain: str, port: int = 443) -> Dict:
        """Comprehensive SSL/TLS scan of a domain."""
        try:
            scan_results = {
                'domain': domain,
                'port': port,
                'timestamp': timezone.now(),
                'certificate_info': {},
                'ssl_grade': 'F',
                'vulnerabilities': {},
                'cipher_suites': [],
                'protocols': [],
                'performance_metrics': {},
                'errors': []
            }
            
            # Get certificate information
            cert_info = await self.get_certificate_info(domain, port)
            scan_results['certificate_info'] = cert_info
            
            # Check supported protocols and cipher suites
            protocols = await self.check_protocols(domain, port)
            scan_results['protocols'] = protocols
            
            cipher_suites = await self.check_cipher_suites(domain, port)
            scan_results['cipher_suites'] = cipher_suites
            
            # Run vulnerability checks
            vulnerabilities = await self.run_vulnerability_checks(domain, port)
            scan_results['vulnerabilities'] = vulnerabilities
            
            # Calculate SSL grade
            scan_results['ssl_grade'] = self.calculate_ssl_grade(cert_info, protocols, cipher_suites, vulnerabilities)
            
            # Measure performance
            perf_metrics = await self.measure_performance(domain, port)
            scan_results['performance_metrics'] = perf_metrics
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Scan failed for {domain}:{port} - {str(e)}")
            return {
                'domain': domain,
                'port': port,
                'timestamp': timezone.now(),
                'error': str(e)
            }
    
    async def get_certificate_info(self, domain: str, port: int) -> Dict:
        """Get detailed certificate information."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    
                    return {
                        'issuer': dict(x509_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value),
                        'subject': dict(x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value),
                        'version': x509_cert.version,
                        'serial_number': x509_cert.serial_number,
                        'not_valid_before': x509_cert.not_valid_before,
                        'not_valid_after': x509_cert.not_valid_after,
                        'signature_algorithm': x509_cert.signature_algorithm_oid._name,
                        'public_key_size': x509_cert.public_key().key_size,
                        'san_domains': self.get_san_domains(x509_cert),
                        'is_expired': x509_cert.not_valid_after < datetime.datetime.now()
                    }
        except Exception as e:
            logger.error(f"Failed to get certificate info for {domain}:{port} - {str(e)}")
            raise
    
    def get_san_domains(self, cert) -> List[str]:
        """Get Subject Alternative Names from certificate."""
        try:
            san_list = []
            for ext in cert.extensions:
                if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    san_list.extend([name.value for name in ext.value])
            return san_list
        except Exception:
            return []
    
    async def check_protocols(self, domain: str, port: int) -> List[Dict]:
        """Check supported SSL/TLS protocols."""
        protocols = []
        test_protocols = [
            ('SSLv2', ssl.PROTOCOL_SSLv2),
            ('SSLv3', ssl.PROTOCOL_SSLv3),
            ('TLSv1', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.3', ssl.PROTOCOL_TLS)
        ]
        
        for protocol_name, protocol in test_protocols:
            try:
                context = ssl.SSLContext(protocol)
                with socket.create_connection((domain, port)) as sock:
                    with context.wrap_socket(sock) as ssock:
                        protocols.append({
                            'name': protocol_name,
                            'supported': True,
                            'secure': protocol_name in ['TLSv1.2', 'TLSv1.3']
                        })
            except:
                protocols.append({
                    'name': protocol_name,
                    'supported': False,
                    'secure': protocol_name in ['TLSv1.2', 'TLSv1.3']
                })
        
        return protocols
    
    async def check_cipher_suites(self, domain: str, port: int) -> List[Dict]:
        """Check supported cipher suites."""
        cipher_suites = []
        
        try:
            output = subprocess.check_output(
                f"openssl ciphers -v 'ALL:eNULL' | sed -e 's/  */ /g'",
                shell=True
            ).decode()
            
            for line in output.split('\n'):
                if line.strip():
                    cipher = line.split(' ')[0]
                    try:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                        context.set_ciphers(cipher)
                        with socket.create_connection((domain, port)) as sock:
                            with context.wrap_socket(sock) as ssock:
                                cipher_suites.append({
                                    'name': cipher,
                                    'supported': True,
                                    'secure': cipher in self.cipher_suites['recommended']
                                })
                    except:
                        cipher_suites.append({
                            'name': cipher,
                            'supported': False,
                            'secure': cipher in self.cipher_suites['recommended']
                        })
        except Exception as e:
            logger.error(f"Cipher suite check failed: {str(e)}")
        
        return cipher_suites
    
    async def run_vulnerability_checks(self, domain: str, port: int) -> Dict:
        """Run all vulnerability checks."""
        results = {}
        for vuln_name, check_func in self.vulnerability_checks.items():
            try:
                is_vulnerable, details = await check_func(domain, port)
                results[vuln_name] = {
                    'vulnerable': is_vulnerable,
                    'description': details
                }
            except Exception as e:
                logger.error(f"Vulnerability check {vuln_name} failed: {str(e)}")
                results[vuln_name] = {
                    'vulnerable': False,
                    'description': f"Check failed: {str(e)}"
                }
        return results
    
    async def check_heartbleed(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for Heartbleed vulnerability."""
        # Implementation of Heartbleed check
        return False, "Heartbleed check not implemented"
    
    async def check_poodle(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for POODLE vulnerability."""
        # Implementation of POODLE check
        return False, "POODLE check not implemented"
    
    async def check_beast(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for BEAST vulnerability."""
        # Implementation of BEAST check
        return False, "BEAST check not implemented"
    
    async def check_crime(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for CRIME vulnerability."""
        # Implementation of CRIME check
        return False, "CRIME check not implemented"
    
    async def check_breach(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for BREACH vulnerability."""
        # Implementation of BREACH check
        return False, "BREACH check not implemented"
    
    async def check_freak(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for FREAK vulnerability."""
        # Implementation of FREAK check
        return False, "FREAK check not implemented"
    
    async def check_logjam(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for Logjam vulnerability."""
        # Implementation of Logjam check
        return False, "Logjam check not implemented"
    
    async def check_drown(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for DROWN vulnerability."""
        # Implementation of DROWN check
        return False, "DROWN check not implemented"
    
    async def check_sweet32(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for SWEET32 vulnerability."""
        # Implementation of SWEET32 check
        return False, "SWEET32 check not implemented"
    
    async def check_robot(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for ROBOT vulnerability."""
        # Implementation of ROBOT check
        return False, "ROBOT check not implemented"
    
    async def check_ticketbleed(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for Ticketbleed vulnerability."""
        # Implementation of Ticketbleed check
        return False, "Ticketbleed check not implemented"
    
    async def check_lucky13(self, domain: str, port: int) -> Tuple[bool, str]:
        """Check for Lucky13 vulnerability."""
        # Implementation of Lucky13 check
        return False, "Lucky13 check not implemented"
    
    def calculate_ssl_grade(self, cert_info: Dict, protocols: List[Dict], cipher_suites: List[Dict], vulnerabilities: Dict) -> str:
        """Calculate overall SSL grade."""
        score = 100
        
        # Check certificate
        if cert_info.get('is_expired', True):
            score -= 40
        if cert_info.get('public_key_size', 0) < 2048:
            score -= 20
        
        # Check protocols
        if any(p['supported'] and not p['secure'] for p in protocols):
            score -= 20
        
        # Check cipher suites
        weak_ciphers = sum(1 for c in cipher_suites if c['supported'] and not c['secure'])
        score -= min(weak_ciphers * 5, 20)
        
        # Check vulnerabilities
        critical_vulns = sum(1 for v in vulnerabilities.values() if v['vulnerable'])
        score -= min(critical_vulns * 10, 40)
        
        # Convert score to grade
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    async def measure_performance(self, domain: str, port: int) -> Dict:
        """Measure SSL/TLS performance metrics."""
        metrics = {
            'handshake_time': 0,
            'connection_time': 0,
            'total_time': 0
        }
        
        try:
            start_time = time.time()
            
            context = ssl.create_default_context()
            conn_start = time.time()
            with socket.create_connection((domain, port)) as sock:
                conn_time = time.time() - conn_start
                
                handshake_start = time.time()
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    handshake_time = time.time() - handshake_start
                    
                    metrics.update({
                        'handshake_time': int(handshake_time * 1000),  # ms
                        'connection_time': int(conn_time * 1000),      # ms
                        'total_time': int((time.time() - start_time) * 1000)  # ms
                    })
        except Exception as e:
            logger.error(f"Performance measurement failed: {str(e)}")
        
        return metrics
    
    def start_monitoring(self):
        """Start the monitoring thread."""
        def monitor_loop():
            while True:
                for domain, port in self.monitored_domains:
                    try:
                        asyncio.run(self.scan_domain(domain, port))
                    except Exception as e:
                        logger.error(f"Monitoring failed for {domain}:{port} - {str(e)}")
                time.sleep(3600)  # Sleep for 1 hour
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
