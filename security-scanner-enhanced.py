import os
import re
import json
import yaml
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Any
from datetime import datetime
import logging
from fpdf import FPDF
import platform
import subprocess
import magic  # for file type detection
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import ssl
import socket
from urllib.parse import urlparse

@dataclass
class SecurityConfig:
    """Configuration for security scanning"""
    min_password_length: int = 8
    max_file_size_mb: int = 100
    allowed_file_types: List[str] = None
    excluded_dirs: List[str] = None
    
    def __post_init__(self):
        self.allowed_file_types = [
            '.py', '.js', '.php', '.java', '.html', '.css', 
            '.xml', '.json', '.yml', '.yaml', '.md', '.txt',
            '.sh', '.bash', '.env', '.config', '.htaccess'
        ]
        self.excluded_dirs = [
            'node_modules', 'venv', '__pycache__', 
            '.git', '.idea', '.vscode', 'build', 'dist'
        ]

class EnhancedSecurityScorer:
    def __init__(self, project_path: str, config: SecurityConfig = None):
        self.project_path = Path(project_path)
        self.config = config or SecurityConfig()
        self.total_score = 100
        self.findings = []
        self.logger = self._setup_logger()
        
        # Enhanced weights
        self.weights = {
            'secrets_exposed': 25,
            'vulnerabilities': 20,
            'secure_configs': 15,
            'dependencies': 10,
            'code_quality': 10,
            'access_controls': 10,
            'ssl_tls': 5,
            'file_permissions': 5
        }
        
        # Extended security patterns
        self.secret_patterns = {
            'api_key': r'(?i)(api[_-]key|apikey|secret[_-]key|token)[\s]*[=:]\s*[\'"]([\w\-+=]+)[\'"]',
            'password': r'(?i)(password|passwd|pwd)[\s]*[=:]\s*[\'"]([\w\-+=]+)[\'"]',
            'aws_key': r'(?i)(aws[_-]access[_-]key|aws[_-]secret[_-]key)[\s]*[=:]\s*[\'"]([\w\-+=]+)[\'"]',
            'private_key': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
            'ssh_key': r'ssh-rsa\s+AAAA[0-9A-Za-z+/]+[=]{0,3}',
            'github_token': r'(?i)github[_-]token.*?[\'"][0-9a-zA-Z]{35,40}[\'"]',
            'google_oauth': r'(?i)(google|gcp|firebase).*?[\'"][0-9a-zA-Z-_]{24}[\'"]',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        }
        
        self.vulnerable_patterns = {
            'sql_injection': [
                r'(?i)execute\s*\(\s*[\'"].*?\%s.*?[\'"]\s*%',
                r'(?i).*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*?\+\s*(?:request|params|user)',
            ],
            'xss': [
                r'(?i)innerHTML|document\.write\s*\(',
                r'(?i)\.html\(\s*(?:request|params|user)',
                r'(?i)eval\(\s*(?:request|params|user)'
            ],
            'command_injection': [
                r'(?i)(?:exec|system|popen|subprocess\.call)\s*\(',
                r'(?i)os\.system\(.*?\+\s*(?:request|params|user)',
                r'(?i)shell=True'
            ],
            'path_traversal': [
                r'(?i)\.\.\/|\.\.\\',
                r'(?i)file:\/\/\/',
                r'(?i)\/etc\/passwd'
            ],
            'insecure_deserialize': [
                r'(?i)pickle\.loads\(',
                r'(?i)yaml\.load\(',
                r'(?i)marshal\.loads\('
            ],
            'cors_misconfiguration': [
                r'(?i)Access-Control-Allow-Origin:\s*\*',
                r'(?i)add_header\s+Access-Control-Allow-Origin\s+"\*"'
            ]
        }

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('SecurityScorer')
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # File handler
        fh = logging.FileHandler('security_scan.log')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        return logger

    def check_htaccess(self) -> List[Dict]:
        findings = []
        htaccess_path = self.project_path / '.htaccess'
        
        if htaccess_path.exists():
            with open(htaccess_path, 'r') as f:
                content = f.read()
                
            # Check for common security misconfigurations
            if 'Options +Indexes' in content:
                findings.append({
                    'type': 'htaccess_config',
                    'severity': 'HIGH',
                    'description': 'Directory listing is enabled',
                    'file': str(htaccess_path)
                })
                
            if not re.search(r'ServerSignature\s+Off', content, re.I):
                findings.append({
                    'type': 'htaccess_config',
                    'severity': 'MEDIUM',
                    'description': 'Server signature is not disabled',
                    'file': str(htaccess_path)
                })
                
            if not re.search(r'Header\s+always\s+set\s+X-Frame-Options\s+"SAMEORIGIN"', content, re.I):
                findings.append({
                    'type': 'htaccess_config',
                    'severity': 'MEDIUM',
                    'description': 'X-Frame-Options header is not set',
                    'file': str(htaccess_path)
                })
        
        return findings

    def check_ssl_configuration(self) -> List[Dict]:
        findings = []
        
        # Check for SSL/TLS configuration in common web server configs
        config_files = [
            'nginx.conf',
            'apache2.conf',
            'httpd.conf',
            '.htaccess'
        ]
        
        for config_file in config_files:
            config_path = self.project_path / config_file
            if config_path.exists():
                with open(config_path, 'r') as f:
                    content = f.read()
                    
                if 'SSLv3' in content or 'TLSv1.0' in content:
                    findings.append({
                        'type': 'ssl_config',
                        'severity': 'HIGH',
                        'description': f'Outdated SSL/TLS protocol version found in {config_file}',
                        'file': str(config_path)
                    })
                    
                if not re.search(r'ssl_protocols\s+TLSv1.2\s+TLSv1.3', content):
                    findings.append({
                        'type': 'ssl_config',
                        'severity': 'MEDIUM',
                        'description': f'Modern TLS protocols not explicitly enabled in {config_file}',
                        'file': str(config_path)
                    })
        
        return findings

    def generate_pdf_report(self, results: Dict, output_file: str = 'security_report.pdf'):
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Security Scan Report', 0, 1, 'C')
        pdf.ln(10)
        
        # Project Information
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, f"Project: {results['project_path']}", 0, 1)
        pdf.cell(0, 10, f"Scan Date: {results['scan_time']}", 0, 1)
        pdf.cell(0, 10, f"Security Score: {results['security_score']}/100", 0, 1)
        pdf.ln(10)
        
        # Summary
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Summary', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f"Total Findings: {results['summary']['total_findings']}", 0, 1)
        pdf.cell(0, 10, f"High Severity: {results['summary']['high_severity']}", 0, 1)
        pdf.cell(0, 10, f"Medium Severity: {results['summary']['medium_severity']}", 0, 1)
        pdf.cell(0, 10, f"Low Severity: {results['summary']['low_severity']}", 0, 1)
        pdf.ln(10)
        
        # Detailed Findings
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Detailed Findings', 0, 1)
        pdf.ln(5)
        
        for finding in results['findings']:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, f"Finding Type: {finding['type']}", 0, 1)
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 10, f"Severity: {finding['severity']}", 0, 1)
            pdf.cell(0, 10, f"Description: {finding['description']}", 0, 1)
            pdf.cell(0, 10, f"File: {finding['file']}", 0, 1)
            if 'line' in finding:
                pdf.cell(0, 10, f"Line: {finding['line']}", 0, 1)
            pdf.ln(5)
        
        # Save the PDF
        pdf.output(output_file)
        return output_file

    def scan_project(self) -> Dict:
        self.logger.info(f"Starting security scan for project: {self.project_path}")
        all_findings = []
        
        try:
            # Parallel scanning for large projects
            with ThreadPoolExecutor() as executor:
                file_paths = []
                for root, _, files in os.walk(self.project_path):
                    if any(excluded in root for excluded in self.config.excluded_dirs):
                        continue
                    
                    for file in files:
                        if file.startswith('.') or not any(file.endswith(ext) for ext in self.config.allowed_file_types):
                            continue
                        file_paths.append(Path(root) / file)
                
                # Submit scanning tasks
                future_to_file = {
                    executor.submit(self._scan_file, file_path): file_path 
                    for file_path in file_paths
                }
                
                # Collect results
                for future in future_to_file:
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                    except Exception as e:
                        self.logger.error(f"Error scanning file {future_to_file[future]}: {str(e)}")
            
            # Additional checks
            all_findings.extend(self.check_htaccess())
            all_findings.extend(self.check_ssl_configuration())
            
            # Calculate final score
            final_score = self.calculate_score(all_findings)
            
            results = {
                'scan_time': datetime.now().isoformat(),
                'project_path': str(self.project_path),
                'security_score': round(final_score, 2),
                'findings': all_findings,
                'summary': {
                    'total_findings': len(all_findings),
                    'high_severity': len([f for f in all_findings if f['severity'] == 'HIGH']),
                    'medium_severity': len([f for f in all_findings if f['severity'] == 'MEDIUM']),
                    'low_severity': len([f for f in all_findings if f['severity'] == 'LOW'])
                },
                'scan_metadata': {
                    'python_version': platform.python_version(),
                    'os_platform': platform.platform(),
                    'scanner_version': '2.0.0'
                }
            }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error during project scan: {str(e)}")
            raise

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Enhanced Project Security Scorer')
    parser.add_argument('project_path', help='Path to the project directory to scan')
    parser.add_argument('--output', help='Output file path for JSON report', default='security_report.json')
    parser.add_argument('--pdf', help='Generate PDF report', action='store_true')
    parser.add_argument('--config', help='Path to custom configuration file')
    
    args = parser.parse_args()
    
    # Load custom configuration if provided
    config = SecurityConfig()
    if args.config:
        with open(args.config, 'r') as f:
            custom_config = yaml.safe_load(f)
            config = SecurityConfig(**custom_config)
    
    scorer = EnhancedSecurityScorer(args.project_path, config)
    results = scorer.scan_project()
    
    # Save JSON report
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Generate PDF report if requested
    if args.pdf:
        pdf_path = scorer.generate_pdf_report(results)
        print(f"\nPDF report generated: {pdf_path}")
    
    print(f"\nSecurity Scan Complete!")
    print(f"Security Score: {results['security_score']}/100")
    print(f"\nFindings Summary:")
    print(f"Total Findings: {results['summary']['total_findings']}")
    print(f"High Severity: {results['summary']['high_severity']}")
    print(f"Medium Severity: {results['summary']['medium_severity']}")
    print(f"Low Severity: {results['summary']['low_severity']}")
    print(f"\nDetailed report saved to: {args.output}")

if __name__ == "__main__":
    main()
