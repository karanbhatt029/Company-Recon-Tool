#!/usr/bin/env python3
"""
Company Reconnaissance Automation Tool
Gathers publicly available information about a company including:
- Open S3 buckets and cloud storage
- GitHub repositories
- Subdomains and DNS records
- Technology stack
- Social media presence
- Job postings
"""

import requests
import json
import re
import time
from urllib.parse import urlparse, quote
from typing import Dict, List, Set
import concurrent.futures
from datetime import datetime
import socket
import base64

class CompanyRecon:
    def __init__(self, company_name: str, domain: str = None):
        self.company_name = company_name
        self.domain = domain
        self.results = {
            'company': company_name,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            's3_buckets': [],
            'gcs_buckets': [],
            'azure_blobs': [],
            'github_repos': [],
            'subdomains': [],
            'dns_records': {},
            'certificate_transparency': [],
            'whois_info': {},
            'technologies': [],
            'social_media': {},
            'job_postings': [],
            'emails': set(),
            'errors': []
        }
        
    def search_cloud_storage(self):
        """Search for exposed cloud storage buckets (AWS S3, GCS, Azure)"""
        print(f"\n[*] Searching for cloud storage buckets...")
        
        # Common bucket naming patterns
        variations = [
            self.company_name.lower().replace(' ', ''),
            self.company_name.lower().replace(' ', '-'),
            self.company_name.lower().replace(' ', '_'),
        ]
        
        if self.domain:
            domain_parts = self.domain.split('.')[0]
            variations.extend([domain_parts, f"{domain_parts}-backup", f"{domain_parts}-assets"])
        
        # Common suffixes
        suffixes = ['', '-backup', '-backups', '-data', '-assets', '-files', '-docs', 
                   '-images', '-media', '-public', '-private', '-prod', '-dev', '-staging']
        
        bucket_names = []
        for var in variations:
            for suffix in suffixes:
                bucket_names.append(f"{var}{suffix}")
        
        # AWS S3 Buckets
        print("  [*] Checking AWS S3...")
        found_s3 = []
        for bucket in bucket_names[:15]:  # Limit to avoid rate limits
            try:
                url = f"https://{bucket}.s3.amazonaws.com"
                response = requests.head(url, timeout=3)
                if response.status_code in [200, 403]:
                    found_s3.append({
                        'name': bucket,
                        'url': url,
                        'status': 'accessible' if response.status_code == 200 else 'exists_but_forbidden'
                    })
                    print(f"    [+] S3 Found: {bucket} ({response.status_code})")
            except:
                pass
        
        # Google Cloud Storage
        print("  [*] Checking Google Cloud Storage...")
        found_gcs = []
        for bucket in bucket_names[:15]:
            try:
                url = f"https://storage.googleapis.com/{bucket}"
                response = requests.head(url, timeout=3)
                if response.status_code in [200, 403]:
                    found_gcs.append({
                        'name': bucket,
                        'url': url,
                        'status': 'accessible' if response.status_code == 200 else 'exists_but_forbidden'
                    })
                    print(f"    [+] GCS Found: {bucket} ({response.status_code})")
            except:
                pass
        
        # Azure Blob Storage
        print("  [*] Checking Azure Blob Storage...")
        found_azure = []
        for bucket in bucket_names[:15]:
            try:
                # Azure format: https://{storage-account}.blob.core.windows.net/{container}
                url = f"https://{bucket}.blob.core.windows.net/"
                response = requests.head(url, timeout=3)
                if response.status_code in [200, 400, 403]:  # 400 can indicate existence
                    found_azure.append({
                        'name': bucket,
                        'url': url,
                        'status': 'accessible' if response.status_code == 200 else 'exists_but_forbidden'
                    })
                    print(f"    [+] Azure Found: {bucket} ({response.status_code})")
            except:
                pass
        
        self.results['s3_buckets'] = found_s3
        self.results['gcs_buckets'] = found_gcs
        self.results['azure_blobs'] = found_azure
        
    def search_github(self):
        """Search GitHub for company repositories"""
        print(f"\n[*] Searching GitHub...")
        
        try:
            # Search for organization
            url = f"https://api.github.com/search/users?q={quote(self.company_name)}+type:org"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('items'):
                    org = data['items'][0]
                    
                    # Get organization repos
                    repos_url = org['repos_url']
                    repos_response = requests.get(repos_url, timeout=10)
                    
                    if repos_response.status_code == 200:
                        repos = repos_response.json()
                        for repo in repos[:10]:  # First 10 repos
                            self.results['github_repos'].append({
                                'name': repo['name'],
                                'url': repo['html_url'],
                                'description': repo.get('description', ''),
                                'stars': repo['stargazers_count'],
                                'language': repo.get('language', 'Unknown')
                            })
                            print(f"  [+] Repo: {repo['name']} ({repo['stargazers_count']} stars)")
        except Exception as e:
            self.results['errors'].append(f"GitHub search error: {str(e)}")
            print(f"  [-] Error: {str(e)}")
    
    def enumerate_dns_records(self):
        """Enumerate DNS records for the domain"""
        if not self.domain:
            return
            
        print(f"\n[*] Enumerating DNS records for {self.domain}...")
        
        dns_records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': []
        }
        
        # A Records (IPv4)
        try:
            ips = socket.getaddrinfo(self.domain, None, socket.AF_INET)
            for ip in ips:
                if ip[4][0] not in [record['value'] for record in dns_records['A']]:
                    dns_records['A'].append({'type': 'A', 'value': ip[4][0]})
                    print(f"  [+] A: {ip[4][0]}")
        except:
            pass
        
        # AAAA Records (IPv6)
        try:
            ips = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
            for ip in ips:
                if ip[4][0] not in [record['value'] for record in dns_records['AAAA']]:
                    dns_records['AAAA'].append({'type': 'AAAA', 'value': ip[4][0]})
                    print(f"  [+] AAAA: {ip[4][0]}")
        except:
            pass
        
        # MX Records (Mail servers) - using dig-like approach
        try:
            import subprocess
            result = subprocess.run(['nslookup', '-type=mx', self.domain], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'mail exchanger' in line.lower():
                        parts = line.split('=')
                        if len(parts) > 1:
                            mx_record = parts[1].strip()
                            dns_records['MX'].append({'type': 'MX', 'value': mx_record})
                            print(f"  [+] MX: {mx_record}")
        except:
            pass
        
        # NS Records (Name servers)
        try:
            import subprocess
            result = subprocess.run(['nslookup', '-type=ns', self.domain], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'nameserver' in line.lower():
                        parts = line.split('=')
                        if len(parts) > 1:
                            ns_record = parts[1].strip()
                            dns_records['NS'].append({'type': 'NS', 'value': ns_record})
                            print(f"  [+] NS: {ns_record}")
        except:
            pass
        
        # TXT Records
        try:
            import subprocess
            result = subprocess.run(['nslookup', '-type=txt', self.domain], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '"' in line and 'text' not in line.lower():
                        txt_record = line.strip()
                        if txt_record and txt_record not in [r['value'] for r in dns_records['TXT']]:
                            dns_records['TXT'].append({'type': 'TXT', 'value': txt_record})
                            print(f"  [+] TXT: {txt_record[:80]}...")
        except:
            pass
        
        self.results['dns_records'] = dns_records
    
    def enumerate_subdomains(self):
        """Enumerate subdomains using various techniques"""
        if not self.domain:
            return
            
        print(f"\n[*] Enumerating subdomains for {self.domain}...")
        
        # Common subdomain prefixes
        common_subs = ['www', 'mail', 'ftp', 'admin', 'portal', 'blog', 'shop', 
                      'api', 'dev', 'staging', 'test', 'demo', 'app', 'mobile',
                      'cdn', 'assets', 'static', 'images', 'media', 'docs']
        
        found_subs = []
        for sub in common_subs:
            subdomain = f"{sub}.{self.domain}"
            try:
                # Simple check - try to resolve
                import socket
                socket.gethostbyname(subdomain)
                found_subs.append(subdomain)
                print(f"  [+] Found: {subdomain}")
            except:
                pass
        
        self.results['subdomains'] = found_subs
    
    def search_certificate_transparency(self):
        """Search Certificate Transparency logs for subdomains"""
        if not self.domain:
            return
            
        print(f"\n[*] Searching Certificate Transparency logs...")
        
        try:
            # Using crt.sh API
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                certs = response.json()
                
                # Extract unique subdomains
                subdomains = set()
                for cert in certs:
                    name_value = cert.get('name_value', '')
                    # Split by newlines as crt.sh can return multiple domains
                    for domain in name_value.split('\n'):
                        domain = domain.strip().lower()
                        if domain.endswith(self.domain) and '*' not in domain:
                            subdomains.add(domain)
                
                # Get detailed info for unique certificates
                cert_details = []
                seen_fingerprints = set()
                
                for cert in certs[:20]:  # Limit to first 20 for performance
                    fingerprint = cert.get('id')
                    if fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(fingerprint)
                        cert_details.append({
                            'id': fingerprint,
                            'issuer': cert.get('issuer_name', 'Unknown'),
                            'common_name': cert.get('common_name', ''),
                            'not_before': cert.get('not_before', ''),
                            'not_after': cert.get('not_after', ''),
                            'domains': cert.get('name_value', '').split('\n')
                        })
                
                self.results['certificate_transparency'] = {
                    'unique_subdomains': sorted(list(subdomains)),
                    'total_certificates': len(certs),
                    'certificate_samples': cert_details
                }
                
                print(f"  [+] Found {len(subdomains)} unique subdomains from {len(certs)} certificates")
                for subdomain in sorted(list(subdomains))[:10]:  # Show first 10
                    print(f"    - {subdomain}")
                if len(subdomains) > 10:
                    print(f"    ... and {len(subdomains) - 10} more")
                    
        except Exception as e:
            self.results['errors'].append(f"Certificate Transparency error: {str(e)}")
            print(f"  [-] Error: {str(e)}")
    
    def get_whois_info(self):
        """Get WHOIS information for the domain"""
        if not self.domain:
            return
            
        print(f"\n[*] Fetching WHOIS information...")
        
        try:
            import subprocess
            result = subprocess.run(['whois', self.domain], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                whois_text = result.stdout
                
                # Parse common WHOIS fields
                whois_data = {
                    'raw': whois_text,
                    'registrar': '',
                    'creation_date': '',
                    'expiration_date': '',
                    'name_servers': [],
                    'status': [],
                    'organization': ''
                }
                
                for line in whois_text.split('\n'):
                    line_lower = line.lower()
                    
                    # Registrar
                    if 'registrar:' in line_lower:
                        whois_data['registrar'] = line.split(':', 1)[1].strip()
                    
                    # Creation date
                    if any(x in line_lower for x in ['creation date:', 'created:', 'registered:']):
                        whois_data['creation_date'] = line.split(':', 1)[1].strip()
                    
                    # Expiration date
                    if any(x in line_lower for x in ['expir', 'registry expiry']):
                        whois_data['expiration_date'] = line.split(':', 1)[1].strip()
                    
                    # Name servers
                    if 'name server:' in line_lower or 'nserver:' in line_lower:
                        ns = line.split(':', 1)[1].strip()
                        if ns and ns not in whois_data['name_servers']:
                            whois_data['name_servers'].append(ns)
                    
                    # Status
                    if 'status:' in line_lower or 'domain status:' in line_lower:
                        status = line.split(':', 1)[1].strip()
                        if status and status not in whois_data['status']:
                            whois_data['status'].append(status)
                    
                    # Organization
                    if 'organization:' in line_lower or 'org:' in line_lower:
                        whois_data['organization'] = line.split(':', 1)[1].strip()
                
                self.results['whois_info'] = whois_data
                
                print(f"  [+] Registrar: {whois_data['registrar']}")
                print(f"  [+] Organization: {whois_data['organization']}")
                print(f"  [+] Created: {whois_data['creation_date']}")
                print(f"  [+] Expires: {whois_data['expiration_date']}")
                if whois_data['name_servers']:
                    print(f"  [+] Name Servers: {', '.join(whois_data['name_servers'][:3])}")
                
        except FileNotFoundError:
            self.results['errors'].append("WHOIS command not found. Install whois utility.")
            print("  [-] WHOIS utility not installed")
        except Exception as e:
            self.results['errors'].append(f"WHOIS error: {str(e)}")
            print(f"  [-] Error: {str(e)}")
    
    def detect_technologies(self):
        """Detect technologies used by the company website"""
        if not self.domain:
            return
            
        print(f"\n[*] Detecting technologies...")
        
        try:
            url = f"https://{self.domain}"
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            
            headers = response.headers
            html = response.text.lower()
            
            techs = []
            
            # Check headers
            if 'Server' in headers:
                techs.append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                techs.append(f"Powered by: {headers['X-Powered-By']}")
            
            # Check HTML content
            if 'wordpress' in html:
                techs.append("WordPress")
            if 'react' in html or 'reactjs' in html:
                techs.append("React")
            if 'angular' in html:
                techs.append("Angular")
            if 'vue' in html or 'vuejs' in html:
                techs.append("Vue.js")
            if 'bootstrap' in html:
                techs.append("Bootstrap")
            if 'jquery' in html:
                techs.append("jQuery")
            
            self.results['technologies'] = techs
            for tech in techs:
                print(f"  [+] {tech}")
                
        except Exception as e:
            self.results['errors'].append(f"Tech detection error: {str(e)}")
    
    def search_social_media(self):
        """Find social media profiles"""
        print(f"\n[*] Searching social media...")
        
        platforms = {
            'LinkedIn': f"https://www.linkedin.com/company/{self.company_name.lower().replace(' ', '-')}",
            'Twitter': f"https://twitter.com/{self.company_name.lower().replace(' ', '')}",
            'Facebook': f"https://www.facebook.com/{self.company_name.lower().replace(' ', '')}",
            'Instagram': f"https://www.instagram.com/{self.company_name.lower().replace(' ', '')}",
        }
        
        for platform, url in platforms.items():
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    self.results['social_media'][platform] = url
                    print(f"  [+] {platform}: {url}")
            except:
                pass
    
    def search_job_postings(self):
        """Search for job postings (basic implementation)"""
        print(f"\n[*] Searching for job postings...")
        
        # This would typically use job board APIs
        # For now, we'll just note common job board URLs
        job_boards = {
            'LinkedIn Jobs': f"https://www.linkedin.com/jobs/search/?keywords={quote(self.company_name)}",
            'Indeed': f"https://www.indeed.com/q-{quote(self.company_name)}-jobs.html",
            'Glassdoor': f"https://www.glassdoor.com/Jobs/{quote(self.company_name)}-jobs-SRCH_KO0,{len(self.company_name)}.htm",
        }
        
        for board, url in job_boards.items():
            self.results['job_postings'].append({
                'board': board,
                'search_url': url
            })
            print(f"  [+] {board}: Check {url}")
    
    def extract_emails(self):
        """Extract email addresses from company website"""
        if not self.domain:
            return
            
        print(f"\n[*] Extracting email addresses...")
        
        try:
            url = f"https://{self.domain}"
            response = requests.get(url, timeout=10)
            
            # Simple email regex
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = set(re.findall(email_pattern, response.text))
            
            self.results['emails'] = list(emails)
            for email in emails:
                print(f"  [+] {email}")
                
        except Exception as e:
            self.results['errors'].append(f"Email extraction error: {str(e)}")
    
    def run_full_scan(self):
        """Run all reconnaissance modules"""
        print(f"\n{'='*60}")
        print(f"Company Reconnaissance: {self.company_name}")
        if self.domain:
            print(f"Domain: {self.domain}")
        print(f"{'='*60}")
        
        # Run all modules
        self.search_cloud_storage()
        self.search_github()
        if self.domain:
            self.get_whois_info()
            self.enumerate_dns_records()
            self.search_certificate_transparency()
        self.enumerate_subdomains()
        self.detect_technologies()
        self.search_social_media()
        self.search_job_postings()
        self.extract_emails()
        
        return self.results
    
    def save_results(self, filename: str = None):
        """Save results to JSON file"""
        if not filename:
            safe_name = self.company_name.lower().replace(' ', '_')
            filename = f"{safe_name}_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Convert sets to lists for JSON serialization
        results_copy = self.results.copy()
        results_copy['emails'] = list(results_copy['emails'])
        
        with open(filename, 'w') as f:
            json.dump(results_copy, f, indent=2)
        
        print(f"\n[*] Results saved to: {filename}")
        return filename


def main():
    print("="*60)
    print("Company Reconnaissance Tool")
    print("="*60)
    
    # Get company information
    company_name = input("\nEnter company name: ").strip()
    domain = input("Enter company domain (optional, e.g., example.com): ").strip()
    
    if not domain:
        domain = None
    
    # Create reconnaissance object
    recon = CompanyRecon(company_name, domain)
    
    # Run scan
    results = recon.run_full_scan()
    
    # Save results
    output_file = recon.save_results()
    
    # Print summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"S3 Buckets Found: {len(results['s3_buckets'])}")
    print(f"GCS Buckets Found: {len(results['gcs_buckets'])}")
    print(f"Azure Blobs Found: {len(results['azure_blobs'])}")
    print(f"GitHub Repos Found: {len(results['github_repos'])}")
    print(f"Subdomains Found: {len(results['subdomains'])}")
    
    if results.get('certificate_transparency'):
        ct_data = results['certificate_transparency']
        print(f"Certificate Transparency Subdomains: {len(ct_data.get('unique_subdomains', []))}")
    
    if results.get('dns_records'):
        total_dns = sum(len(records) for records in results['dns_records'].values())
        print(f"DNS Records Found: {total_dns}")
    
    print(f"Technologies Detected: {len(results['technologies'])}")
    print(f"Social Media Profiles: {len(results['social_media'])}")
    print(f"Email Addresses: {len(results['emails'])}")
    
    if results.get('whois_info', {}).get('registrar'):
        print(f"WHOIS Registrar: {results['whois_info']['registrar']}")
    
    if results['errors']:
        print(f"\nErrors encountered: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  - {error}")
    
    print(f"\nFull results saved to: {output_file}")


if __name__ == "__main__":
    main()
