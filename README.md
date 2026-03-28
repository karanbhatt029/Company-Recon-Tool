A Python script that gathers publicly available information about a company from various sources.
Features
The tool performs the following reconnaissance tasks:

Cloud Storage Discovery

AWS S3 buckets
Google Cloud Storage (GCS) buckets
Azure Blob Storage containers


GitHub Repository Search - Finds the company's GitHub organization and public repositories
WHOIS Information - Domain registration details, registrar, creation/expiration dates
DNS Record Enumeration - A, AAAA, MX, NS, TXT, and CNAME records
Certificate Transparency Logs - Discovers subdomains from SSL/TLS certificates
Subdomain Enumeration - Discovers subdomains of the company's main domain
Technology Detection - Identifies web technologies and frameworks in use
Social Media Discovery - Locates official social media profiles
Job Posting Search - Generates search URLs for major job boards
Email Extraction - Finds email addresses from the company website

Installation
bash# Install dependencies
pip install -r requirements.txt

# For WHOIS lookups (optional, OS-specific):
# On Ubuntu/Debian:
sudo apt-get install whois

# On macOS (usually pre-installed):
# whois should already be available

# On Windows:
# Download from https://docs.microsoft.com/sysinternals/downloads/whois
Usage
Interactive Mode
bashpython company_recon.py
The script will prompt you for:

Company name (required)
Company domain (optional, e.g., example.com)

Programmatic Usage
pythonfrom company_recon import CompanyRecon

# Create reconnaissance object
recon = CompanyRecon("Example Corp", "example.com")

# Run full scan
results = recon.run_full_scan()

# Save results to JSON
recon.save_results()

# Or access specific results
print(f"Found {len(results['s3_buckets'])} S3 buckets")
print(f"Found {len(results['github_repos'])} GitHub repos")
Output
Results are saved to a JSON file with the format:
{company_name}_recon_{timestamp}.json
Example output structure:
json{
  "company": "Example Corp",
  "domain": "example.com",
  "timestamp": "2024-03-28T10:30:00",
  "s3_buckets": [
    {
      "name": "example-backup",
      "url": "https://example-backup.s3.amazonaws.com",
      "status": "accessible"
    }
  ],
  "gcs_buckets": [...],
  "azure_blobs": [...],
  "github_repos": [...],
  "subdomains": [...],
  "dns_records": {
    "A": [{"type": "A", "value": "93.184.216.34"}],
    "MX": [{"type": "MX", "value": "mail.example.com"}],
    "TXT": [...]
  },
  "certificate_transparency": {
    "unique_subdomains": ["www.example.com", "api.example.com", ...],
    "total_certificates": 45,
    "certificate_samples": [...]
  },
  "whois_info": {
    "registrar": "Example Registrar Inc.",
    "creation_date": "1995-08-14",
    "expiration_date": "2025-08-13",
    "organization": "Example Corp"
  },
  "technologies": [...],
  "social_media": {...},
  "job_postings": [...],
  "emails": [...]
}
Modules
Cloud Storage Search
Tests common naming patterns across multiple cloud providers:

AWS S3: Company name variations with common suffixes
Google Cloud Storage: Same patterns as S3
Azure Blob Storage: Account-level storage detection
Common suffixes: -backup, -data, -assets, -prod, -dev, -staging, etc.

Certificate Transparency Logs

Queries crt.sh database for SSL/TLS certificates
Discovers subdomains that may not be publicly linked
Shows certificate issuers and validity periods
Can reveal historical subdomains and internal naming conventions

DNS Record Enumeration
Queries multiple DNS record types:

A/AAAA: IPv4 and IPv6 addresses
MX: Mail server records
NS: Name server records
TXT: Text records (SPF, DKIM, verification tokens)

WHOIS Information
Retrieves domain registration details:

Registrar information
Creation and expiration dates
Organization/registrant data
Name servers
Domain status

GitHub Search

Searches for company organization
Retrieves public repositories
Collects repo metadata (stars, language, description)

Subdomain Enumeration
Tests common subdomain prefixes:

www, mail, api, dev, staging, admin, etc.

Technology Detection
Analyzes HTTP headers and HTML content for:

Server information
Web frameworks (React, Angular, Vue.js)
CMS platforms (WordPress)
CSS frameworks (Bootstrap)

Social Media
Checks for presence on:

LinkedIn
Twitter
Facebook
Instagram

Ethical Use & Legal Disclaimer
⚠️ IMPORTANT: This tool is for educational and authorized security testing purposes only.

Only use on companies you have permission to test
All information gathered is from publicly accessible sources
Respect rate limits and robots.txt
Do not use for malicious purposes
Check local laws regarding web scraping and reconnaissance

Extending the Tool
You can easily add new modules:
pythondef custom_search(self):
    """Your custom search logic"""
    print(f"\n[*] Running custom search...")
    # Add your logic here
    self.results['custom_data'] = []

# Add to run_full_scan method
def run_full_scan(self):
    # ... existing modules ...
    self.custom_search()
Limitations

GitHub API has rate limits (60 requests/hour unauthenticated)
Cloud storage checks are limited to prevent excessive requests
Some websites may block automated requests
Subdomain enumeration uses basic DNS resolution (consider using dedicated tools like Amass or Subfinder for comprehensive results)
WHOIS requires the whois command-line utility to be installed
DNS enumeration uses basic system tools (nslookup)
Certificate Transparency depends on crt.sh API availability

Advanced Tips

Add GitHub Token for Higher Rate Limits:

pythonheaders = {'Authorization': 'token YOUR_GITHUB_TOKEN'}
response = requests.get(url, headers=headers)

Use Threading for Faster Scans:
The tool structure supports concurrent.futures for parallel execution
Integrate with Other APIs:


SecurityTrails for subdomain enumeration
Hunter.io for email discovery
BuiltWith for technology detection

Troubleshooting

Connection timeouts: Some networks may block requests; try using a VPN
No results found: Company may use different naming conventions
Rate limiting: Add delays between requests or use proxies

Contributing
Feel free to extend this tool with:

Additional reconnaissance modules
Better error handling
Cloud storage beyond S3 (Azure, GCP)
Certificate transparency log searches
DNS record enumeration
WHOIS information gathering

License
Use responsibly and ethically.
