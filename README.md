# Domain Checker

dmnchk.py and domaincheck.oy are essentially the same, except dmnchk.py omits the ability to take screenshots using Selenium.

A comprehensive domain profiling tool that provides detailed information about domains including HTTP/HTTPS status, DNS records, SSL certificates, registrar information, subdomains, email security configurations, and website screenshots.

## Features

- **HTTP/HTTPS Status Check**: Verify if a domain is accessible over HTTP and HTTPS
- **DNS Information**: Retrieve A, AAAA, MX, CNAME, NS, and TXT records
- **SSL Certificate Analysis**: Extract certificate details, issuer info, expiry dates, and more
- **Registrar Information**: Get domain registration, creation, expiration, and abuse contact details
- **Subdomain Enumeration**: Discover subdomains using Sublist3r
- **Subdomain Status Check**: Verify if discovered subdomains are accessible
- **Email Security Verification**: Check SPF, DKIM, DMARC, and DNSSEC configurations
- **Certificate Transparency Logs**: Verify if the domain appears in CT logs
- **Website Screenshots**: Capture screenshots of domains with automated cookie consent handling
- **Reputation Checks**: Generate links to reputation services (VirusTotal, URLVoid, Spamhaus, etc.)
- **Output Options**: Save results to text files and display in terminal
- **Batch Processing**: Process multiple domains from a file with multithreading support
- **Interactive Mode**: User-friendly interactive mode for guided operation

## Requirements

- Python 3.7+
- Chrome/Chromium browser
- ChromeDriver matching your Chrome version

### Python Dependencies

```
requests
validators
whois
tabulate
dnspython
sublist3r
selenium
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/domain-checker.git
   cd domain-checker
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Download and install ChromeDriver:
   - Download the appropriate version for your operating system from [ChromeDriver downloads](https://sites.google.com/chromium.org/driver/)
   - Place the ChromeDriver executable in the `chromedriver` directory or set the `CHROMEDRIVER_PATH` environment variable

## Usage

### Interactive Mode

Run the tool in interactive mode for a guided, step-by-step experience:

```bash
python domainCheck.py -i
```

### Command Line Arguments

```
usage: domainCheck.py [-h] [-i] [-a] [-c] [-d DOMAIN] [-f FILE] [-s] [-k] [-t THREADS] [-u USER_AGENT] [-e]

Domain Profiler Script

options:
  -h, --help            show this help message and exit
  -i, --interactive     Run in interactive mode
  -a, --all             Run all checks
  -c, --capture-screenshot
                        Take screenshot of the domain
  -d DOMAIN, --domain DOMAIN
                        Domain to profile
  -f FILE, --file FILE  File containing list of domains
  -s, --subdomains      Include subdomain enumeration
  -k, --check-subdomain-status
                        Check if identified subdomains are up or down
  -t THREADS, --threads THREADS
                        Number of threads to use for processing
  -u USER_AGENT, --user-agent USER_AGENT
                        Specify a custom user-agent
  -e, --email-security-checks
                        Perform email security checks (SPF, DKIM, DMARC, DNSSEC)
```

### Example Commands

Profile a single domain:
```bash
python domainCheck.py -d example.com
```

Profile a domain with all checks enabled:
```bash
python domainCheck.py -d example.com -a
```

Take a screenshot of a domain:
```bash
python domainCheck.py -d example.com -c
```

Process multiple domains from a file:
```bash
python domainCheck.py -f domains.txt -t 10
```

Enable subdomain discovery and check their status:
```bash
python domainCheck.py -d example.com -s -k
```

Check email security configurations:
```bash
python domainCheck.py -d example.com -e
```

## Output

The tool creates a structured output directory containing:

- Text files with comprehensive domain information
- Screenshots of websites (if enabled)
- Logs of the operation in `domain_check/logfile.txt`

Each domain gets its own directory for organization. Results include:

1. Basic domain information
2. HTTP/HTTPS status
3. Reputation URLs for further investigation
4. Certificate transparency information
5. Registrar details and abuse contacts
6. DNS records for all queried types
7. Subdomain list (if enabled)
8. SSL certificate details
9. Email security details (if enabled)

## Advanced Configuration

You can customize the default behavior through environment variables:

- `CHROMEDRIVER_PATH`: Set a custom path to the ChromeDriver executable
- Custom headers and user agents can be set via command-line arguments

## Notes

- Screenshots require Chrome/Chromium browser and a compatible ChromeDriver
- Subdomain scanning can take time, especially for large domains
- Results are cached locally in the `domain_check` directory
- In batch mode with screenshot capture, screenshots are taken for each domain individually
- The tool attempts to bypass cookie consent popups automatically when capturing screenshots

## Troubleshooting

- If ChromeDriver fails, ensure it matches your Chrome/Chromium version
- For SSL errors, verify the domain has a valid SSL certificate
- Domain validation failure may indicate incorrect domain format
- If subdomain scanning fails, check your network connection or try reducing the thread count

## License

[Your License Information Here]

## Disclaimer

This tool is for legitimate security research and system administration purposes only. Users are responsible for ensuring their usage complies with applicable laws and regulations.