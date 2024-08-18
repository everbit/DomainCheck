import os
import re
import argparse
import requests
import dns.resolver
import whois
import random
import validators
import logging
import hashlib
import ssl
import sublist3r
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Define base_path as the current working directory under a "domain_check" folder
base_path = os.path.join(os.getcwd(), "domain_check")

# Ensure the base_path directory exists
if not os.path.exists(base_path):
    os.makedirs(base_path)

# Define log_path as base_path/logfile.txt
log_path = os.path.join(base_path, 'logfile.txt')

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)

# Pool of user-agents
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Mobile Safari/537.36",
]

def get_user_agent(custom_user_agent=None):
    return custom_user_agent if custom_user_agent else random.choice(user_agents)

def validate_domain(domain):
    if not validators.domain(domain):
        raise ValueError(f"Invalid domain format: {domain}")

def sanitise_input(domain):
    # Remove 'http://', 'https://' from the start of the domain for consistent internal processing
    sanitised_domain = re.sub(r'^https?:\/\/', '', domain).split('/')[0]
    logging.info(f"sanitised domain: {sanitised_domain}")
    return sanitised_domain

def sanitise_output_filename(domain):
    # Remove 'http://', 'https://', and replace any '/' with '_'
    sanitised_filename = re.sub(r'^https?:\/\/', '', domain).replace('/', '_')
    logging.info(f"sanitised output filename: {sanitised_filename}")
    return sanitised_filename

def fetch_status(url, user_agent):
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        final_url = response.url
        # Output the status code to the console or log
        logging.info(f"HTTP Status for {url}: {response.status_code}")
        if response.status_code == 200:
            content = response.text
            if content.strip():
                if final_url != url:
                    logging.info(f"{url} redirects to {final_url}")
                    return f"Up ({url}) - Status Code {response.status_code} - Redirects to {final_url}"
                else:
                    return f"Up ({url}) - Status Code {response.status_code}"
            else:
                return f"Up ({url}) - No Content - Status Code {response.status_code}"
        else:
            return f"Up ({url}) - Status Code {response.status_code}"
    except requests.exceptions.HTTPError as e:
        logging.warning(f"Request returned a response error for {url}: {e.response.status_code}")
        return f"Down ({url}) with Status Code {e.response.status_code}"
    except requests.exceptions.ConnectionError:
        logging.warning(f"Failed to connect to {url}")
        return f"Down ({url}) - Connection Failed"
    except requests.exceptions.Timeout:
        logging.warning(f"Request timed out for {url}")
        return f"Down ({url}) - Timeout"
    except requests.exceptions.RequestException as e:
        logging.warning(f"Request failed for {url}: {e}")
        return f"Down ({url}) - Client Error"


def check_http_status(base_domain, user_agent, threads):
    # Check the status of the domain with both http and https protocols
    protocols = ['http', 'https']
    urls = [f"{protocol}://{base_domain}" for protocol in protocols]

    status = {}
    redirects = {}
    logging.info(f"Checking HTTP status for domain: {base_domain} with URLs: {urls}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(fetch_status, url, user_agent): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            protocol = url.split("://")[0]
            try:
                result = future.result()
                status[protocol] = result
                # Check for redirection in the result
                if "Redirects to" in result:
                    redirects[protocol] = result.split("Redirects to")[-1].strip()
            except Exception as e:
                logging.error(f"Failed to check {protocol.upper()} status for {url}: {e}")
                status[protocol] = "Unknown"

    if redirects:
        logging.info(f"Redirects detected for domain {base_domain}: {redirects}")

    return status, redirects

def generate_reputation_urls(domain, urlscan_url=None):
    try:
        formatted_url = f"http://{domain}/"
        sha256_hash = hashlib.sha256(formatted_url.encode('utf-8')).hexdigest()
        virustotal_url = f"https://www.virustotal.com/gui/url/{sha256_hash}"
        urlvoid_url = f"https://www.urlvoid.com/scan/{domain}"
        spamhaus_url = f"https://www.spamhaus.org/domain-reputation?domain={domain}"
        talos_url = f"https://talosintelligence.com/reputation_center/lookup?search={domain}"
        google_safebrowsing_url = f"https://transparencyreport.google.com/safe-browsing/search?url={domain}&hl=en"
    except Exception as e:
        logging.error(f"Failed to generate reputation URLs for {domain}: {e}")
        return {}

    reputation_urls = {
        "virustotal": virustotal_url,
        "urlvoid": urlvoid_url,
        "spamhaus": spamhaus_url,
        "talos": talos_url,
        "google_safebrowsing": google_safebrowsing_url
    }

    if urlscan_url:
        reputation_urls["urlscan"] = urlscan_url

    return reputation_urls

def get_dns_info(domain, threads):
    base_domain = sanitise_and_get_base_domain(domain)
    logging.info(f"Gathering DNS information for base domain: {base_domain}")

    dns_info = {}
    resolver = dns.resolver.Resolver()

    def fetch_record(record_type):
        try:
            return record_type, [str(rdata) for rdata in resolver.resolve(base_domain, record_type)]
        except dns.exception.DNSException as e:
            logging.warning(f"DNS record fetch failed for {record_type}: {e}")
            return record_type, ['[DNS record not set]']
        except Exception as e:
            logging.error(f"Unexpected error fetching {record_type} record for {base_domain}: {e}")
            return record_type, ['[Error fetching record]']

    record_types = ['A', 'AAAA', 'MX', 'CNAME', 'NS', 'TXT']
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(fetch_record, record_type): record_type for record_type in record_types}
        for future in as_completed(futures):
            record_type, result = future.result()
            dns_info[record_type] = result

    return dns_info

def get_ssl_info(domain):
    base_domain = sanitise_and_get_base_domain(domain)
    logging.info(f"Gathering SSL certificate information for base domain: {base_domain}")
    
    def fetch_ssl_info():
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=base_domain) as s:
                s.settimeout(5)
                s.connect((base_domain, 443))
                cert = s.getpeercert()

                return {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'start_date': cert['notBefore'],
                    'expiry': cert['notAfter'],
                    'serial_number': cert['serialNumber'],
                    'subject_alt_name': [entry[1] for entry in cert.get('subjectAltName', ())]
                }
        except ssl.SSLError as e:
            logging.error(f"SSL error for domain {base_domain}: {e}")
            return {'error': str(e)}
        except socket.error as e:
            logging.error(f"Socket error for domain {base_domain}: {e}")
            return {'error': str(e)}
        except Exception as e:
            logging.error(f"Unexpected error fetching SSL info for {base_domain}: {e}")
            return {'error': str(e)}

    return fetch_ssl_info()

def check_certificate_transparency(domain):
    try:
        ct_url = f"https://crt.sh/?q={domain}"
        response = requests.get(ct_url)
        if response.status_code == 200:
            return f"Certificate Transparency logs found: {ct_url}"
        else:
            return "No Certificate Transparency logs found."
    except Exception as e:
        logging.error(f"Failed to check Certificate Transparency for {domain}: {e}")
        return f"Error: {e}"

def get_registrar_info(domain):
    logging.info(f"Gathering registrar information for domain: {domain}")
    registrar_info = {}

    try:
        domain_info = whois.whois(domain)
        registrar_info['registrar'] = domain_info.registrar
        registrar_info['created'] = domain_info.creation_date
        registrar_info['updated'] = domain_info.updated_date
        registrar_info['expires'] = domain_info.expiration_date

        abuse_email = domain_info.emails if domain_info.emails else None
        if not abuse_email and domain_info.text:
            for line in domain_info.text.splitlines():
                if "abuse" in line.lower() and "email" in line.lower():
                    abuse_email = line.split(":")[-1].strip()
                    break

        registrar_info['abuse_contact_email'] = abuse_email or "Not Available"
    except Exception as e:
        logging.error(f"Failed to gather registrar information for {domain}: {e}")
        registrar_info['error'] = str(e)

    return registrar_info

def check_spf(domain):
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for record in spf_records:
            if 'v=spf1' in record.to_text():
                return f"SPF record found: {record.to_text()}"
        return "No SPF record found."
    except Exception as e:
        logging.error(f"Failed to check SPF for {domain}: {e}")
        return f"Error: {e}"

def check_dkim(domain):
    selector = 'default'
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
        for record in dkim_records:
            return f"DKIM record found: {record.to_text()}"
        return "No DKIM record found."
    except dns.resolver.NXDOMAIN:
        return "No DKIM record found."
    except Exception as e:
        logging.error(f"Failed to check DKIM for {domain}: {e}")
        return f"Error: {e}"

def check_dmarc(domain):
    dmarc_domain = f"_dmarc.{domain}"
    try:
        dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        for record in dmarc_records:
            return f"DMARC record found: {record.to_text()}"
        return "No DMARC record found."
    except dns.resolver.NoAnswer:
        return "No DMARC record found."
    except Exception as e:
        logging.error(f"Failed to check DMARC for {domain}: {e}")
        return f"Error: {e}"

def get_subdomains(domain, threads):
    base_domain = sanitise_and_get_base_domain(domain)
    logging.info(f"Enumerating subdomains for base domain: {base_domain}")

    try:
        subdomains = sublist3r.main(base_domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        return subdomains
    except Exception as e:
        logging.error(f"Failed to enumerate subdomains for domain {base_domain}: {e}")
        return [f"Error: {str(e)}"]

def check_subdomain_status(subdomains, user_agent, threads):
    protocols = ['http', 'https']
    status = {}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for subdomain in subdomains:
            for protocol in protocols:
                url = f"{protocol}://{subdomain}"
                futures.append(executor.submit(fetch_status, url, user_agent))

        for future in as_completed(futures):
            try:
                result = future.result()
                subdomain = result.split(' ')[1]
                if subdomain not in status:
                    status[subdomain] = {}
                protocol = subdomain.split("://")[0]
                status[subdomain][protocol] = result
            except Exception as e:
                logging.error(f"Unexpected error checking subdomain status: {e}")

    return status

def sanitise_and_get_base_domain(domain):
    try:
        domain = sanitise_input(domain)
        parsed_url = urlparse(domain)
        base_domain = parsed_url.netloc or parsed_url.path  # Extract the domain without protocol
        parts = base_domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return base_domain
    except Exception as e:
        logging.error(f"Error sanitising domain {domain}: {e}")
        return domain

def write_output(sanitised_domain, original_domain, server_status, dns_info, ssl_info, registrar_info, output_dir, reputation_urls, redirects=None, subdomains=None, subdomain_status=None, spf_info=None, dmarc_info=None, dkim_info=None, certificate_transparency_info=None):
    sanitised_filename = sanitise_output_filename(original_domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"{sanitised_filename}_{timestamp}.txt")
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    logging.info(f"Writing output to file: {filename}")
    
    try:
        with open(filename, 'w') as f:
            f.write(f"Domain Provided for Analysis: {original_domain}\n")
            
            # Server Status
            f.write("\nServer Status:\n")
            for protocol, status in server_status.items():
                if "Up" in status:
                    f.write(f"{protocol.upper()}: UP\n")
                elif "Down" in status:
                    f.write(f"{protocol.upper()}: DOWN\n")
                else:
                    f.write(f"{protocol.upper()}: UNKNOWN\n")

            # Redirects Information
            if redirects:
                f.write("\nRedirect Information:\n")
                for protocol, destination in redirects.items():
                    f.write(f"{protocol.upper()} Redirects to: {destination}\n")

            f.write(f"\nDomain analysis: {sanitised_domain}")
            
            # Reputation Checks
            f.write("\nReputation Checks:\n")
            for service, url in reputation_urls.items():
                f.write(f"{service.capitalize()}: {url}\n")
                
            if certificate_transparency_info:
                f.write("\nCertificate Transparency:\n")
                f.write(f"{certificate_transparency_info}\n")
            
            # Registrar Info
            f.write("\nRegistrar Info:\n")
            for key, value in registrar_info.items():
                f.write(f"{key}: {value}\n")
                
            # DNS Info
            f.write("\nDNS Info:\n")
            for key, value in dns_info.items():
                f.write(f"{key}: {', '.join(value)}\n")
                
            # SSL Info
            if ssl_info:
                f.write("\nSSL Info:\n")
                for key, value in ssl_info.items():
                    f.write(f"{key}: {value}\n")

            # Subdomains
            if subdomains:
                f.write("\nSubdomains:\n")
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")

            # Subdomain Status
            if subdomain_status:
                f.write("\nSubdomain Status:\n")
                for subdomain, status in subdomain_status.items():
                    f.write(f"{subdomain}: {status['http']} / {status['https']}\n")

            # Email Security Info
            if spf_info or dmarc_info or dkim_info:
                f.write("\nEmail Security Info:\n")
                if spf_info:
                    f.write(f"SPF Info: {spf_info}\n")
                if dmarc_info:
                    f.write(f"DMARC Info: {dmarc_info}\n")
                if dkim_info:
                    f.write(f"DKIM Info: {dkim_info}\n")

        logging.info(f"Output successfully written for domain: {sanitised_domain}")
    except Exception as e:
        logging.error(f"Failed to write output to file {filename}: {e}")


def check_existing_urlscan(domain, api_key):
    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json',
    }
    query_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"

    try:
        response = requests.get(query_url, headers=headers)
        response.raise_for_status()

        data = response.json()
        results = data.get('results', [])

        if results:
            most_recent = results[0]
            scan_date = most_recent.get('task', {}).get('time')
            scan_url = most_recent.get('result')
            if scan_url:
                # Remove '/api/v1' from the scan_url if it exists
                scan_url = scan_url.replace('/api/v1', '')
            logging.info(f"Domain {domain} was last scanned on {scan_date}.")
            return scan_date, scan_url
        else:
            logging.info(f"No previous scans found for domain {domain} on URLScan.")
            return None, None

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred while checking existing URLScan data: {http_err}")
    except Exception as e:
        logging.error(f"Failed to check existing URLScan data for {domain}: {e}")
    return None, None

def scan_with_urlscan(domain, api_key, force_rescan=False, auto_rescan=False):
    if not force_rescan:
        scan_date, scan_url = check_existing_urlscan(domain, api_key)
        if scan_date and scan_url:
            if auto_rescan:
                logging.info(f"Auto-rescanning domain {domain}.")
            else:
                logging.info(f"Domain {domain} was last scanned on {scan_date}. Using existing scan result.")
                return scan_url

    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json',
    }
    data = {
        "url": domain,
        "visibility": "private"  # or "public" depending on your use case
    }
    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
        response.raise_for_status()

        logging.info(f"URLScan API Response: Status Code: {response.status_code}")
        logging.info(f"URLScan API Response Headers: {response.headers}")
        logging.info(f"URLScan API Raw Response Content: {response.text}")

        if not response.content.strip():
            logging.error(f"Received empty response from URLScan for {domain}")
            return None

        if 'application/json' not in response.headers.get('Content-Type', ''):
            logging.error(f"Unexpected content type: {response.headers.get('Content-Type')}")
            logging.error(f"Raw Response Content: {response.text}")
            return None

        result_url = response.json().get('result')
        if result_url:
            return result_url
        else:
            logging.error(f"URLScan did not return a valid result URL for {domain}")
            return None
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        logging.error(f"Response content: {response.text}")
    except ValueError as json_err:
        logging.error(f"Failed to parse JSON response from URLScan for {domain}: {json_err}")
        logging.error(f"Raw Response Content: {response.text}")
    except Exception as e:
        logging.error(f"Failed to scan {domain} with URLScan: {e}")
    return None

def process_domain(domain, custom_user_agent=None, include_subdomains=False, check_subdomain_status_flag=False, email_security_checks=False, ssl_check_flag=False, use_urlscan=None, auto_rescan=False, threads=10, use_urlvoid=None, use_virustotal=None, use_phishtank=None):
    logging.info(f"Processing domain: {domain}")

    try:
        sanitised_domain = sanitise_input(domain)
        validate_domain(sanitised_domain)
        base_domain = sanitise_and_get_base_domain(sanitised_domain)
        output_dir = os.path.join(base_path, base_domain)
        os.makedirs(output_dir, exist_ok=True)
        user_agent = get_user_agent(custom_user_agent)
        logging.info(f"User-Agent used: {user_agent}")

        try:
            # Pass the sanitised domain to the status check function
            server_status, redirects = check_http_status(sanitised_domain, user_agent, threads)
        except Exception as e:
            logging.error(f"Failed to check HTTP status for {sanitised_domain}: {e}")
            server_status = {"http": "Unknown", "https": "Unknown"}
            redirects = {}

        dns_info, ssl_info, registrar_info = {}, {}, {}
        try:
            dns_info = get_dns_info(sanitised_domain, threads)
        except Exception as e:
            logging.error(f"Failed to retrieve DNS information for {sanitised_domain}: {e}")
            dns_info = {"Error": f"DNS check failed: {str(e)}"}

        if ssl_check_flag:
            try:
                ssl_info = get_ssl_info(sanitised_domain)
            except Exception as e:
                logging.error(f"Failed to retrieve SSL information for {sanitised_domain}: {e}")
                ssl_info = {"Error": f"SSL check failed: {str(e)}"}

        try:
            registrar_info = get_registrar_info(sanitised_domain)
        except Exception as e:
            logging.error(f"Failed to retrieve registrar information for {sanitised_domain}: {e}")
            registrar_info = {"Error": f"Registrar check failed: {str(e)}"}

        spf_info, dmarc_info, dkim_info = None, None, None
        if email_security_checks:
            try:
                spf_info = check_spf(sanitised_domain)
            except Exception as e:
                logging.error(f"Failed to check SPF for {sanitised_domain}: {e}")
                spf_info = f"Error: {e}"

            try:
                dkim_info = check_dkim(sanitised_domain)
            except Exception as e:
                logging.error(f"Failed to check DKIM for {sanitised_domain}: {e}")
                dkim_info = f"Error: {e}"

            try:
                dmarc_info = check_dmarc(sanitised_domain)
            except Exception as e:
                logging.error(f"Failed to check DMARC for {sanitised_domain}: {e}")
                dmarc_info = f"Error: {e}"

        subdomains, subdomain_status = None, None
        if include_subdomains:
            try:
                subdomains = get_subdomains(sanitised_domain, threads)
                if check_subdomain_status_flag and subdomains:
                    subdomain_status = check_subdomain_status(subdomains, user_agent, threads)
            except Exception as e:
                logging.error(f"Failed to enumerate subdomains for {sanitised_domain}: {e}")

        try:
            certificate_transparency_info = check_certificate_transparency(sanitised_domain)
        except Exception as e:
            logging.error(f"Failed to check Certificate Transparency for {sanitised_domain}: {e}")
            certificate_transparency_info = f"Error: {e}"

        urlscan_url = None

        if use_urlscan:
            try:
                # Submit the original (unsanitized) domain to URLscan
                urlscan_url = scan_with_urlscan(domain, use_urlscan, auto_rescan=auto_rescan)
            except Exception as e:
                logging.error(f"Failed to perform URLScan analysis for {domain}: {e}")

        try:
            # Use the base domain for reputation checks
            reputation_urls = generate_reputation_urls(base_domain, urlscan_url=urlscan_url)

            write_output(
                base_domain,
                domain,
                server_status,
                dns_info,
                ssl_info if ssl_check_flag else None,
                registrar_info,
                output_dir,
                reputation_urls,
                redirects=redirects,
                subdomains=subdomains,
                subdomain_status=subdomain_status,
                spf_info=spf_info,
                dmarc_info=dmarc_info,
                dkim_info=dkim_info,
                certificate_transparency_info=certificate_transparency_info
            )
        except Exception as e:
            logging.error(f"Failed to generate reputation URLs for {base_domain}: {e}")
            reputation_urls = {"Error": f"Reputation check failed: {str(e)}"}

    except ValueError as e:
        logging.error(f"Domain validation failed: {e}")
    except Exception as e:
        logging.error(f"Failed to process domain {domain}: {e}")
    finally:
        logging.info(f"Finished processing domain: {base_domain}")

def main():
    parser = argparse.ArgumentParser(description="Domain Profiler Script")
    
    parser.add_argument("-d", "--domain", help="Domain to profile")
    parser.add_argument("-f", "--file", help="File containing a list of domains to profile")
    parser.add_argument("-u", "--user-agent", help="Specify a custom user-agent", required=False)
    parser.add_argument("-s", "--subdomains", help="Include subdomain enumeration", action='store_true')
    parser.add_argument("-k", "--check-subdomain-status", help="Check if identified subdomains are up or down", action='store_true')
    parser.add_argument("-e", "--email-security-checks", help="Perform email security checks (SPF, DKIM, DMARC)", action='store_true')
    parser.add_argument("-x", "--ssl-check", help="Perform SSL certificate checks", action='store_true')
    parser.add_argument("-l", "--use-urlscan", help="Enable URLScan analysis and provide the API key", required=False)
    parser.add_argument("-r", "--auto-rescan", help="Automatically rescan the domain with URLScan if it has been scanned before", action='store_true')
    parser.add_argument("-t", "--threads", help="Specify the number of threads (workers) to use", type=int, default=10)

    args = parser.parse_args()

    logging.info(f"Arguments used: {args}")
    
    domains = []

    if args.domain:
        domains.append(args.domain)

    if args.file:
        try:
            with open(args.file, 'r') as file:
                domains.extend([line.strip() for line in file if line.strip()])
        except Exception as e:
            logging.error(f"Failed to read domains from file {args.file}: {e}")
            return

    if not domains:
        logging.error("No domain or file specified. Use --domain or --file to specify a domain or a file with domains.")
        return

    for domain in domains:
        process_domain(
            domain,
            custom_user_agent=args.user_agent,
            include_subdomains=args.subdomains,
            check_subdomain_status_flag=args.check_subdomain_status,
            email_security_checks=args.email_security_checks,
            ssl_check_flag=args.ssl_check,
            use_urlscan=args.use_urlscan,
            auto_rescan=args.auto_rescan,
            threads=args.threads
        )

if __name__ == "__main__":
    main()
