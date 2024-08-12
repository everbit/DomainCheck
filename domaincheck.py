import os
import sys
import argparse
import platform
import socket
import ssl
import requests
import dns.resolver
import whois
from datetime import datetime
import sublist3r
import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# Determine the operating system and set the ChromeDriver path accordingly
os_name = platform.system()

if os_name == 'Windows':
    CHROMEDRIVER_PATH = os.path.join(os.getcwd(), 'chromedriver', 'chromedriver_win.exe')
elif os_name == 'Darwin':  # MacOS is identified as 'Darwin'
    CHROMEDRIVER_PATH = os.path.join(os.getcwd(), 'chromedriver', 'chromedriver_macarm')
elif os_name == 'Linux':
    CHROMEDRIVER_PATH = os.path.join(os.getcwd(), 'chromedriver', 'chromedriver_linux')
else:
    raise Exception("Unsupported OS: Please provide the correct path to ChromeDriver for your OS")

# Verify the ChromeDriver path
if not os.path.exists(CHROMEDRIVER_PATH):
    raise FileNotFoundError(f"ChromeDriver not found at {CHROMEDRIVER_PATH}")

# Set Chrome user-agent
my_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36"


def check_server_status(domain):
    logging.info(f"Checking server status for domain: {domain}")
    
    status = {
        'http': 'Down (HTTP)',
        'https': 'Down (HTTPS)'
    }

    # Check HTTP status
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        status['http'] = f"Up (HTTP)" if response.status_code == 200 else f"Up (HTTP) with Status Code {response.status_code}"
        logging.info(f"HTTP server status for {domain} - {status['http']}")
    except requests.exceptions.RequestException as e:
        logging.warning(f"HTTP request to {domain} failed: {e}")
    
    # Check HTTPS status
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        status['https'] = f"Up (HTTPS)" if response.status_code == 200 else f"Up (HTTPS) with Status Code {response.status_code}"
        logging.info(f"HTTPS server status for {domain} - {status['https']}")
    except requests.exceptions.RequestException as e:
        logging.warning(f"HTTPS request to {domain} failed: {e}")

    return status


def get_dns_info(domain):
    logging.info(f"Gathering DNS information for domain: {domain}")
    dns_info = {}
    resolver = dns.resolver.Resolver()

    try:
        dns_info['A'] = [str(rdata) for rdata in resolver.resolve(domain, 'A')]
    except:
        dns_info['A'] = []

    try:
        dns_info['AAAA'] = [str(rdata) for rdata in resolver.resolve(domain, 'AAAA')]
    except:
        dns_info['AAAA'] = []

    try:
        dns_info['MX'] = [str(rdata.exchange) for rdata in resolver.resolve(domain, 'MX')]
    except:
        dns_info['MX'] = []

    try:
        dns_info['CNAME'] = [str(rdata) for rdata in resolver.resolve(domain, 'CNAME')]
    except:
        dns_info['CNAME'] = []

    try:
        dns_info['NS'] = [str(rdata) for rdata in resolver.resolve(domain, 'NS')]
    except:
        dns_info['NS'] = []

    try:
        dns_info['TXT'] = [str(rdata) for rdata in resolver.resolve(domain, 'TXT')]
    except:
        dns_info['TXT'] = []

    logging.info(f"DNS information gathered for {domain}")
    return dns_info


def get_ssl_info(domain):
    logging.info(f"Gathering SSL certificate information for domain: {domain}")
    ssl_info = {}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

            ssl_info['subject'] = dict(x[0] for x in cert['subject'])
            ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
            ssl_info['start_date'] = cert['notBefore']
            ssl_info['expiry'] = cert['notAfter']
            ssl_info['serial_number'] = cert['serialNumber']
            
            # Extract Subject Alternative Names (SANs)
            san = cert.get('subjectAltName', ())
            ssl_info['subject_alt_name'] = [entry[1] for entry in san]

        logging.info(f"SSL certificate information gathered for {domain}")
    except Exception as e:
        ssl_info['error'] = str(e)
        logging.error(f"Failed to gather SSL information for {domain}: {e}")

    return ssl_info


def get_registrar_info(domain):
    logging.info(f"Gathering registrar information for domain: {domain}")
    registrar_info = {}

    try:
        domain_info = whois.whois(domain)
        registrar_info['registrar'] = domain_info.registrar
        registrar_info['created'] = domain_info.creation_date
        registrar_info['updated'] = domain_info.updated_date
        registrar_info['expires'] = domain_info.expiration_date
        registrar_info['abuse_contact_email'] = domain_info.emails

        logging.info(f"Registrar information gathered for {domain}")
    except Exception as e:
        registrar_info['error'] = str(e)
        logging.error(f"Failed to gather registrar information for {domain}: {e}")

    return registrar_info


def get_subdomains(domain):
    logging.info(f"Enumerating subdomains for domain: {domain}")
    try:
        subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        logging.info(f"Subdomains enumeration completed for {domain}")
        return subdomains
    except Exception as e:
        logging.error(f"Failed to enumerate subdomains for {domain}: {e}")
        return [f"Error: {str(e)}"]


def sanitize_domain(domain):
    """
    Strips out any protocol (http, https, etc.) from the domain input.
    """
    if "://" in domain:
        domain = domain.split("://")[1]
    return domain.split('/')[0]  # Further strip out any path after the domain


def bypass_cookie_consent(driver):
    logging.info("Attempting to bypass cookie consent pop-up.")
    try:
        possible_selectors = [
            "//button[contains(text(), 'Accept')]",
            "//button[contains(text(), 'Agree')]",
            "//button[contains(text(), 'I agree')]",
            "//button[contains(text(), 'OK')]",
            "//button[contains(text(), 'Got it')]",
            "//button[contains(text(), 'Allow all')]",
            "//a[contains(text(), 'Accept')]",
            "//a[contains(text(), 'Agree')]",
            "//div[contains(@class, 'cookie')]//button",
            "//div[contains(@class, 'consent')]//button",
            "//div[contains(@class, 'cookie')]//a",
            "//div[contains(@class, 'consent')]//a",
        ]

        for selector in possible_selectors:
            try:
                WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH, selector))).click()
                logging.info(f"Clicked cookie consent button with selector: {selector}")
                break
            except Exception as e:
                logging.debug(f"No clickable element found for selector: {selector}")

    except Exception as e:
        logging.error(f"Failed to bypass cookie consent: {e}")


def take_screenshot(domain, output_dir):
    logging.info(f"Taking screenshot of domain: {domain}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=1920x1080")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument(f"--user-agent={my_user_agent}")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")
        service = Service(executable_path=CHROMEDRIVER_PATH)
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_window_size(1920, 1080)

        driver.get(f"http://{domain}")
        
        # Attempt to bypass cookie consent pop-ups
        bypass_cookie_consent(driver)

        screenshot_path = os.path.join(output_dir, f"{domain}_{timestamp}.png")
        driver.save_screenshot(screenshot_path)
        driver.quit()

        logging.info(f"Screenshot saved to {screenshot_path}")
        return screenshot_path
    except Exception as e:
        logging.error(f"Failed to take screenshot of {domain}: {e}")
        return None


def write_output(domain, server_status, dns_info, ssl_info, registrar_info, subdomains, output_dir):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = os.path.join(output_dir, f"{domain}_{timestamp}.txt")
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    logging.info(f"Writing output to file: {filename}")
    with open(filename, 'w') as f:
        f.write(f"Domain: {domain}\n")
        #f.write(f"Server Status: {server_status}\n")
        f.write(f"{server_status}\n")

        
        f.write("\nRegistrar Info:\n")
        for key, value in registrar_info.items():
            f.write(f"{key}: {value}\n")
            
        f.write("\nDNS Info:\n")
        for key, value in dns_info.items():
            f.write(f"{key}: {', '.join(value)}\n")

        f.write("\nSubdomains:\n")
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")
            
        f.write("\nSSL Info:\n")
        for key, value in ssl_info.items():
            f.write(f"{key}: {value}\n")
    logging.info(f"Output successfully written for domain: {domain}")


def process_domain(domain, take_screenshot_flag, include_subdomains=False):
    domain = sanitize_domain(domain)  # Sanitize the domain input
    logging.info(f"Processing domain: {domain}")
    output_dir = os.path.join(base_path, f"{domain}")
    os.makedirs(output_dir, exist_ok=True)

    server_status = check_server_status(domain)
    dns_info = get_dns_info(domain)
    ssl_info = get_ssl_info(domain)
    registrar_info = get_registrar_info(domain)
    
    # Only scan for subdomains if the flag is enabled
    subdomains = get_subdomains(domain) if include_subdomains else ["Subdomain scanning not performed."]
    
    # Prepare the combined status message
    combined_status = f"Server Status: {server_status['http']}\nServer Status: {server_status['https']}"

    # Handle screenshot logic
    if take_screenshot_flag:
        screenshot_path = take_screenshot(domain, output_dir)
        screenshot_info = f"Screenshot taken: {screenshot_path}" if screenshot_path else "Screenshot failed."
    else:
        screenshot_info = "Screenshot not taken."

    # Write output including screenshot information
    write_output(domain, f"{combined_status}\n{screenshot_info}", dns_info, ssl_info, registrar_info, subdomains, output_dir)

    logging.info(f"Finished processing domain: {domain}")


def main():
    parser = argparse.ArgumentParser(description="Domain Profiler Script")
    parser.add_argument("-d", "--domain", help="Domain to profile", required=False)
    parser.add_argument("-f", "--file", help="File containing list of domains", required=False)
    parser.add_argument("-i", "--include-subdomains", help="Include subdomain enumeration", action='store_true')
    parser.add_argument("-s", "--screenshot", help="Take screenshot of the domain", action='store_true')
    parser.add_argument("-t", "--threads", help="Number of threads to use for processing", type=int, default=5)
    
    args = parser.parse_args()

    if args.domain:
        process_domain(args.domain, args.screenshot, args.include_subdomains)

    if args.file:
        with open(args.file, 'r') as file:
            domains = file.read().splitlines()
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(process_domain, domain, args.screenshot, args.include_subdomains) for domain in domains]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logging.error(f"Error processing domain: {e}")


if __name__ == "__main__":
    main()
