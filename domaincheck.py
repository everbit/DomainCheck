import os
import re
import argparse
import platform
import socket
import ssl
import requests
import dns.resolver
import whois
import random
import validators
import time
import sublist3r
import logging
import hashlib
import urllib.parse
from datetime import datetime
from urllib.parse import urlparse, urlunparse, quote, unquote
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate

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

# Environment-specific configuration for CHROMEDRIVER_PATH
CHROMEDRIVER_PATH = os.getenv('CHROMEDRIVER_PATH')

if not CHROMEDRIVER_PATH:
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

# Pool of user-agents
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Mobile Safari/537.36",
]

def get_user_agent(custom_user_agent=None):
    """
    Returns the user-agent to be used. If a custom user-agent is provided, it will be used.
    Otherwise, a random user-agent from the pool will be selected.
    """
    if custom_user_agent:
        return custom_user_agent
    return random.choice(user_agents)

def validate_domain(domain):
    """
    Validate the domain format using validators library.
    """
    if not validators.domain(domain):
        raise ValueError(f"Invalid domain format: {domain}")

def check_http_status(domain, user_agent):
    """
    Check the HTTP/HTTPS status of a domain using a session to reuse connections.
    """
    def check_http(protocol, session):
        url = f"{protocol}://{domain}"
        headers = {'User-Agent': user_agent}
        try:
            response = session.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return f"Up ({protocol.upper()})"
            else:
                return f"Up ({protocol.upper()}) with Status Code {response.status_code}"
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed for {protocol.upper()} on {domain}: {e}")
            return f"Down ({protocol.upper()})"

    status = {}
    protocols = ['http', 'https']

    with requests.Session() as session:
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(check_http, protocol, session): protocol for protocol in protocols}
            for future in as_completed(futures):
                protocol = futures[future]
                try:
                    status[protocol] = future.result()
                except Exception as e:
                    logging.error(f"Failed to check {protocol.upper()} status for {domain}: {e}")
                    status[protocol] = "Unknown"

    return status

def generate_reputation_urls(domain):
    try:
        formatted_url = f"http://{domain}/"
        sha256_hash = hashlib.sha256(formatted_url.encode('utf-8')).hexdigest()
        virustotal_url = f"https://www.virustotal.com/gui/url/{sha256_hash}"
        urlvoid_url = f"https://www.urlvoid.com/scan/{domain}"
        talos_url = f"https://talosintelligence.com/reputation_center/lookup?search={domain}"
        google_safebrowsing_url = f"https://transparencyreport.google.com/safe-browsing/search?url={domain}&hl=en"
    except Exception as e:
        logging.error(f"Failed to generate reputation URLs for {domain}: {e}")
        return {}

    return {
        "virustotal": virustotal_url,
        "urlvoid": urlvoid_url,
        "talos": talos_url,
        "google_safebrowsing": google_safebrowsing_url
    }

def get_dns_info(domain):
    base_domain = sanitize_and_get_base_domain(domain)
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
    
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(fetch_record, record_type): record_type for record_type in record_types}
        for future in as_completed(futures):
            record_type, result = future.result()
            dns_info[record_type] = result

    return dns_info

def get_ssl_info(domain):
    base_domain = sanitize_and_get_base_domain(domain)
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

    with ThreadPoolExecutor() as executor:
        future = executor.submit(fetch_ssl_info)
        ssl_info = future.result()

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

def get_subdomains(domain):
    base_domain = sanitize_and_get_base_domain(domain)
    logging.info(f"Enumerating subdomains for base domain: {base_domain}")

    try:
        subdomains = sublist3r.main(base_domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        return subdomains
    except Exception as e:
        logging.error(f"Failed to enumerate subdomains for domain {base_domain}: {e}")
        return [f"Error: {str(e)}"]

def check_subdomain_status(subdomains, user_agent):
    """
    Check if identified subdomains are up or down using HTTP and HTTPS.
    """
    def check_http(protocol, subdomain, session):
        url = f"{protocol}://{subdomain}"
        headers = {'User-Agent': user_agent}
        try:
            response = session.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return protocol, subdomain, f"Up ({protocol.upper()})"
            else:
                return protocol, subdomain, f"Up ({protocol.upper()}) with Status Code {response.status_code}"
        except requests.exceptions.RequestException:
            return protocol, subdomain, f"Down ({protocol.upper()})"
        except Exception as e:
            logging.error(f"Unexpected error checking status for {subdomain}: {e}")
            return protocol, subdomain, f"Unknown ({protocol.upper()})"
    
    subdomain_status = {}
    protocols = ['http', 'https']
    
    with requests.Session() as session:
        with ThreadPoolExecutor() as executor:
            futures = []
            for subdomain in subdomains:
                for protocol in protocols:
                    futures.append(executor.submit(check_http, protocol, subdomain, session))
                    
            for future in as_completed(futures):
                try:
                    protocol, subdomain, result = future.result()
                    if subdomain not in subdomain_status:
                        subdomain_status[subdomain] = {}
                    subdomain_status[subdomain][protocol] = result
                except ValueError as e:
                    logging.error(f"Error unpacking values: {e}. Future result: {future.result()}")
                except Exception as e:
                    logging.error(f"Unexpected error checking subdomain status: {e}")

    return subdomain_status

def sanitize_and_get_base_domain(domain):
    try:
        if "://" in domain:
            domain = domain.split("://")[1]
        domain = domain.split('/')[0]
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return domain
    except Exception as e:
        logging.error(f"Error sanitizing domain {domain}: {e}")
        return domain

def sanitize_domain(domain):
    try:
        if "://" in domain:
            domain = domain.split("://")[1]
        domain = urllib.parse.unquote(domain)
        domain = re.sub(r'[\/:*?"<>|]', '_', domain)
    except Exception as e:
        logging.error(f"Error sanitizing domain {domain}: {e}")
    return domain

def bypass_cookie_consent(driver):
    logging.info("Attempting to bypass cookie consent pop-up.")
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

    def click_selector(selector):
        try:
            WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH, selector))).click()
            logging.info(f"Clicked cookie consent button with selector: {selector}")
            return True
        except Exception:
            return False

    with ThreadPoolExecutor() as executor:
        future_to_selector = {executor.submit(click_selector, selector): selector for selector in possible_selectors}
        for future in future_to_selector:
            if future.result():
                break

def take_screenshot(domain, output_dir, user_agent):
    logging.info(f"Taking screenshot of domain: {domain}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_filename = re.sub(r'[\/:*?"<>|]', '_', domain)
    
    try:
        parsed_url = urlparse(domain)
        if not parsed_url.scheme:
            parsed_url = parsed_url._replace(scheme='http')
        netloc = parsed_url.netloc or parsed_url.path
        path = parsed_url.path if parsed_url.netloc else ''
        encoded_path = quote(unquote(path))
        encoded_query = quote(unquote(parsed_url.query), safe='=&')
        valid_url = urlunparse((
            parsed_url.scheme,
            netloc,
            encoded_path,
            parsed_url.params,
            encoded_query,
            parsed_url.fragment
        ))
        logging.info(f"Validated URL for screenshot: {valid_url}")
        
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--window-size=1920x1080")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument(f"--user-agent={user_agent}")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")
        service = Service(executable_path=CHROMEDRIVER_PATH)
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(30)
        driver.set_window_size(1920, 1080)

        try:
            driver.get(valid_url)
            bypass_cookie_consent(driver)
            time.sleep(10)
            screenshot_path = os.path.join(output_dir, f"{sanitized_filename}_{timestamp}.png")
            driver.save_screenshot(screenshot_path)
            logging.info(f"Screenshot saved to {screenshot_path}")
            return screenshot_path
        except Exception as e:
            logging.error(f"Error during screenshot capture: {e}")
            return None
        finally:
            driver.close()
            driver.quit()
    except Exception as e:
        logging.error(f"Failed to take screenshot of {domain}: {e}")
        return None

def write_output(sanitized_domain, original_domain, server_status, dns_info, ssl_info, registrar_info, subdomains, output_dir, reputation_urls):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"{sanitized_domain}_{timestamp}.txt")
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    logging.info(f"Writing output to file: {filename}")
    
    try:
        with open(filename, 'w') as f:
            f.write(f"Domain Provided for Analysis: {original_domain}\n")
            f.write(f"{server_status}\n")
            f.write("\nReputation Checks:\n")
            for service, url in reputation_urls.items():
                f.write(f"{service.capitalize()}: {url}\n")

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

        logging.info(f"Output successfully written for domain: {sanitized_domain}")
    except Exception as e:
        logging.error(f"Failed to write output to file {filename}: {e}")

def display_in_terminal(sanitized_domain, original_domain, server_status, dns_info, ssl_info, registrar_info, subdomains, reputation_urls):
    print(f"\nDomain Provided for Analysis: {original_domain}\n")
    print(f"Server Status:")
    print(tabulate(server_status.items(), headers=["Protocol", "Status"]))

    print("\nReputation Checks:")
    for service, url in reputation_urls.items():
        print(f"{service.capitalize()}: {url}")

    print("\nRegistrar Info:")
    print(tabulate(registrar_info.items(), headers=["Key", "Value"]))

    print("\nDNS Info:")
    print(tabulate([(key, ", ".join(value)) for key, value in dns_info.items()], headers=["Record Type", "Records"]))

    print("\nSubdomains:")
    if isinstance(subdomains, list):
        print("\n".join(subdomains))
    elif isinstance(subdomains, dict):
        for subdomain, status in subdomains.items():
            print(f"{subdomain}: {status}")

    print("\nSSL Info:")
    print(tabulate(ssl_info.items(), headers=["Key", "Value"]))

def format_server_status(server_status):
    """
    Format the server status dictionary into a more readable string.
    """
    formatted_status = []
    for protocol, status in server_status.items():
        # Extract the actual status from the string
        if "Up" in status:
            status_text = "UP"
        elif "Down" in status:
            status_text = "DOWN"
        else:
            status_text = "Unknown"
        formatted_status.append(f"{protocol.upper()} status: {status_text}")
    return "\n".join(formatted_status)

def process_domain(domain, take_screenshot_flag, include_subdomains=False, should_check_subdomain_status=False, custom_user_agent=None, interactive=False):
    logging.info(f"Processing domain: {domain}")

    sanitized_domain = None  # Initialize sanitized_domain to avoid UnboundLocalError

    try:
        # Extract just the domain name, stripping out any paths or query strings
        sanitized_domain = sanitize_and_get_base_domain(domain)
        
        # Validate domain format
        validate_domain(sanitized_domain)
        
        # Sanitize the domain to remove protocols and replace special characters for filenames
        sanitized_domain = sanitize_domain(sanitized_domain)
        
        # Use the sanitized domain for the output directory
        output_dir = os.path.join(base_path, sanitized_domain.split('_')[0])  # Directory name based on domain only
        os.makedirs(output_dir, exist_ok=True)

        # Get the base domain for DNS, SSL, and subdomain checks
        base_domain = sanitize_and_get_base_domain(sanitized_domain.split('_')[0])
        
        # Get the user agent
        user_agent = get_user_agent(custom_user_agent)
        
        # Log the user agent used
        logging.info(f"User-Agent used: {user_agent}")
        
        # Perform server status check using the sanitized domain without paths
        try:
            server_status = check_http_status(sanitized_domain.split('_')[0], user_agent)
        except Exception as e:
            logging.error(f"Failed to check HTTP status for {sanitized_domain.split('_')[0]}: {e}")
            server_status = {"http": "Unknown", "https": "Unknown"}
        
        # Format the server status for better readability
        formatted_server_status = format_server_status(server_status)
        
        # Perform DNS, SSL, and subdomain checks using the base domain
        try:
            dns_info = get_dns_info(base_domain)
        except Exception as e:
            logging.error(f"Failed to retrieve DNS information for {base_domain}: {e}")
            dns_info = {"Error": "DNS check failed"}

        try:
            ssl_info = get_ssl_info(base_domain)
        except Exception as e:
            logging.error(f"Failed to retrieve SSL information for {base_domain}: {e}")
            ssl_info = {"Error": "SSL check failed"}

        try:
            registrar_info = get_registrar_info(base_domain)
        except Exception as e:
            logging.error(f"Failed to retrieve registrar information for {base_domain}: {e}")
            registrar_info = {"Error": "Registrar check failed"}

        # Generate reputation URLs using the base domain
        try:
            reputation_urls = generate_reputation_urls(base_domain)
        except Exception as e:
            logging.error(f"Failed to generate reputation URLs for {base_domain}: {e}")
            reputation_urls = {"Error": "Reputation check failed"}
        
        # Only scan for subdomains if the flag is enabled
        subdomains = []
        if include_subdomains:
            try:
                subdomains = get_subdomains(base_domain)
                if not subdomains:
                    subdomains = ["No subdomains identified."]
                else:
                    # Check if subdomains are up or down if the flag is enabled
                    if should_check_subdomain_status:
                        try:
                            subdomain_status = check_subdomain_status(subdomains, user_agent)
                            subdomains = [f"{subdomain} - {status['http']} / {status['https']}" for subdomain, status in subdomain_status.items()]
                        except Exception as e:
                            logging.error(f"Failed to check subdomain status for {base_domain}: {e}")
                            subdomains = ["Subdomain status check failed."]
            except Exception as e:
                logging.error(f"Failed to enumerate subdomains for {base_domain}: {e}")
                subdomains = ["Subdomain scanning failed."]
        else:
            subdomains = ["Subdomain scanning not performed."]
        
        # Handle screenshot logic using the original domain (unaltered) for the URL and sanitized domain for the filename
        screenshot_info = "Screenshot not taken."
        if take_screenshot_flag:
            try:
                screenshot_path = take_screenshot(domain, output_dir, user_agent)  # Pass original domain
                screenshot_info = f"Screenshot taken: {screenshot_path}" if screenshot_path else "Screenshot failed."
            except Exception as e:
                logging.error(f"Failed to take screenshot for {domain}: {e}")
                screenshot_info = "Screenshot failed."

        # Write output including the original domain, screenshot, subdomain information, and reputation URLs
        try:
            write_output(
                sanitized_domain.split('_')[0],  # Pass the sanitized domain for the filename
                domain,  # Pass the original domain for the top of the output file
                f"{formatted_server_status}\n{screenshot_info}",
                dns_info,
                ssl_info,
                registrar_info,
                subdomains,
                output_dir,
                reputation_urls
            )
        except Exception as e:
            logging.error(f"Failed to write output for {domain}: {e}")

        # If interactive mode, display output in the terminal
        if interactive:
            display_in_terminal(
                sanitized_domain.split('_')[0],  # Pass the sanitized domain
                domain,  # Pass the original domain
                formatted_server_status,  # Use the formatted server status
                dns_info,
                ssl_info,
                registrar_info,
                subdomains,
                reputation_urls
            )

    except ValueError as e:
        logging.error(f"Domain validation failed: {e}")
    except Exception as e:
        logging.error(f"Failed to process domain {domain}: {e}")
    finally:
        if sanitized_domain:
            logging.info(f"Finished processing domain: {sanitized_domain.split('_')[0]}")
        else:
            logging.info(f"Finished processing domain: {domain}")



def interactive_mode():
    print("Welcome to the Interactive Domain Profiler!")
    print("You can type 'exit' at any time to quit the interactive mode.\n")
    
    # Loop to get a valid domain input
    while True:
        domain = input("Please enter the domain you want to profile: ").strip()
        if domain.lower() == "exit":
            print("Exiting interactive mode.")
            return
        try:
            validate_domain(domain)
            break  # Exit loop if domain is valid
        except ValueError:
            print("Invalid domain format. Please try again with a valid domain (e.g., example.com).")
    
    # Loop to get a valid choice for subdomain enumeration
    while True:
        subdomains_choice = input("Do you want to enumerate subdomains? (yes/no): ").strip().lower()
        if subdomains_choice == "exit":
            print("Exiting interactive mode.")
            return
        if subdomains_choice in ['yes', 'no']:
            include_subdomains = subdomains_choice == 'yes'
            break
        else:
            print("Invalid input. Please answer 'yes' or 'no'.")
    
    # Loop to get a valid choice for subdomain status check if subdomains are to be enumerated
    should_check_subdomain_status = False
    if include_subdomains:
        while True:
            subdomain_status_choice = input("Do you want to check if the subdomains are up? (yes/no): ").strip().lower()
            if subdomain_status_choice == "exit":
                print("Exiting interactive mode.")
                return
            if subdomain_status_choice in ['yes', 'no']:
                should_check_subdomain_status = subdomain_status_choice == 'yes'
                break
            else:
                print("Invalid input. Please answer 'yes' or 'no'.")

    # Loop to get a valid choice for screenshot capture
    while True:
        screenshot_choice = input("Do you want to take a screenshot of the domain? (yes/no): ").strip().lower()
        if screenshot_choice == "exit":
            print("Exiting interactive mode.")
            return
        if screenshot_choice in ['yes', 'no']:
            take_screenshot_flag = screenshot_choice == 'yes'
            break
        else:
            print("Invalid input. Please answer 'yes' or 'no'.")

    # Optional: Custom User-Agent
    while True:
        custom_user_agent = input("Optionally, provide a custom user-agent (or press Enter to use a random one): ").strip()
        if custom_user_agent.lower() == "exit":
            print("Exiting interactive mode.")
            return
        if custom_user_agent:
            # Validate that the custom user-agent isn't just whitespace or too short
            if len(custom_user_agent) < 10:
                print("The provided user-agent is too short. Please provide a valid user-agent string.")
            else:
                break
        else:
            custom_user_agent = None
            break
    
    # Final confirmation before processing
    print("\nSummary of your selections:")
    print(f"Domain: {domain}")
    print(f"Subdomain Enumeration: {'Yes' if include_subdomains else 'No'}")
    if include_subdomains:
        print(f"Check Subdomain Status: {'Yes' if should_check_subdomain_status else 'No'}")
    print(f"Take Screenshot: {'Yes' if take_screenshot_flag else 'No'}")
    if custom_user_agent:
        print(f"Custom User-Agent: {custom_user_agent}")
    else:
        print("Custom User-Agent: None (a random one will be used)")

    while True:
        proceed_choice = input("Do you want to proceed with these settings? (yes/no): ").strip().lower()
        if proceed_choice == "exit":
            print("Exiting interactive mode.")
            return
        if proceed_choice == 'yes':
            process_domain(domain, take_screenshot_flag, include_subdomains, should_check_subdomain_status, custom_user_agent, interactive=True)
            break
        elif proceed_choice == 'no':
            print("Operation cancelled by the user.")
            break
        else:
            print("Invalid input. Please answer 'yes' or 'no'.")


def main():
    parser = argparse.ArgumentParser(description="Domain Profiler Script")
    
    parser.add_argument("-i", "--interactive", help="Run in interactive mode", action='store_true')
    parser.add_argument("-a", "--all", help="Run all checks", action='store_true')
    parser.add_argument("-c", "--capture-screenshot", help="Take screenshot of the domain", action='store_true')
    parser.add_argument("-d", "--domain", help="Domain to profile", required=False)
    parser.add_argument("-f", "--file", help="File containing list of domains", required=False)
    parser.add_argument("-s", "--subdomains", help="Include subdomain enumeration", action='store_true')
    parser.add_argument("-k", "--check-subdomain-status", help="Check if identified subdomains are up or down", action='store_true')
    parser.add_argument("-t", "--threads", help="Number of threads to use for processing", type=int, default=5)
    parser.add_argument("-u", "--user-agent", help="Specify a custom user-agent", required=False)

    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
    else:
        logging.info(f"Arguments used: {args}")
        
        if args.all:
            args.subdomains = True
            args.capture_screenshot = True
            args.check_subdomain_status = True

        if args.domain:
            process_domain(args.domain, args.capture_screenshot, args.subdomains, args.check_subdomain_status, args.user_agent)

        if args.file:
            try:
                with open(args.file, 'r') as file:
                    domains = file.read().splitlines()
                    with ThreadPoolExecutor(max_workers=args.threads) as executor:
                        futures = [executor.submit(process_domain, domain, args.capture_screenshot, args.subdomains, args.check_subdomain_status, args.user_agent) for domain in domains]
                        for future in as_completed(futures):
                            try:
                                future.result()
                            except Exception as e:
                                logging.error(f"Error processing domain: {e}")
            except FileNotFoundError as e:
                logging.error(f"File not found: {args.file}")
            except Exception as e:
                logging.error(f"Error reading file {args.file}: {e}")

if __name__ == "__main__":
    main()
