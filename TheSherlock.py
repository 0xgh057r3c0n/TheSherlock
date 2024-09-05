import requests
from bs4 import BeautifulSoup
import nmap
import whois
import geoip2.database
import dns.resolver
import socket
import json
import os
from urllib.parse import urlparse, urljoin

# Initialize colorama
import colorama
from colorama import Fore

colorama.init(autoreset=True)

# Tool information
TOOL_NAME = "TheSherlock"
VERSION = "1.0"
AUTHOR = "G4UR4V007"

# ASCII Banner
BANNER = r"""
___________.__             _________.__                 .__                 __    
\__    ___/|  |__   ____  /   _____/|  |__   ___________|  |   ____   ____ |  | __
  |    |   |  |  \_/ __ \ \_____  \ |  |  \_/ __ \_  __ \  |  /  _ \_/ ___\|  |/ /
  |    |   |   Y  \  ___/ /        \|   Y  \  ___/|  | \/  |_(  <_> )  \___|    < 
  |____|   |___|  /\___  >_______  /|___|  /\___  >__|  |____/\____/ \___  >__|_ \
                \/     \/        \/      \/     \/                       \/     \/
                
                       Version: 1.0
                       Author: G4UR4V007
"""

def print_banner():
    print(Fore.BLUE + BANNER)

def crawl_links(base_url):
    try:
        # Get the page content
        response = requests.get(base_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract all the links and convert them into full URLs
        links = [urljoin(base_url, link.get('href')) for link in soup.find_all('a', href=True)]
        return links
    except Exception as e:
        print(Fore.RED + f"[+] Error crawling links: {e}")
        return []


def filter_links_with_parameters(links):
    links_with_params = [link for link in links if '?' in link]
    return links_with_params

def error_based_sqli(url):
    try:
        response = requests.get(url + "'")
        if response.status_code == 500 or "error" in response.text.lower():
            print(Fore.GREEN + f"[+] SQL Injection vulnerability detected: {url}")
        else:
            print(Fore.YELLOW + f"[+] No SQL Injection vulnerability found for: {url}")
    except Exception as e:
        print(Fore.RED + f"[+] Error checking for SQLi: {e}")

def nmap_scan(url):
    try:
        # Extract the domain from the URL input
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        
        # Remove any leading 'www.' from the domain if present
        domain = domain.replace('www.', '')

        # Resolve the domain to an IP address
        ip = socket.gethostbyname(domain)
        
        # Initialize Nmap scanner
        nm = nmap.PortScanner()
        
        # Run the scan with Nmap using common scripts and service/version detection
        nm.scan(ip, arguments='-sC -sV -A')
        
        print(Fore.GREEN + "[+] Nmap Scan Results:")
        print(json.dumps(nm[ip], indent=4))  # Pretty print Nmap results
        
    except socket.gaierror as e:
        print(Fore.RED + f"[+] Error: Unable to resolve hostname '{domain}'. Please check the URL.")
    except Exception as e:
        print(Fore.RED + f"[+] Error during Nmap scan: {e}")

def site_title(url):
    try:
        response = requests.get(url)
        if "<title>" in response.text:
            title = response.text.split('<title>')[1].split('</title>')[0]
            return title
        else:
            return "[+] No title found"
    except Exception as e:
        return f"[+] Error: {str(e)}"

def ip_address(url):
    try:
        # Ensure the URL is formatted correctly
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"  # Add default protocol if missing
            
        # Extract the hostname from the URL
        hostname = urlparse(url).hostname  # Get the hostname
        return socket.gethostbyname(hostname)  # Resolve the hostname to an IP address
    except socket.gaierror:
        return f"[+] Error: Unable to resolve hostname '{url}'. Please check the URL."
    except Exception as e:
        return f"[+] Error: {str(e)}"
    
def web_server_detection(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return headers.get('Server', "Not found")
    except Exception as e:
        return f"[+] Error: {str(e)}"

def cms_detection(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return headers.get('X-Powered-By', "Not found")
    except Exception as e:
        return f"[+] Error: {str(e)}"

def cloudflare_detection(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return "Cloudflare detected" if 'CF-RAY' in headers else "Not found"
    except Exception as e:
        return f"[+] Error: {str(e)}"

def robots_txt_scanner(url):
    try:
        response = requests.get(url + '/robots.txt')
        return response.text if response.status_code == 200 else "Not found"
    except Exception as e:
        return f"[+] Error: {str(e)}"

def whois_lookup(url):
    try:
        whois_info = whois.whois(url)
        # Return WHOIS info in a clean format
        return whois_info
    except Exception as e:
        return f"[+] Error: {str(e)}"

def geo_ip_lookup(url):
    try:
        # Ensure the URL is formatted correctly
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"  # Add default protocol if missing
        
        # Extract the hostname from the URL
        hostname = urlparse(url).hostname  # Get the hostname
        ip = socket.gethostbyname(hostname)  # Resolve the hostname to an IP address
        
        # Verify that the GeoIP database exists
        geoip_db_path = './GeoLite2-City.mmdb'
        if not os.path.exists(geoip_db_path):
            return "[+] Error: GeoLite2-City.mmdb database not found. Please ensure it is in the correct path."
        
        # Perform GeoIP lookup
        reader = geoip2.database.Reader(geoip_db_path)
        response = reader.city(ip)
        
        # Check if the 'en' key exists in the country names
        country_name = response.country.names.get('en')
        if country_name:
            return country_name
        else:
            return f"[+] Country name not found for IP: {ip}"
    
    except socket.gaierror:
        return f"[+] Error: Unable to resolve hostname '{url}'. Please check the URL."
    except geoip2.errors.AddressNotFoundError:
        return f"[+] Error: IP address {ip} not found in the GeoIP database."
    except Exception as e:
        return f"[+] Error: {str(e)}"


def grab_banners(url):
    try:
        response = requests.get(url)
        return response.headers  # Assuming you want to return the headers as the "banner"
    except Exception as e:
        return f"[+] Error: {str(e)}"

def main():
    print_banner()
    
    # Example URL to scan
    url = input(Fore.YELLOW + "[+] Enter the URL to scan (without http/https): ")
    url = f"http://{url}" if not url.startswith(('http://', 'https://')) else url

    print(Fore.BLUE + "\n[+] Crawling Links...")
    links = crawl_links(url)
    print(Fore.GREEN + f"[+] Found links: {links}")

    print(Fore.BLUE + "\n[+] Filtering links with parameters...")
    links_with_params = filter_links_with_parameters(links)
    print(Fore.GREEN + f"[+] Links with parameters: {links_with_params}")

    print(Fore.BLUE + "\n[+] Checking for SQL Injection on links with parameters...")
    for link in links_with_params:
        # Convert relative links to absolute
        if link.startswith('/'):
            link = urljoin(url, link)
        error_based_sqli(link)

    print(Fore.BLUE + "\n[+] Performing Nmap Scan...")
    nmap_scan(url)

    print(Fore.BLUE + "\n[+] Fetching Site Title...")
    title = site_title(url)
    print(Fore.GREEN + f"[+] Site Title: {title}")

    print(Fore.BLUE + "\n[+] Getting IP Address...")
    ip = ip_address(url)
    print(Fore.GREEN + f"[+] IP Address: {ip}")

    print(Fore.BLUE + "\n[+] Detecting Web Server...")
    server = web_server_detection(url)
    print(Fore.GREEN + f"[+] Web Server: {server}")

    print(Fore.BLUE + "\n[+] Detecting CMS...")
    cms = cms_detection(url)
    print(Fore.GREEN + f"[+] CMS: {cms}")

    print(Fore.BLUE + "\n[+] Checking for Cloudflare...")
    cloudflare = cloudflare_detection(url)
    print(Fore.GREEN + f"[+] Cloudflare: {cloudflare}")

    print(Fore.BLUE + "\n[+] Scanning robots.txt...")
    robots_txt = robots_txt_scanner(url)
    print(Fore.GREEN + f"[+] robots.txt:\n{robots_txt}")

    print(Fore.BLUE + "\n[+] Performing WHOIS Lookup...")
    whois_info = whois_lookup(url)
    print(Fore.GREEN + f"[+] WHOIS Info:\n{whois_info}")

    print(Fore.BLUE + "\n[+] Performing GeoIP Lookup...")
    country = geo_ip_lookup(url)
    print(Fore.GREEN + f"[+] Country: {country}")

    print(Fore.BLUE + "\n[+] Grabbing Banners...")
    banners = grab_banners(url)
    print(Fore.GREEN + f"[+] Banners:\n{banners}")

if __name__ == "__main__":
    main()
