# Web Scanner Tool

## Overview

The Sherlock Tool is a comprehensive utility for scanning and analyzing websites. It performs various security checks and provides detailed information about the target site, including:

- Link crawling
- SQL Injection detection
- Nmap port scanning
- Site title retrieval
- IP address lookup
- Web server and CMS detection
- Cloudflare presence check
- `robots.txt` scanning
- WHOIS lookup
- GeoIP lookup
- Banner grabbing

## Features

- **Link Crawling**: Extracts all the links from a specified webpage.
- **SQL Injection Detection**: Checks for basic SQL injection vulnerabilities.
- **Nmap Scan**: Performs a detailed port scan using Nmap.
- **Site Title**: Retrieves the HTML title of the webpage.
- **IP Address Lookup**: Resolves the IP address of the given domain.
- **Web Server Detection**: Identifies the web server software.
- **CMS Detection**: Detects the CMS (Content Management System) used by the site.
- **Cloudflare Detection**: Checks if the site is protected by Cloudflare.
- **Robots.txt Scanner**: Fetches and displays the `robots.txt` file if available.
- **WHOIS Lookup**: Provides WHOIS information about the domain.
- **GeoIP Lookup**: Determines the country associated with the IP address.
- **Banner Grabbing**: Retrieves HTTP headers to get server banners.

## Requirements

- Python 3.x
- Required Python libraries:
  - `requests`
  - `beautifulsoup4`
  - `nmap`
  - `whois`
  - `geoip2`
  - `colorama`
  - `dnspython`
  - `socket`
- GeoLite2-City database file (download from MaxMind)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/0xgh057r3c0n/TheSherlock.git
   cd TheSherlock
   ```

2. **Install Dependencies:**

   Users can install all required libraries by running:

   ```bash
   pip install -r requirements.txt
   ```

This will ensure that all the necessary packages are installed for the Web Scanner Tool to function correctly.

3. **Download the GeoLite2-City database:**

   - Go to [MaxMind's GeoLite2 database download page](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en).
   - Download the `GeoLite2-City.mmdb` file and place it in the same directory as the script or update the script to the correct path.

## Usage

1. **Run the script:**

   ```bash
   python web_scanner.py
   ```

2. **Follow the prompts:**

   - Enter the URL of the website you want to scan. You can provide the domain name or a full URL.

3. **View results:**

   The tool will output various details about the website, including scan results, detected vulnerabilities, and more.

## Example

```bash
$ python TheSherlock.py
[+] Enter the URL to scan (e.g., adtu.in): adtu.in
```

The script will then proceed to perform the scans and checks, displaying results for each.

## Troubleshooting

- **Error: Unable to resolve hostname**: Ensure the URL or domain is correct and that your network connection is working.
- **GeoIP Lookup Error**: Verify that the `GeoLite2-City.mmdb` file is in the correct directory and accessible.

## Contributing

Feel free to contribute to the project by submitting issues, suggestions, or pull requests. 

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
