#!/usr/bin/env python3

import socket
import ssl
import requests
import logging
import argparse
import json
import time
import threading
import asyncio
import datetime
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Semaphore for rate limiting
rate_limit = threading.Semaphore(5)  # Allows 5 concurrent connections

# Load indicators from external files
def load_indicators(file_path):
    try:
        with open(file_path, 'r') as f:
            indicators = [line.strip() for line in f if line.strip()]
        return indicators
    except Exception as e:
        logging.error(f"Error loading indicators from {file_path}: {e}")
        return []

# Function to check if a port is open (supports IPv4 and IPv6)
async def is_port_open(host, port):
    try:
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                coro = asyncio.open_connection(host=sa[0], port=sa[1], family=af)
                reader, writer = await asyncio.wait_for(coro, timeout=2)
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue
        return False
    except Exception as e:
        logging.debug(f"Error in is_port_open for {host}:{port} - {e}")
        return False

# Function to check open ports asynchronously
async def check_open_ports(host, ports):
    open_ports = []
    tasks = [is_port_open(host, port) for port in ports]
    results = await asyncio.gather(*tasks)
    for port, is_open in zip(ports, results):
        if is_open:
            open_ports.append(port)
    return open_ports

# Function to get SSL/TLS information
def get_ssl_info(host, port=443):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(5)
        conn.connect((host, port))
        ssl_info = conn.getpeercert()
        cipher = conn.cipher()
        protocol_version = conn.version()
        # Get certificate details
        der_cert = conn.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # Use the new properties that return aware datetime objects
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        # Compare with current UTC time
        current_time = datetime.datetime.now(datetime.timezone.utc)
        is_valid = not_after > current_time

        conn.close()
        return {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'version': cert.version.name,
            'not_valid_before': not_before.strftime('%Y-%m-%d %H:%M:%S %Z'),
            'not_valid_after': not_after.strftime('%Y-%m-%d %H:%M:%S %Z'),
            'serial_number': str(cert.serial_number),
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'cipher': cipher,
            'protocol': protocol_version,
            'is_valid': is_valid,
        }
    except Exception as e:
        logging.error(f"Error getting SSL info for {host}:{port} - {e}")
        return None

# Function to perform banner grabbing
def grab_banner(host, port):
    try:
        with rate_limit:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            sock.sendall(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % host.encode())
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
    except Exception as e:
        return None

# Function to check HTTP headers
def check_http_headers(url):
    try:
        headers = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/91.0.4472.124 Safari/537.36'
            )
        }
        response = requests.head(
            url,
            headers=headers,
            timeout=5,
            verify=False,
            allow_redirects=True
        )
        return response.headers, response.status_code, response.history
    except requests.RequestException as e:
        logging.error(f"Error checking {url}: {e}")
        return None, None, None

# Function to detect WAF based on headers
def detect_waf(headers, waf_indicators):
    detected_wafs = []
    for header, waf in waf_indicators.items():
        if header.lower() in [h.lower() for h in headers]:
            detected_wafs.append(waf)
    return detected_wafs

# Function to get GeoIP information
def get_geoip_info(ip):
    try:
        response = requests.get(f'https://geolocation-db.com/json/{ip}&position=true').json()
        return {
            'country': response.get('country_name'),
            'state': response.get('state'),
            'city': response.get('city'),
            'latitude': response.get('latitude'),
            'longitude': response.get('longitude'),
        }
    except Exception as e:
        logging.error(f"Error getting GeoIP info: {e}")
        return None

# Main detection function
async def detect_proxy(host, common_ports, proxy_indicators, waf_indicators):
    results = {
        'host': host,
        'ip': None,
        'geoip': {},
        'open_ports': [],
        'banners': {},
        'ssl_info': {},
        'http_headers': {},
        'https_headers': {},
        'proxy_indicators': [],
        'waf_detected': [],
        'redirects': []
    }

    logging.info(f"Analyzing {host}...")

    try:
        ip = socket.gethostbyname(host)
        results['ip'] = ip
        logging.info(f"Resolved {host} to IP: {ip}")
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        return results

    # Get GeoIP information
    geoip_info = get_geoip_info(ip)
    if geoip_info:
        results['geoip'] = geoip_info
        logging.info(f"Geolocation info: {geoip_info}")

    # Check open ports
    open_ports = await check_open_ports(ip, common_ports)
    results['open_ports'] = open_ports
    logging.info(f"Open ports: {open_ports}")

    # Perform banner grabbing
    for port in open_ports:
        banner = grab_banner(host, port)
        if banner:
            results['banners'][port] = banner
            logging.info(f"Banner for port {port}: {banner}")

    # Check SSL certificate (if port 443 is open)
    if 443 in open_ports:
        cert = get_ssl_info(host)
        if cert:
            results['ssl_info'] = cert
            logging.info("SSL certificate information:")
            for key, value in cert.items():
                logging.info(f"  {key}: {value}")
        else:
            logging.info("Unable to retrieve SSL information")

    # Check HTTP headers
    http_url = f"http://{host}"
    https_url = f"https://{host}"

    http_headers, http_status, http_history = check_http_headers(http_url)
    https_headers, https_status, https_history = check_http_headers(https_url)

    if http_headers:
        results['http_headers'] = dict(http_headers)
        logging.info(f"\nHTTP Headers (Status: {http_status}):")
        for key, value in http_headers.items():
            logging.info(f"  {key}: {value}")

    if https_headers:
        results['https_headers'] = dict(https_headers)
        logging.info(f"\nHTTPS Headers (Status: {https_status}):")
        for key, value in https_headers.items():
            logging.info(f"  {key}: {value}")

    # Check for redirects
    if http_history:
        results['redirects'].append({'protocol': 'http', 'chain': [r.url for r in http_history]})
        logging.info("\nHTTP Redirects:")
        logging.info(" -> ".join([r.url for r in http_history]))
    if https_history:
        results['redirects'].append({'protocol': 'https', 'chain': [r.url for r in https_history]})
        logging.info("\nHTTPS Redirects:")
        logging.info(" -> ".join([r.url for r in https_history]))

    # Detect proxy indicators
    found_indicators = []
    combined_headers = {}
    if http_headers:
        combined_headers.update(http_headers)
    if https_headers:
        combined_headers.update(https_headers)

    for header in proxy_indicators:
        if header.lower() in [h.lower() for h in combined_headers]:
            found_indicators.append(header)

    results['proxy_indicators'] = found_indicators
    if found_indicators:
        logging.info(f"\nPotential proxy/load balancer detected. Indicators found: {', '.join(found_indicators)}")
    else:
        logging.info("\nNo clear indicators of a proxy or load balancer were found.")

    # Detect WAF
    waf_http = detect_waf(http_headers or {}, waf_indicators)
    waf_https = detect_waf(https_headers or {}, waf_indicators)
    results['waf_detected'] = list(set(waf_http + waf_https))
    if results['waf_detected']:
        logging.info(f"\nWAF detected: {', '.join(results['waf_detected'])}")
    else:
        logging.info("\nNo Web Application Firewall (WAF) detected")

    # Summary of findings
    logging.info("\nSummary of findings:")
    logging.info(f"  Host: {host}")
    logging.info(f"  IP: {results['ip']}")
    logging.info(f"  Open ports: {results['open_ports']}")
    if results['ssl_info']:
        logging.info(f"  SSL certificate subject: {results['ssl_info']['subject']}")
    if results['proxy_indicators']:
        logging.info(f"  Proxy/load balancer indicators: {', '.join(results['proxy_indicators'])}")
    if results['waf_detected']:
        logging.info(f"  WAF detected: {', '.join(results['waf_detected'])}")
    if results['redirects']:
        logging.info(f"  Redirects detected: {len(results['redirects'])}")

    return results

# Main function
def main():
    parser = argparse.ArgumentParser(
        description="Proxy and WAF Detection Tool",
        epilog=(
            "Example usage:\n"
            "  python testproxy.py -t example.com -o json -f results.json\n"
            "  python testproxy.py -T targets.txt -p 80,443,8000-8100 -of csv -f output.csv"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="IP address or hostname to analyze")
    group.add_argument("-T", "--target-file", help="File containing a list of targets")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports or port ranges (e.g., 80,443,8000-8100)")
    parser.add_argument("-o", "--output", choices=['text', 'json'], default='text', help="Output format (default: text)")
    parser.add_argument("-of", "--output-format", choices=['text', 'json', 'csv'], default='text', help="Output format")
    parser.add_argument("-f", "--file", help="Output file path")
    parser.add_argument("-l", "--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help="Set the logging level (default: INFO)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (equivalent to --log-level DEBUG)")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Load indicators
    proxy_indicators = load_indicators('proxy_indicators.txt') or [
        # Default proxy indicators if file is not found
        'X-Forwarded-For', 'X-Real-IP', 'Via', 'X-Forwarded-Host', 'X-Forwarded-Proto',
        # ... (other indicators as in previous examples)
    ]
    waf_indicators = {
        # Default WAF indicators if file is not found
        'X-WAF-Rate-Limit': 'Generic WAF',
        'X-Powered-By-Plesk': 'Plesk WAF',
        # ... (other indicators as in previous examples)
    }

    # Determine ports to scan
    if args.ports:
        ports = []
        for part in args.ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        common_ports = ports
    else:
        common_ports = [80, 443, 8080, 3128, 8443, 8888, 8880, 8000, 9000, 9090]

    # Determine targets to scan
    if args.target_file:
        try:
            with open(args.target_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logging.error(f"Error reading target file: {e}")
            return
    else:
        targets = [args.target]

    start_time = time.time()
    all_results = []

    # Run detection for each target
    for target in targets:
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(
            detect_proxy(target, common_ports, proxy_indicators, waf_indicators)
        )
        all_results.append(results)

    end_time = time.time()

    # Output results
    if args.output_format == 'json':
        output = json.dumps(all_results, indent=2)
    elif args.output_format == 'csv':
        # Flatten results for CSV output
        keys = set()
        for result in all_results:
            keys.update(result.keys())
        keys = sorted(keys)

        # Write to CSV file or stdout
        if args.file:
            csvfile = open(args.file, 'w', newline='')
        else:
            csvfile = sys.stdout

        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for result in all_results:
            writer.writerow(result)
        if args.file:
            csvfile.close()
            logging.info(f"\nResults saved to {args.file}")
        return
    else:
        # Text output
        output = f"\nAnalysis completed in {end_time - start_time:.2f} seconds."
        print(output)
        return

    # Save output to file if specified
    if args.file:
        with open(args.file, 'w') as f:
            f.write(output)
        logging.info(f"\nResults saved to {args.file}")
    else:
        print(output)

if __name__ == "__main__":
    main()
