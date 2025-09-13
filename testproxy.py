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
import sys
import urllib3
import re
import ipaddress
import os
from typing import Dict, List, Optional, Union, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Semaphore for rate limiting
rate_limit = threading.Semaphore(5)  # Allows 5 concurrent connections

# Default configuration constants
DEFAULT_CONCURRENT_CONNECTIONS: int = 5
DEFAULT_SCAN_TIMEOUT: float = 2.0
MIN_TIMEOUT: float = 1.0
MAX_TIMEOUT: float = 30.0
DEFAULT_BANNER_TIMEOUT: int = 2
DEFAULT_HTTP_TIMEOUT: int = 5
DEFAULT_HTTPS_TIMEOUT: int = 5

# Security-related constants
VALID_HOSTNAME_REGEX = re.compile(r'^[a-zA-Z0-9\-_\.]+$')
VALID_IP_REGEX = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
VALID_PORT_RANGE = range(1, 65536)
VALID_FILE_PATH_MAX_LENGTH = 4096
MAX_PORT_RANGES = 50

# Input validation and sanitization functions
def validate_hostname(hostname: str) -> bool:
    """Validate hostname for security"""
    if not hostname or len(hostname) > 253:  # RFC 1035 limit
        return False

    # Check for valid hostname format
    if not VALID_HOSTNAME_REGEX.match(hostname):
        return False

    # Prevent localhost/private addresses
    private_hosts = ['localhost', '127.0.0.1', '::1']
    if hostname.lower() in private_hosts:
        return False

    # Try to validate as IP if it looks like one
    if VALID_IP_REGEX.match(hostname):
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            return False

    # Additional validation for hostname format
    try:
        # Check if the hostname can be encoded properly
        hostname.encode('idna').decode('utf-8')
        return True
    except (UnicodeError, UnicodeDecodeError):
        return False

def validate_port(port: int) -> bool:
    """Validate port number for security"""
    return port in VALID_PORT_RANGE

def validate_ports_list(ports_string: str) -> Tuple[bool, List[int]]:
    """Validate and parse comma-separated port ranges"""
    if len(ports_string) > 1000:  # Prevent DoS with large inputs
        return False, []

    ports = []
    seen_ports = set()

    try:
        parts = ports_string.split(',')
        if len(parts) > MAX_PORT_RANGES:
            return False, []

        for part in parts:
            part = part.strip()
            if '-' in part:
                try:
                    start_str, end_str = part.split('-')
                    start, end = int(start_str), int(end_str)
                    if not all(validate_port(x) for x in [start, end]):
                        return False, []
                    if start > end or (end - start) > 1000:  # Prevent large ranges
                        return False, []
                    for p in range(start, end + 1):
                        if p not in seen_ports:
                            ports.append(p)
                            seen_ports.add(p)
                except (ValueError, IndexError):
                    return False, []
            else:
                try:
                    port = int(part)
                    if not validate_port(port) or port in seen_ports:
                        return False, []
                    ports.append(port)
                    seen_ports.add(port)
                except ValueError:
                    return False, []

    except Exception:
        return False, []

    return True, ports

def sanitize_file_path(file_path: str) -> Optional[str]:
    """Sanitize file path to prevent directory traversal"""
    if not file_path or len(file_path) > VALID_FILE_PATH_MAX_LENGTH:
        return None

    # Expand path and resolve any symbolic links
    try:
        expanded = os.path.expanduser(file_path)
        resolved = os.path.abspath(expanded)
        # Check if path is still within acceptable bounds
        if '..' in resolved or not resolved.startswith(os.getcwd() if not os.path.isabs(expanded) else '/'):
            return None
        return resolved
    except (OSError, ValueError):
        return None

def secure_headers_check(url: str, verify_ssl: bool = True) -> Tuple[Optional[requests.structures.CaseInsensitiveDict], Optional[int], Optional[List[requests.Response]]]:
    """Secure version of HTTP headers check with SSL verification"""
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
            timeout=DEFAULT_HTTP_TIMEOUT,
            verify=verify_ssl,
            allow_redirects=True
        )
        return response.headers, response.status_code, response.history
    except requests.RequestException as e:
        logging.warning(f"Error checking {url}: HTTP request failed ({'SSL verification' if 'certificate verify failed' in str(e) else 'connection error'})")
        return None, None, None

# Advanced rate limiting class
class AdvancedRateLimiter:
    def __init__(self, max_requests: int = 5, time_window: float = 1.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self.lock = threading.Lock()

    def acquire(self) -> bool:
        """Acquire permission to make a request"""
        with self.lock:
            now = time.time()
            # Remove requests outside the time window
            self.requests = [req for req in self.requests if now - req < self.time_window]

            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False

    def __enter__(self):
        # Simple wait-based acquisition
        while not self.acquire():
            time.sleep(0.1)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

# Load indicators from external files
def load_indicators(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r') as f:
            indicators = [line.strip() for line in f if line.strip()]
        return indicators
    except Exception as e:
        logging.error(f"Error loading indicators from {file_path}: {e}")
        return []

# Function to check if a port is open (supports IPv4 and IPv6)
async def is_port_open(host: str, port: int) -> bool:
    try:
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                coro = asyncio.open_connection(host=sa[0], port=sa[1], family=af)
                reader, writer = await asyncio.wait_for(coro, timeout=DEFAULT_SCAN_TIMEOUT)
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
async def check_open_ports(host: str, ports: List[int]) -> List[int]:
    open_ports = []
    tasks = [is_port_open(host, port) for port in ports]
    results = await asyncio.gather(*tasks)
    for port, is_open in zip(ports, results):
        if is_open:
            open_ports.append(port)
    return open_ports

# Function to get SSL/TLS information
def get_ssl_info(host: str, port: int = 443) -> Optional[Dict[str, Union[str, tuple, bool]]]:
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(DEFAULT_HTTP_TIMEOUT)
        conn.connect((host, port))
        ssl_info = conn.getpeercert()
        cipher = conn.cipher()
        protocol_version = conn.version()
        # Get certificate details
        der_cert = conn.getpeercert(binary_form=True)
        if der_cert is None:
            return None
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
def grab_banner(host: str, port: int) -> Optional[str]:
    try:
        with rate_limit:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(DEFAULT_BANNER_TIMEOUT)
            sock.connect((host, port))
            sock.sendall(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % host.encode())
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
    except Exception as _:
        return None

# Async wrapper for banner grabbing
async def grab_banner_async(host: str, port: int) -> Optional[str]:
    import concurrent.futures
    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(pool, grab_banner, host, port),
                timeout=DEFAULT_BANNER_TIMEOUT + 0.5
            )
            return result
        except asyncio.TimeoutError:
            return None

# Function to check HTTP headers
def check_http_headers(url: str) -> Tuple[Optional[requests.structures.CaseInsensitiveDict], Optional[int], Optional[List[requests.Response]]]:
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
            timeout=DEFAULT_HTTP_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        return response.headers, response.status_code, response.history
    except requests.RequestException as e:
        logging.error(f"Error checking {url}: {e}")
        return None, None, None

# Function to detect WAF based on headers
def detect_waf(headers: Dict[str, str], waf_indicators: Dict[str, str]) -> List[str]:
    detected_wafs = []
    header_keys = [h.lower() for h in headers.keys()]
    for indicator_header, waf_name in waf_indicators.items():
        if indicator_header.lower() in header_keys:
            detected_wafs.append(waf_name)
    return detected_wafs

# Function to get GeoIP information
def get_geoip_info(ip: str) -> Optional[Dict[str, Union[str, float, None]]]:
    try:
        response = requests.get(f'https://geolocation-db.com/json/{ip}&position=true', timeout=DEFAULT_HTTP_TIMEOUT).json()
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
async def detect_proxy(host: str, common_ports: List[int], proxy_indicators: List[str], waf_indicators: Dict[str, str], verify_ssl: bool = False) -> Dict[str, Union[str, None, Dict[str, Any], List[Any]]]:
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

    # Perform banner grabbing (parallelized for performance)
    if open_ports:
        logging.info("Scanning banners...")
        banner_tasks = [grab_banner_async(host, port) for port in open_ports]
        try:
            banners = await asyncio.gather(*banner_tasks, return_exceptions=True)
            for port, banner in zip(open_ports, banners):
                if banner and not isinstance(banner, Exception):
                    results['banners'][int(port)] = banner
                    logging.info(f"Banner for port {port}: {banner}")
                elif isinstance(banner, Exception):
                    logging.debug(f"Banner grab failed for port {port}: {banner}")
        except Exception as e:
            logging.warning(f"Error during banner grabbing: {e}")

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

    http_headers, http_status, http_history = secure_headers_check(http_url, verify_ssl)
    https_headers, https_status, https_history = secure_headers_check(https_url, verify_ssl)

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
    parser.add_argument("--verify-ssl", action="store_true", help="Enable SSL certificate verification (default: disabled)")
    parser.add_argument("--rate-limit", type=int, default=5, help="Maximum concurrent connections (default: 5)")
    parser.add_argument("--rate-window", type=float, default=1.0, help="Rate limiting time window in seconds (default: 1.0)")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Validate inputs for security
    if args.target:
        if not validate_hostname(args.target):
            logging.error(f"Invalid hostname or IP address: {args.target}")
            return

    if args.target_file:
        sanitized_path = sanitize_file_path(args.target_file)
        if not sanitized_path:
            logging.error(f"Invalid file path: {args.target_file}")
            return
        args.target_file = sanitized_path

    # Validate ports if provided
    if args.ports:
        valid, port_list = validate_ports_list(args.ports)
        if not valid:
            logging.error(f"Invalid port specification: {args.ports}")
            return
        common_ports = port_list
    else:
        common_ports = [80, 443, 8080, 3128, 8443, 8888, 8880, 8000, 9000, 9090]

    # Set up global rate limiting
    if args.rate_limit < 1 or args.rate_limit > 100:
        logging.error("Rate limit must be between 1 and 100")
        return

    global rate_limit
    rate_limit = AdvancedRateLimiter(
        max_requests=args.rate_limit,
        time_window=args.rate_window
    )

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
            detect_proxy(target, common_ports, proxy_indicators, waf_indicators, args.verify_ssl)
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
