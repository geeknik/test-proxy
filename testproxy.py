import socket
import ssl
import requests
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_open_ports(host, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {executor.submit(is_port_open, host, port): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception as e:
                logging.error(f"Error checking port {port}: {e}")
    return open_ports

def is_port_open(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def get_ssl_info(host, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                der_cert = secure_sock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                return {
                    'subject': cert.subject.rfc4514_string(),
                    'issuer': cert.issuer.rfc4514_string(),
                    'version': cert.version,
                    'not_valid_before': cert.not_valid_before,
                    'not_valid_after': cert.not_valid_after,
                    'serial_number': cert.serial_number,
                    'signature_hash_algorithm': cert.signature_hash_algorithm,
                    'signature_algorithm': cert.signature_algorithm_oid,
                }
    except Exception as e:
        logging.error(f"Error getting SSL info: {e}")
        return None

def check_http_headers(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.head(url, headers=headers, timeout=5, verify=False)
        return response.headers
    except requests.RequestException as e:
        logging.error(f"Error checking {url}: {e}")
        return None

def detect_proxy(host):
    logging.info(f"Analyzing {host}...")

    try:
        # Resolve hostname to IP address
        ip = socket.gethostbyname(host)
        logging.info(f"Resolved {host} to IP: {ip}")
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        return

    # Check common ports
    common_ports = [80, 443, 8080, 3128, 8443, 8888, 8880, 8000, 9000, 9090]
    open_ports = check_open_ports(ip, common_ports)
    logging.info(f"Open ports: {open_ports}")

    # Check SSL certificate (if applicable)
    if 443 in open_ports:
        cert = get_ssl_info(host)
        if cert:
            logging.info("SSL certificate information:")
            for key, value in cert.items():
                logging.info(f"  {key}: {value}")
        else:
            logging.info("Unable to retrieve SSL information")

    # Check HTTP headers
    http_url = f"http://{host}"
    https_url = f"https://{host}"

    http_headers = check_http_headers(http_url)
    https_headers = check_http_headers(https_url)

    if http_headers:
        logging.info("\nHTTP Headers:")
        for key, value in http_headers.items():
            logging.info(f"  {key}: {value}")

    if https_headers:
        logging.info("\nHTTPS Headers:")
        for key, value in https_headers.items():
            logging.info(f"  {key}: {value}")

    # Look for proxy/load balancer indicators
    proxy_indicators = [
        'X-Forwarded-For', 'X-Real-IP', 'Via', 'X-Forwarded-Host', 'X-Forwarded-Proto',
        'X-Load-Balancer', 'Proxy-Connection', 'X-Proxy-ID', 'Forwarded', 'X-Forwarded-Server',
        'X-Forwarded-Port', 'X-Original-URL', 'X-Rewrite-URL', 'X-Proxy-Cache', 'X-Cache',
        'X-Cache-Lookup', 'X-Varnish', 'X-Azure-Ref', 'CF-RAY', 'X-Amzn-Trace-Id', 'X-Client-IP',
        'X-Host', 'X-Forwarded-By', 'X-Originating-IP', 'X-Backend-Server', 'X-Served-By',
        'X-Timer', 'Fastly-Debug-Digest', 'X-CDN', 'X-CDN-Provider', 'X-Edge-IP', 'X-Backend-Host',
        'X-Proxy-Host', 'X-Akamai-Transformed', 'X-True-Client-IP', 'Fly-Request-ID', 'Server-Timing',
        'X-Cache-Hit', 'X-Cache-Status', 'X-Middleton-Response', 'X-Origin-Server'
    ]

    found_indicators = []
    for header in proxy_indicators:
        if header.lower() in [h.lower() for h in (http_headers or {})] + [h.lower() for h in (https_headers or {})]:
            found_indicators.append(header)

    if found_indicators:
        logging.info(f"\nPotential proxy/load balancer detected. Indicators found: {', '.join(found_indicators)}")
    else:
        logging.info("\nNo clear indicators of a proxy or load balancer were found.")

    # Summary of findings
    logging.info("\nSummary of findings:")
    logging.info(f"  Open ports: {open_ports}")
    if cert:
        logging.info(f"  SSL certificate subject: {cert['subject']}")
    if found_indicators:
        logging.info(f"  Proxy/load balancer indicators: {', '.join(found_indicators)}")
    else:
        logging.info("  No proxy/load balancer indicators found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a host for proxy/load balancer indicators.")
    parser.add_argument("target", help="The IP address or hostname to analyze")
    args = parser.parse_args()

    detect_proxy(args.target)
