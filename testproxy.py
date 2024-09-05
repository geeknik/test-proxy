import socket
import ssl
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_open_ports(host, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
            open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass
        except OSError as e:
            print(f"Error checking port {port}: {e}")
    return open_ports

def get_ssl_info(host, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                der_cert = secure_sock.getpeercert(binary_form=True)
                return x509.load_der_x509_certificate(der_cert, default_backend())
    except Exception as e:
        print(f"Error getting SSL info: {e}")
        return None

def check_http_headers(url):
    try:
        response = requests.head(url, timeout=5, verify=False)
        return response.headers
    except requests.RequestException as e:
        print(f"Error checking {url}: {e}")
        return None

def detect_proxy(host):
    print(f"Analyzing {host}...")
    
    try:
        # Resolve hostname to IP address
        ip = socket.gethostbyname(host)
        print(f"Resolved {host} to IP: {ip}")
    except socket.gaierror as e:
        print(f"Error resolving hostname: {e}")
        return

    # Check common ports
    common_ports = [80, 443, 8080, 3128, 8443]
    open_ports = check_open_ports(ip, common_ports)
    print(f"Open ports: {open_ports}")
    
    # Check SSL certificate (if applicable)
    if 443 in open_ports:
        cert = get_ssl_info(host)
        if cert:
            print("SSL certificate information:")
            print(f"  Subject: {cert.subject.rfc4514_string()}")
            print(f"  Issuer: {cert.issuer.rfc4514_string()}")
            print(f"  Version: {cert.version}")
            print(f"  Not valid before: {cert.not_valid_before_utc}")
            print(f"  Not valid after: {cert.not_valid_after_utc}")
        else:
            print("Unable to retrieve SSL information")
    
    # Check HTTP headers
    http_url = f"http://{host}"
    https_url = f"https://{host}"
    
    http_headers = check_http_headers(http_url)
    https_headers = check_http_headers(https_url)
    
    if http_headers:
        print("\nHTTP Headers:")
        for key, value in http_headers.items():
            print(f"  {key}: {value}")
    
    if https_headers:
        print("\nHTTPS Headers:")
        for key, value in https_headers.items():
            print(f"  {key}: {value}")
    
    # Look for proxy/load balancer indicators
    proxy_indicators = [
        'X-Forwarded-For',
        'X-Real-IP',
        'Via',
        'X-Forwarded-Host',
        'X-Forwarded-Proto',
        'X-Load-Balancer',
        'Proxy-Connection',
        'X-Proxy-ID',
        'Forwarded',
        'X-Forwarded-Server',
        'X-Forwarded-Port',
        'X-Original-URL',
        'X-Rewrite-URL',
        'X-Proxy-Cache',
        'X-Cache',
        'X-Cache-Lookup',
        'X-Varnish',
        'X-Azure-Ref',
        'CF-RAY',  # Cloudflare
        'X-Amzn-Trace-Id',  # Amazon Web Services
        'X-Client-IP',
        'X-Host',
        'X-Forwarded-By',
        'X-Originating-IP',
        'X-Backend-Server',
        'X-Served-By',
        'X-Timer',  # Fastly
        'Fastly-Debug-Digest',  # Fastly
        'X-CDN',
        'X-CDN-Provider',
        'X-Edge-IP',
        'X-Backend-Host',
        'X-Proxy-Host',
        'X-Akamai-Transformed',  # Akamai
        'X-True-Client-IP',  # Akamai
        'Fly-Request-ID',  # Fly.io
        'Server-Timing',  # Can indicate CDN usage
        'X-Cache-Hit',
        'X-Cache-Status',
        'X-Middleton-Response',
        'X-Origin-Server'
    ]
    
    found_indicators = []
    for header in proxy_indicators:
        if header.lower() in [h.lower() for h in (http_headers or {})] + [h.lower() for h in (https_headers or {})]:
            found_indicators.append(header)
    
    if found_indicators:
        print(f"\nPotential proxy/load balancer detected. Indicators found: {', '.join(found_indicators)}")
    else:
        print("\nNo clear indicators of a proxy or load balancer were found.")

if __name__ == "__main__":
    target = input("Enter the IP address or hostname to analyze: ")
    detect_proxy(target)
