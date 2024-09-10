import socket
import ssl
import requests
import logging
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def check_open_ports(host, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
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
                    'not_valid_before': cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S'),
                    'not_valid_after': cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
                    'serial_number': cert.serial_number,
                    'signature_algorithm': cert.signature_algorithm_oid._name,
                }
    except Exception as e:
        logging.error(f"Error getting SSL info: {e}")
        return None

def check_http_headers(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.head(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        return response.headers, response.status_code, response.history
    except requests.RequestException as e:
        logging.error(f"Error checking {url}: {e}")
        return None, None, None

def detect_waf(headers):
    waf_indicators = {
        # Generic and common WAF indicators
        'X-WAF-Rate-Limit': 'Generic WAF',
        'X-Powered-By-Plesk': 'Plesk WAF',
        'X-CDN': 'CDN WAF',
        'cf-ray': 'Cloudflare WAF',
        'X-Sucuri-ID': 'Sucuri WAF',
        'X-Wx-Version': 'WatchGuard WAF',
        'X-Akamai-WAF-Request': 'Akamai WAF',
        'X-Mod-Security': 'ModSecurity WAF',
        'X-AMP-Cache-HIT': 'AMP WAF',
        'X-Varnish': 'Varnish Cache (potential WAF)',

        # CDN providers with WAF capabilities
        'X-Cloudflare-CDN': 'Cloudflare WAF',
        'X-Fastly-WAF': 'Fastly WAF',
        'X-AWS-WAF-ID': 'AWS WAF',
        'X-Google-Cache-Status': 'Google Cloud Armor (WAF)',
        'X-Azure-CDN-WAF': 'Azure WAF',

        # Advanced and less common WAFs
        'X-Barracuda-WAF': 'Barracuda WAF',
        'X-Citrix-NS': 'Citrix Netscaler WAF',
        'X-Imperva-ID': 'Imperva WAF',
        'X-Fortinet-WAF': 'Fortinet WAF',
        'X-PaloAlto-ID': 'Palo Alto WAF',
        'X-Radware-WAF': 'Radware WAF',
        'X-Denied-By-SonicWall': 'SonicWall WAF',
        'X-Silverline-Request-ID': 'F5 Silverline WAF',
        'X-F5-Edge-Request-ID': 'F5 Networks WAF',

        # New and emerging WAFs and cache solutions with WAF integration
        'X-Cloud-Proxy-ID': 'Cloud Proxy (potential WAF)',
        'X-SiteLock-Request-ID': 'SiteLock WAF',
        'X-StackPath-WAF-ID': 'StackPath WAF',
        'X-Reblaze-WAF': 'Reblaze WAF',
        'X-Armor-WAF': 'Armor WAF',
        'X-PerimeterX-Client-ID': 'PerimeterX WAF',
        'X-TrueShield': 'SiteGround TrueShield WAF',

        # Security headers with potential WAF presence
        'X-Firewall-ID': 'Generic Firewall (potential WAF)',
        'X-Security-Firewall': 'Security Firewall (potential WAF)',
        'X-WAF-Detected': 'Generic WAF',
        'X-Cache-Status': 'Cache-Control (potential WAF)',
        'Server-Timing': 'Server Timing (potential WAF)',
        
        # Legacy or lesser-known WAFs
        'X-BlockID': 'BlockDoS WAF',
        'X-DNS-Guard': 'DNS Guard WAF',
        'X-CacheWall': 'CacheWall (potential WAF)',
        'X-Shield-ID': 'ShieldSquare WAF',

        # Miscellaneous WAFs
        'X-SafeGuard': 'SafeGuard WAF',
        'X-Request-Guard-ID': 'Request Guard (potential WAF)',
        'X-WAF-Block-ID': 'Generic WAF',
    }
    
    detected_wafs = []
    for header, waf in waf_indicators.items():
        if header.lower() in [h.lower() for h in headers]:
            detected_wafs.append(waf)
    return detected_wafs

def detect_proxy(host, output_format='text'):
    results = {
        'host': host,
        'ip': None,
        'open_ports': [],
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

    # Check common ports
    common_ports = [80, 443, 8080, 3128, 8443, 8888, 8880, 8000, 9000, 9090]
    open_ports = check_open_ports(ip, common_ports)
    results['open_ports'] = open_ports
    logging.info(f"Open ports: {open_ports}")
    
    # Check SSL certificate (if applicable)
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
    
    # Expanded and enhanced list for proxy/load balancer indicators
    proxy_indicators = [
    # Common Proxy Headers
    'X-Forwarded-For', 'X-Real-IP', 'Via', 'X-Forwarded-Host', 'X-Forwarded-Proto',
    'X-Load-Balancer', 'Proxy-Connection', 'X-Proxy-ID', 'Forwarded', 'X-Forwarded-Server',
    'X-Forwarded-Port', 'X-Original-URL', 'X-Rewrite-URL', 'X-Proxy-Cache', 'X-Cache',
    'X-Cache-Lookup', 'X-Varnish', 'X-Azure-Ref', 'CF-RAY', 'X-Amzn-Trace-Id',
    'X-Client-IP', 'X-Host', 'X-Forwarded-By', 'X-Originating-IP', 'X-Backend-Server',
    'X-Served-By', 'X-Timer', 'Fastly-Debug-Digest', 'X-CDN', 'X-CDN-Provider',
    'X-Edge-IP', 'X-Backend-Host', 'X-Proxy-Host', 'X-Akamai-Transformed', 'X-True-Client-IP',
    'Fly-Request-ID', 'Server-Timing', 'X-Cache-Hit', 'X-Cache-Status',
    'X-Middleton-Response', 'X-Origin-Server',

    # Emerging Proxy and CDN indicators
    'X-Cloudflare-Visitor', 'X-Cloudtrace-Context', 'CF-Connecting-IP', 'X-Cloud-ID',
    'X-Google-Forwarding', 'X-Forwarded-Scheme', 'X-Original-Host', 'X-Accel-Buffering',
    'X-Fastly-Request-ID', 'X-Envoy-Internal', 'X-Edge-Request-ID', 'X-Edge-Cache',
    'X-Proxy-Backend', 'True-Client-IP', 'X-Azure-FDID', 'X-Correlation-ID',

    # VPN/Anonymity Indicators
    'X-VPN-IP', 'X-Anon-Client-IP', 'X-Anonymous-Request-ID', 'X-Tor-Exit-Node', 'X-Proxy-User',
    'X-Onion-Request', 'X-Tunnel-ID', 'X-VPN-Forwarded-For',

    # Security Service Indicators
    'X-Security-Proxy', 'X-Identity-Forwarded', 'X-WAF-Proxy', 'X-Security-Appliance',
    'X-Security-Service-ID', 'X-WAF-Trace', 'X-DDoS-Request', 'X-Malware-Scan', 'X-Firewall-ID',
    
    # Mobile and IoT Proxy Indicators
    'X-Mobile-Proxy', 'X-IoT-Forwarding', 'X-Mobile-Forwarded-For', 'X-MIOT-Device-ID', 
    'X-Device-Proxy-ID', 'X-SIM-Proxy', 'X-Cellular-Forwarding', 'X-MMS-Forwarding',
    
    # CDN and Edge Compute Specific Indicators
    'X-AWS-Edge-Trace', 'X-Edge-Lambda-Invoke', 'X-Compute-Region', 'X-Edge-Trace',
    'X-CloudFront-Viewer-Country', 'X-CloudFront-Forwarded-Proto', 'X-CloudFront-Is-Desktop-Viewer',
    'X-CloudFront-Is-Mobile-Viewer', 'X-CDN-Edge-ID', 'X-Cloudflare-Country',

    # Additional Specialized Headers
    'X-Balancer-Server', 'X-Load-Balancer-ID', 'X-CDN-Node-ID', 'X-Reverse-Proxy-ID',
    'X-Nginx-Proxy', 'X-Heroku-Request-ID', 'X-CF-Connecting-IP', 'X-Proxy-IP-Chain',
    'X-Cache-Request', 'X-Request-Cluster-ID', 'X-Gateway-Request-ID', 'X-Global-Trace-ID',
    'X-Azure-CDN', 'X-Azure-Edge-Forwarded', 'X-Kubernetes-Service-Proxy', 'X-Cloudtrace-ID'
    ]

    
    found_indicators = []
    for header in proxy_indicators:
        if header.lower() in [h.lower() for h in (http_headers or {})] + [h.lower() for h in (https_headers or {})]:
            found_indicators.append(header)
    
    results['proxy_indicators'] = found_indicators
    if found_indicators:
        logging.info(f"\nPotential proxy/load balancer detected. Indicators found: {', '.join(found_indicators)}")
    else:
        logging.info("\nNo clear indicators of a proxy or load balancer were found.")
    
    # Detect WAF
    waf_http = detect_waf(http_headers or {})
    waf_https = detect_waf(https_headers or {})
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

    if output_format == 'json':
        return json.dumps(results, indent=2)
    else:
        return results

def main():
    parser = argparse.ArgumentParser(description="Proxy and WAF Detection Tool")
    parser.add_argument("target", help="IP address or hostname to analyze")
    parser.add_argument("-o", "--output", choices=['text', 'json'], default='text', help="Output format (default: text)")
    parser.add_argument("-f", "--file", help="Output file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    start_time = time.time()
    results = detect_proxy(args.target, args.output)
    end_time = time.time()

    if args.output == 'json':
        output = results
    else:
        output = f"\nAnalysis completed in {end_time - start_time:.2f} seconds."

    if args.file:
        with open(args.file, 'w') as f:
            f.write(output)
        logging.info(f"\nResults saved to {args.file}")
    else:
        print(output)

if __name__ == "__main__":
    main()
