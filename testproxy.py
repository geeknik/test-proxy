import socket
import ssl
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_open_ports(host, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
            open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass
    return open_ports

def get_ssl_info(host, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()
                return cert
    except Exception:
        return None

def check_http_headers(url):
    try:
        response = requests.head(url, timeout=5)
        return response.headers
    except requests.RequestException:
        return None

def detect_proxy(host):
    print(f"Analyzing {host}...")

    # Check common ports
    common_ports = [80, 443, 8080, 3128]
    open_ports = check_open_ports(host, common_ports)
    print(f"Open ports: {open_ports}")

    # Check SSL certificate (if applicable)
    if 443 in open_ports:
        ssl_info = get_ssl_info(host)
        if ssl_info:
            print("SSL certificate information:")
            print(f"  Subject: {ssl_info.get('subject')}")
            print(f"  Issuer: {ssl_info.get('issuer')}")
            print(f"  Version: {ssl_info.get('version')}")
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
        'Proxy-Connection'
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
