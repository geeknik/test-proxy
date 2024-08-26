import socket
import ssl
import requests
import concurrent.futures
import subprocess
import time
from urllib.parse import urlparse
import struct
import argparse

def check_open_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            return port
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def tcp_fingerprint(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b'')
        response = s.recv(1024)
        options = struct.unpack('!BBHHHBBH', response[20:34])
        mss = options[3]
        window_size = struct.unpack('!H', response[14:16])[0]
        s.close()
        return {'mss': mss, 'window_size': window_size, 'ttl': response[8]}
    except Exception:
        return None

def get_ssl_info(host, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()
                cipher = secure_sock.cipher()
                return cert, cipher
    except Exception:
        return None, None

def check_http_headers(url, user_agent=None):
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.head(url, timeout=5, headers=headers, allow_redirects=True)
        return response.headers, response.elapsed.total_seconds()
    except requests.RequestException:
        return None, None

def check_http_version(url):
    try:
        session = requests.Session()
        session.mount('https://', requests.adapters.HTTPAdapter(pool_maxsize=1))
        response = session.get(url, timeout=5)
        version = response.raw.version
        if version == 20:
            return "HTTP/2"
        elif version == 30:
            return "HTTP/3"
        else:
            return f"HTTP/1.{version}"
    except Exception:
        return None

def analyze_traceroute(traceroute_output):
    lines = traceroute_output.split('\n')
    hops = []
    for line in lines[1:]:
        if line.strip():
            parts = line.split()
            if len(parts) >= 3:
                hop = {
                    'number': int(parts[0]),
                    'ip': parts[1],
                    'latency': float(parts[2].rstrip('ms'))
                }
                hops.append(hop)
    
    potential_proxies = []
    for i in range(1, len(hops)):
        if hops[i]['latency'] - hops[i-1]['latency'] > 20:
            potential_proxies.append(hops[i])
    
    return potential_proxies

def perform_traceroute(host):
    traceroute_commands = [
        ['traceroute', '-m', '15', '-q', '1', '-w', '2', host],
        ['tracert', '-h', '15', '-w', '2000', host],
    ]
    for command in traceroute_commands:
        try:
            return subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None

def analyze_headers(results, protocol):
    if not results:
        return []

    all_headers = set()
    for ua, (headers, _) in results.items():
        all_headers.update(headers.keys())
    
    proxy_indicators = [
        'X-Forwarded-For', 'X-Real-IP', 'Via', 'X-Forwarded-Host', 'X-Forwarded-Proto',
        'X-Load-Balancer', 'Proxy-Connection', 'X-Proxy-ID', 'Forwarded',
        'X-Forwarded-Server', 'X-Forwarded-Port', 'X-Original-URL', 'X-Rewrite-URL',
        'X-Proxy-Cache', 'X-Cache', 'X-Cache-Lookup', 'X-Varnish', 'X-Azure-Ref',
        'CF-RAY', 'X-Amzn-Trace-Id', 'X-Client-IP', 'X-Host', 'X-Forwarded-By',
        'X-Originating-IP', 'X-Backend-Server', 'X-Served-By', 'X-Timer',
        'Fastly-Debug-Digest', 'X-CDN', 'X-CDN-Provider', 'X-Edge-IP',
        'X-Backend-Host', 'X-Proxy-Host', 'X-Akamai-Transformed', 'X-True-Client-IP',
        'Fly-Request-ID', 'Server-Timing', 'X-Cache-Hit', 'X-Cache-Status',
        'X-Middleton-Response', 'X-Origin-Server'
    ]
    
    return [header for header in proxy_indicators if header.lower() in [h.lower() for h in all_headers]]

def calculate_proxy_score(indicators, tcp_fingerprint, http_version, traceroute_proxies):
    score = 0
    max_score = 100
    
    score += len(indicators) * 10
    
    if tcp_fingerprint:
        if tcp_fingerprint['window_size'] != 65535:
            score += 10
        if tcp_fingerprint['mss'] != 1460:
            score += 10
    
    if http_version in ["HTTP/2", "HTTP/3"]:
        score += 10
    
    score += len(traceroute_proxies) * 5
    
    return min(score, max_score)

def detect_proxy(host, verbose=False):
    results = {"host": host, "ip": None, "open_ports": [], "indicators": set(), "http_version": None, "proxy_score": 0}
    
    try:
        results["ip"] = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Error: Unable to resolve hostname {host}")
        return

    common_ports = [80, 443, 8080, 3128, 8443]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(common_ports)) as executor:
        port_futures = {executor.submit(check_open_port, results["ip"], port): port for port in common_ports}
        results["open_ports"] = [future.result() for future in concurrent.futures.as_completed(port_futures) if future.result() is not None]

    tcp_results = {port: tcp_fingerprint(results["ip"], port) for port in results["open_ports"]}

    user_agents = [
        None,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1"
    ]
    
    http_results = {}
    https_results = {}
    
    for ua in user_agents:
        http_headers, _ = check_http_headers(f"http://{host}", ua)
        https_headers, _ = check_http_headers(f"https://{host}", ua)
        
        ua_name = ua[:20] + "..." if ua else "Default"
        if http_headers:
            http_results[ua_name] = (http_headers, 0)
        if https_headers:
            https_results[ua_name] = (https_headers, 0)
    
    http_indicators = analyze_headers(http_results, "HTTP")
    https_indicators = analyze_headers(https_results, "HTTPS")
    results["indicators"].update(http_indicators + https_indicators)

    results["http_version"] = check_http_version(f"https://{host}")

    traceroute_result = perform_traceroute(host)
    traceroute_proxies = analyze_traceroute(traceroute_result) if traceroute_result else []

    results["proxy_score"] = calculate_proxy_score(results["indicators"], tcp_results.get(443), results["http_version"], traceroute_proxies)

    # Print results
    print(f"\nResults for {results['host']} ({results['ip']}):")
    print(f"Open ports: {', '.join(map(str, results['open_ports']))}")
    print(f"HTTP Version: {results['http_version'] or 'Unknown'}")
    print(f"Proxy indicators found: {len(results['indicators'])}")
    print(f"Proxy Detection Score: {results['proxy_score']}/100")

    if results["proxy_score"] >= 80:
        print("Conclusion: High likelihood of proxy/load balancer presence.")
    elif results["proxy_score"] >= 50:
        print("Conclusion: Moderate likelihood of proxy/load balancer presence.")
    elif results["proxy_score"] >= 20:
        print("Conclusion: Low likelihood of proxy/load balancer presence.")
    else:
        print("Conclusion: Very low likelihood of proxy/load balancer presence.")

    if verbose:
        print("\nDetailed Information:")
        if results["indicators"]:
            print("Proxy/Load Balancer Indicators:")
            for indicator in results["indicators"]:
                print(f"  - {indicator}")
        else:
            print("No specific proxy/load balancer indicators found in headers.")

        if traceroute_proxies:
            print("\nPotential proxy hops detected in traceroute:")
            for proxy in traceroute_proxies:
                print(f"  Hop {proxy['number']}: {proxy['ip']} (latency: {proxy['latency']}ms)")
        else:
            print("\nNo clear proxy hops detected in traceroute.")

        if 443 in results["open_ports"]:
            cert, cipher = get_ssl_info(host, 443)
            if cert:
                print("\nSSL Certificate Information:")
                print(f"  Subject: {cert.get('subject')}")
                print(f"  Issuer: {cert.get('issuer')}")
                print(f"  Version: {cert.get('version')}")
                print(f"  Cipher: {cipher}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect proxy or load balancer presence for a given hostname.")
    parser.add_argument("hostname", help="The hostname to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display detailed information")
    args = parser.parse_args()

    detect_proxy(args.hostname, args.verbose)
