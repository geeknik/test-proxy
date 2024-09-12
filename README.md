# test-proxy: An advanced Proxy and WAF Detection Tool

Welcome to the **Advanced Proxy and WAF Detection Tool**! This powerful and flexible tool is designed to analyze potential proxy servers, load balancers, and Web Application Firewalls (WAFs) by examining open ports, SSL certificates, HTTP headers, and various other indicators.

## Overview

This advanced script performs a comprehensive analysis of target hosts, including:

1. **Asynchronous Port Scanning with IPv6 Support**: Rapidly scans custom port ranges on both IPv4 and IPv6 addresses using asynchronous I/O.
2. **SSL/TLS Certificate Analysis**: Retrieves detailed SSL/TLS certificate information, including cipher suites, protocol versions, and validity checks.
3. **HTTP/HTTPS Header Inspection**: Sends requests to both HTTP and HTTPS endpoints and thoroughly examines the headers.
4. **Proxy/Load Balancer Detection**: Analyzes headers for a wide range of proxy and load balancer indicators, loaded dynamically from external files.
5. **Web Application Firewall (WAF) Detection**: Identifies potential WAFs based on specific header signatures, also loaded dynamically.
6. **Redirect Chain Analysis**: Tracks and reports on HTTP and HTTPS redirect chains.
7. **GeoIP Lookup**: Provides geolocation information for target IP addresses.
8. **Banner Grabbing**: Retrieves service banners on open ports to identify running services.
9. **Customizable Output Formats**: Supports text, JSON, and CSV output formats for flexibility in data analysis.
10. **Advanced Logging Control**: Allows setting of logging levels and offers verbose output for in-depth analysis.

## Features

- **High-Performance Asynchronous Scanning**: Utilizes `asyncio` for efficient port scanning and analysis.
- **IPv4 and IPv6 Support**: Capable of analyzing both IPv4 and IPv6 addresses.
- **Rate Limiting**: Implements rate limiting to prevent overwhelming target servers.
- **Custom Port Ranges**: Allows users to specify custom port ranges or additional common ports.
- **Comprehensive SSL/TLS Information**: Provides detailed SSL/TLS certificate data, including cipher suites, protocol versions, and certificate validity.
- **Advanced HTTP(S) Header Analysis**: Examines a wide range of headers to detect proxies, load balancers, and WAFs, with dynamic lists.
- **Banner Grabbing**: Retrieves service banners to identify running services on open ports.
- **Flexible Output Options**: Supports text, JSON, and CSV output formats.
- **Redirect Chain Tracking**: Follows and reports on HTTP and HTTPS redirects.
- **WAF Detection**: Identifies common Web Application Firewalls based on specific headers, with dynamic lists.
- **Verbose Logging and Logging Levels**: Offers detailed logging options and allows setting of logging levels.
- **Multiple Target Support**: Can analyze multiple targets provided via a file.
- **GeoIP Lookup**: Provides geolocation information for target IP addresses.
- **Modular Design**: Code is organized into functions and modules for better readability and maintainability.
- **Dynamic Indicator Lists**: Loads proxy and WAF indicators from external files for easy updates.

## Requirements

- **Python 3.6+**
- **Required Python libraries**:
  - `requests`
  - `urllib3`
  - `cryptography`
  - `asyncio` (built-in with Python 3.4+)
  - `csv` (built-in)
  - `datetime` (built-in)

Install the required libraries using:

```bash
pip install -r requirements.txt
```

**`requirements.txt`:**

```text
requests
cryptography
urllib3
```

## Setup

It's recommended to use a virtual environment to manage dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
```

## Usage

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/geeknik/test-proxy.git
cd test-proxy
```

Run the script with various options:

1. **Basic usage**:

   ```bash
   python testproxy.py -t example.com
   ```

2. **Analyze multiple targets from a file**:

   ```bash
   python testproxy.py -T targets.txt
   ```

3. **Specify custom port ranges**:

   ```bash
   python testproxy.py -t example.com -p 80,443,8000-8100
   ```

4. **JSON output**:

   ```bash
   python testproxy.py -t example.com -of json
   ```

5. **CSV output**:

   ```bash
   python testproxy.py -T targets.txt -of csv -f results.csv
   ```

6. **Save results to a file**:

   ```bash
   python testproxy.py -t example.com -of json -f results.json
   ```

7. **Verbose output**:

   ```bash
   python testproxy.py -t example.com -v
   ```

8. **Set logging level to DEBUG**:

   ```bash
   python testproxy.py -t example.com -l DEBUG
   ```

## Command-line Arguments

- `-t, --target`: The IP address or hostname to analyze.
- `-T, --target-file`: File containing a list of targets to analyze.
- `-p, --ports`: Comma-separated list of ports or port ranges (e.g., `80,443,8000-8100`).
- `-o, --output`: Output format, either 'text' (default) or 'json'.
- `-of, --output-format`: Output format, choices are 'text', 'json', or 'csv'.
- `-f, --file`: Output file path to save results.
- `-l, --log-level`: Set the logging level, choices are 'DEBUG', 'INFO', 'WARNING', 'ERROR' (default: 'INFO').
- `-v, --verbose`: Enable verbose output (equivalent to `--log-level DEBUG`).
- `-h, --help`: Show help message and exit.

**Note**: You must specify either `-t/--target` or `-T/--target-file`.

## Example Output

```plaintext
Analyzing www.mapbox.com...
Resolved www.mapbox.com to IP: 151.101.40.143
Geolocation info: {'country': 'United States', 'state': 'California', 'city': 'San Jose', 'latitude': 37.3388, 'longitude': -121.8914}
Open ports: [80, 443]
Banner for port 80: HTTP/1.1 301 Moved Permanently
Connection: close
Content-Length: 0
Server: Varnish
Retry-After: 0
Location: https://www.mapbox.com/
Accept-Ranges: bytes
Date: Thu, 12 Sep 2024 21:16:32 GMT
Via: 1.1 varnish
X-Frame-Options: SAMEORIGIN
X-Served-By: cache-sjc1000092-SJC
X-Cache: HIT
X-Cache-Hits: 0
X-Timer: S1726175792.109140,VS0,VE1
Cross-Origin-Opener-Policy: same-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-XSS-Protection: 1; mode=block
SSL certificate information:
  subject: CN=www.mapbox.com
  issuer: CN=GlobalSign Atlas R3 DV TLS CA 2024 Q1,O=GlobalSign nv-sa,C=BE
  version: v3
  not_valid_before: 2024-04-03 22:50:29 UTC
  not_valid_after: 2025-05-05 22:50:28 UTC
  serial_number: 2025644571350465834010730283583934283
  signature_algorithm: sha256WithRSAEncryption
  cipher: ('ECDHE-RSA-CHACHA20-POLY1305', 'TLSv1.2', 256)
  protocol: TLSv1.2
  is_valid: True

HTTP Headers (Status: 200):
  Connection: keep-alive
  Content-Type: text/html
  CF-Ray: 8c22eb4d9aa1ce9c-SJC
  CF-Cache-Status: DYNAMIC
  Age: 261818
  Content-Language: en
  Link: <https://www.mapbox.com/>; rel="canonical"
  content-security-policy: frame-ancestors 'self'
  processed-by: Weglot
  Weglot: id.8c22eb4d9aa1ce9c, p.cf
  weglot-translated: true
  x-lambda-id: 7293962f-1695-47b7-a9ad-62a23d5a3360
  Server: cloudflare
  Content-Encoding: gzip
  Accept-Ranges: bytes
  Date: Thu, 12 Sep 2024 21:16:32 GMT
  Via: 1.1 varnish
  X-Frame-Options: SAMEORIGIN
  X-Served-By: cache-sjc1000110-SJC, cache-sjc1000094-SJC
  X-Cache: HIT, MISS
  X-Cache-Hits: 8, 0
  X-Timer: S1726175792.243911,VS0,VE132
  Vary: x-wf-forwarded-proto, Accept-Encoding
  Cross-Origin-Opener-Policy: same-origin
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  X-Content-Type-Options: nosniff
  X-Download-Options: noopen
  X-XSS-Protection: 1; mode=block

HTTPS Headers (Status: 200):
  Connection: keep-alive
  Content-Type: text/html
  CF-Ray: 8c22eb4ebd17d025-SJC
  CF-Cache-Status: DYNAMIC
  Age: 261819
  Content-Language: en
  Link: <https://www.mapbox.com/>; rel="canonical"
  content-security-policy: frame-ancestors 'self'
  processed-by: Weglot
  Weglot: id.8c22eb4ebd17d025, p.cf, cs
  weglot-translated: true
  x-lambda-id: 7293962f-1695-47b7-a9ad-62a23d5a3360
  Server: cloudflare
  Content-Encoding: gzip
  Accept-Ranges: bytes
  Date: Thu, 12 Sep 2024 21:16:32 GMT
  Via: 1.1 varnish
  X-Frame-Options: SAMEORIGIN
  X-Served-By: cache-sjc10074-SJC, cache-sjc1000136-SJC
  X-Cache: HIT, MISS
  X-Cache-Hits: 31, 0
  X-Timer: S1726175792.429858,VS0,VE159
  Vary: x-wf-forwarded-proto, Accept-Encoding
  Cross-Origin-Opener-Policy: same-origin
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  X-Content-Type-Options: nosniff
  X-Download-Options: noopen
  X-XSS-Protection: 1; mode=block

HTTP Redirects:
http://www.mapbox.com/

Potential proxy/load balancer detected. Indicators found: Via, X-Cache, CF-RAY, X-Served-By, X-Timer

No Web Application Firewall (WAF) detected

Summary of findings:
  Host: www.mapbox.com
  IP: 151.101.40.143
  Open ports: [80, 443]
  SSL certificate subject: CN=www.mapbox.com
  Proxy/load balancer indicators: Via, X-Cache, CF-RAY, X-Served-By, X-Timer
  Redirects detected: 1

Analysis completed in 3.18 seconds.
```

## Dynamic Indicator Lists

The script uses external files for proxy and WAF indicators, allowing for easy updates:

- **Proxy Indicators File (`proxy_indicators.txt`)**: Contains a list of proxy indicator headers, one per line.
- **WAF Indicators File (`waf_indicators.txt`)**: Contains WAF indicator headers and their corresponding WAF names in the format `Header:WAF Name`.

Ensure these files are placed in the same directory as the script.

## Contribution

We welcome contributions! If you have ideas for improvements, new features, or bug fixes, please open an issue or submit a pull request. Make sure to follow the existing code style and add tests for new functionality.

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the `requests`, `urllib3`, and `cryptography` libraries for their powerful features.
- Inspired by various cybersecurity tools and the need for comprehensive proxy and WAF detection.
- Thanks to [cryptoscuttlebutt](https://github.com/cryptoscuttlebutt) for their contributions.

## Disclaimer

This tool is for educational and informational purposes only. Ensure you have permission before scanning any networks or systems you do not own or have explicit permission to test.

## Notes

- Always ensure you have proper authorization before scanning or analyzing targets to comply with legal and ethical guidelines.
- Be cautious when scanning multiple targets or using custom port ranges to avoid potential network issues or abuse reports.
