# Advanced Proxy and WAF Detection Tool

Welcome to the **Advanced Proxy and WAF Detection Tool**! This powerful and flexible tool is designed to analyze potential proxy servers, load balancers, and Web Application Firewalls (WAFs) by examining open ports, SSL certificates, HTTP headers, and various other indicators.

## Overview

This advanced script performs a comprehensive analysis of a target host, including:

1. **Multi-threaded Port Scanning**: Rapidly scans common ports associated with proxies and load balancers.
2. **SSL Certificate Analysis**: Retrieves detailed SSL certificate information for secure connections.
3. **HTTP/HTTPS Header Inspection**: Sends requests to both HTTP and HTTPS endpoints and thoroughly examines the headers.
4. **Proxy/Load Balancer Detection**: Analyzes headers for a wide range of proxy and load balancer indicators.
5. **Web Application Firewall (WAF) Detection**: Identifies potential WAFs based on specific header signatures.
6. **Redirect Chain Analysis**: Tracks and reports on HTTP and HTTPS redirect chains.

## Features

- **High-Performance Scanning**: Utilizes multi-threading for efficient port scanning and analysis.
- **Comprehensive SSL Information**: Provides detailed SSL certificate data, including subject, issuer, validity dates, and more.
- **Advanced HTTP(S) Header Analysis**: Examines a wide range of headers to detect proxies, load balancers, and WAFs.
- **Flexible Output Options**: Supports both human-readable text and JSON output formats.
- **Redirect Chain Tracking**: Follows and reports on HTTP and HTTPS redirects.
- **WAF Detection**: Identifies common Web Application Firewalls based on specific headers.
- **Verbose Logging**: Offers a detailed logging option for in-depth analysis and debugging.
- **Results Summary**: Provides a concise summary of key findings at the end of the analysis.

## Requirements

- Python 3.6+
- Required Python libraries: `requests`, `urllib3`, `cryptography`

Install the required libraries using:

```bash
pip install requests urllib3 cryptography
```

## Usage

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/geeknik/test-proxy.git
cd test-proxy
```

Run the script with various options:

1. Basic usage:
   ```
   python testproxy.py example.com
   ```

2. JSON output:
   ```
   python testproxy.py example.com -o json
   ```

3. Save results to a file:
   ```
   python testproxy.py example.com -o json -f results.json
   ```

4. Verbose output:
   ```
   python testproxy.py example.com -v
   ```

## Command-line Arguments

- `target`: The IP address or hostname to analyze (required)
- `-o, --output`: Output format, either 'text' (default) or 'json'
- `-f, --file`: Output file path to save results
- `-v, --verbose`: Enable verbose output for detailed logging

## Example Output

```plaintext
Analyzing example.com...
Resolved example.com to IP: 93.184.216.34
Open ports: [80, 443]

SSL certificate information:
  subject: CN=example.com
  issuer: C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1
  version: 3
  not_valid_before: 2023-08-15 00:00:00
  not_valid_after: 2024-09-14 23:59:59
  serial_number: 12345678901234567890
  signature_algorithm: sha256WithRSAEncryption

HTTP Headers (Status: 200):
  Accept-Ranges: bytes
  Age: 590933
  Cache-Control: max-age=604800
  Content-Type: text/html; charset=UTF-8
  Date: Sat, 30 Aug 2024 00:00:00 GMT
  Etag: "3147526947+ident"
  Expires: Sat, 06 Sep 2024 00:00:00 GMT
  Last-Modified: Thu, 28 Aug 2024 00:00:00 GMT
  Server: ECS (dcb/7ECE)
  Vary: Accept-Encoding
  X-Cache: HIT
  Content-Length: 1256

HTTPS Headers (Status: 200):
  Accept-Ranges: bytes
  Age: 590933
  Cache-Control: max-age=604800
  Content-Type: text/html; charset=UTF-8
  Date: Sat, 30 Aug 2024 00:00:00 GMT
  Etag: "3147526947+ident"
  Expires: Sat, 06 Sep 2024 00:00:00 GMT
  Last-Modified: Thu, 28 Aug 2024 00:00:00 GMT
  Server: ECS (dcb/7ECE)
  Vary: Accept-Encoding
  X-Cache: HIT
  Content-Length: 1256

Potential proxy/load balancer detected. Indicators found: X-Cache
No Web Application Firewall (WAF) detected

Summary of findings:
  Host: example.com
  IP: 93.184.216.34
  Open ports: [80, 443]
  SSL certificate subject: CN=example.com
  Proxy/load balancer indicators: X-Cache

Analysis completed in 2.34 seconds.
```

## Contribution

We welcome contributions! If you have ideas for improvements, new features, or bug fixes, please open an issue or submit a pull request. Make sure to follow the existing code style and add tests for new functionality.

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the `requests`, `urllib3`, and `cryptography` libraries for their powerful features.
- Inspired by various cybersecurity tools and the need for comprehensive proxy and WAF detection.
- Thanks to [cryptoscuttlebutt](https://github.com/cryptoscuttlebutt) for their contribution(s).

## Disclaimer

This tool is for educational and informational purposes only. Ensure you have permission before scanning any networks or systems you do not own or have explicit permission to test.
