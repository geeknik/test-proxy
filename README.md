# Test-Proxy

Welcome to the **test-proxy** project! This tool is designed to analyze potential proxy servers or load balancers by examining open ports, SSL certificates, and HTTP headers for any signs of proxy or load balancer indicators.

## Overview

The `test-proxy` script aims to detect proxies or load balancers by performing the following steps:

1. **Open Port Check**: Scans common proxy and load balancer ports (e.g., 80, 443, 8080, 3128, 8443) to determine if they are open.
2. **SSL Certificate Retrieval**: If port 443 is open, the script retrieves and displays the SSL certificate details.
3. **HTTP Header Inspection**: Sends HTTP `HEAD` requests to the target and inspects the headers for any proxy or load balancer indicators.
4. **Proxy/Load Balancer Detection**: Analyzes HTTP headers to identify potential proxies or load balancers based on common header indicators.

## Features

- **Multi-threaded Port Scanning**: Quickly scans multiple ports using a thread pool to improve performance.
- **SSL Certificate Analysis**: Retrieves SSL certificate details to help determine if the server is behind a proxy or load balancer.
- **Comprehensive HTTP Header Checks**: Examines a wide range of HTTP headers to identify any signs of a proxy or load balancer.
- **Flexible and Extensible**: Easily customizable to add more proxy/load balancer detection techniques.

## Requirements

- Python 3.x
- Required Python libraries: `socket`, `ssl`, `requests`

You can install the required libraries using:

```bash
pip install requests
```

## Usage

Clone the repository and navigate into the project directory:

```bash
git clone https://github.com/geeknik/test-proxy.git
cd test-proxy
```

Run the script by providing the target hostname or IP address:

```bash
python test-proxy.py
```

You will be prompted to enter the IP address or hostname you want to analyze.

## Example Output

```plaintext
Enter the IP address or hostname to analyze: example.com
Analyzing example.com...
Resolved example.com to IP: 93.184.216.34
Open ports: [80, 443]
SSL certificate information:
  Subject: ((('commonName', 'example.com'),),)
  Issuer: ((('countryName', 'US'),), (('organizationName', 'DigiCert Inc'),), (('commonName', 'DigiCert SHA2 Secure Server CA'),))
  Version: 3

HTTP Headers:
  Server: ECS (dcb/7ECF)
  Date: Sat, 30 Aug 2024 00:00:00 GMT
  Content-Type: text/html; charset=UTF-8
  Content-Length: 1234
  Connection: close

HTTPS Headers:
  Server: ECS (dcb/7ECF)
  Date: Sat, 30 Aug 2024 00:00:00 GMT
  Content-Type: text/html; charset=UTF-8
  Content-Length: 1234
  Connection: close

Potential proxy/load balancer detected. Indicators found: X-Forwarded-For, X-Real-IP
```

## Contribution

Contributions are welcome! If you have suggestions for improvements or want to report a bug, please open an issue or submit a pull request.

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgments

- Thanks to the [requests](https://docs.python-requests.org/en/latest/) library for making HTTP requests easy in Python.
- Inspired by various cybersecurity and network security tools for proxy detection and network analysis.
