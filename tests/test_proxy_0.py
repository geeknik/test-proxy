import pytest
import socket
from unittest.mock import patch, MagicMock
from testproxy import check_open_ports, get_ssl_info, check_http_headers, detect_waf, detect_proxy

# Mock host to use in tests
MOCK_HOST = 'example.com'

def test_check_open_ports():
    ports = [80, 443, 8080]
    with patch('socket.create_connection') as mock_connection:
        mock_connection.side_effect = [socket.timeout, MagicMock(), socket.timeout]
        open_ports = check_open_ports(MOCK_HOST, ports)
        assert open_ports == [443]

def test_get_ssl_info():
    mock_cert = MagicMock()
    mock_cert.subject.rfc4514_string.return_value = "CN=example.com"
    mock_cert.issuer.rfc4514_string.return_value = "C=US,O=DigiCert Inc,CN=DigiCert SHA2 Secure Server CA"
    mock_cert.version = 3
    mock_cert.not_valid_before.strftime.return_value = "2023-01-01 00:00:00"
    mock_cert.not_valid_after.strftime.return_value = "2024-01-01 00:00:00"
    mock_cert.serial_number = 12345678901234567890
    mock_cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"

    with patch('ssl.create_default_context'), \
         patch('socket.create_connection'), \
         patch('ssl.SSLSocket.getpeercert', return_value=mock_cert), \
         patch('cryptography.x509.load_der_x509_certificate', return_value=mock_cert):

        ssl_info = get_ssl_info(MOCK_HOST)
        assert ssl_info['subject'] == "CN=example.com"
        assert ssl_info['issuer'] == "C=US,O=DigiCert Inc,CN=DigiCert SHA2 Secure Server CA"
        assert ssl_info['version'] == 3
        assert ssl_info['not_valid_before'] == "2023-01-01 00:00:00"
        assert ssl_info['not_valid_after'] == "2024-01-01 00:00:00"
        assert ssl_info['serial_number'] == 12345678901234567890
        assert ssl_info['signature_algorithm'] == "sha256WithRSAEncryption"

def test_check_http_headers():
    mock_headers = {
        'Server': 'Apache',
        'Content-Type': 'text/html; charset=UTF-8',
        'X-Forwarded-For': '10.0.0.1'
    }

    with patch('requests.head') as mock_request:
        mock_response = MagicMock()
        mock_response.headers = mock_headers
        mock_response.status_code = 200
        mock_response.history = []
        mock_request.return_value = mock_response

        headers, status_code, history = check_http_headers(f'http://{MOCK_HOST}')
        assert headers == mock_headers
        assert status_code == 200
        assert history == []

def test_detect_waf():
    headers_with_waf = {
        'Server': 'Apache',
        'X-WAF-Rate-Limit': '100',
        'cf-ray': '12345678901234567-IAD'
    }
    detected_wafs = detect_waf(headers_with_waf)
    assert 'Generic WAF' in detected_wafs
    assert 'Cloudflare WAF' in detected_wafs

    headers_without_waf = {
        'Server': 'Apache',
        'Content-Type': 'text/html; charset=UTF-8'
    }
    detected_wafs = detect_waf(headers_without_waf)
    assert len(detected_wafs) == 0

def test_detect_proxy():
    mock_results = {
        'host': MOCK_HOST,
        'ip': '93.184.216.34',
        'open_ports': [80, 443],
        'ssl_info': {
            'subject': 'CN=example.com',
            'issuer': 'C=US,O=DigiCert Inc,CN=DigiCert SHA2 Secure Server CA',
            'version': 3,
            'not_valid_before': '2023-01-01 00:00:00',
            'not_valid_after': '2024-01-01 00:00:00',
            'serial_number': 12345678901234567890,
            'signature_algorithm': 'sha256WithRSAEncryption'
        },
        'http_headers': {
            'Server': 'Apache',
            'X-Forwarded-For': '10.0.0.1'
        },
        'https_headers': {
            'Server': 'Apache',
            'Strict-Transport-Security': 'max-age=31536000'
        },
        'proxy_indicators': ['X-Forwarded-For'],
        'waf_detected': ['Generic WAF'],
        'redirects': []
    }

    with patch('socket.gethostbyname', return_value='93.184.216.34'), \
         patch('testproxy.check_open_ports', return_value=[80, 443]), \
         patch('testproxy.get_ssl_info', return_value=mock_results['ssl_info']), \
         patch('testproxy.check_http_headers', side_effect=[
             (mock_results['http_headers'], 200, []),
             (mock_results['https_headers'], 200, [])
         ]), \
         patch('testproxy.detect_waf', return_value=['Generic WAF']):

        results = detect_proxy(MOCK_HOST, 'json')
        assert isinstance(results, str)  # Ensure JSON string is returned

        import json
        parsed_results = json.loads(results)
        assert parsed_results['host'] == MOCK_HOST
        assert parsed_results['ip'] == '93.184.216.34'
        assert parsed_results['open_ports'] == [80, 443]
        assert parsed_results['ssl_info'] == mock_results['ssl_info']
        assert parsed_results['http_headers'] == mock_results['http_headers']
        assert parsed_results['https_headers'] == mock_results['https_headers']
        assert parsed_results['proxy_indicators'] == ['X-Forwarded-For']
        assert parsed_results['waf_detected'] == ['Generic WAF']
        assert parsed_results['redirects'] == []

if __name__ == "__main__":
    pytest.main()
