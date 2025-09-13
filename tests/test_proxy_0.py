import pytest
import asyncio
import socket
import datetime
from unittest.mock import patch, MagicMock
from testproxy import check_open_ports, get_ssl_info, check_http_headers, detect_waf, detect_proxy

# Mock host to use in tests
MOCK_HOST = 'example.com'

@pytest.mark.asyncio
async def test_check_open_ports():
    ports = [80, 443, 8080]

    # Mock is_port_open function directly to return False, True, False for each port
    async def mock_is_port_open(host, port):
        return port == 443  # Only port 443 succeeds

    with patch.object(asyncio, 'open_connection', side_effect=ConnectionRefusedError), \
         patch('testproxy.is_port_open', side_effect=[False, True, False]) as mock_ip:

        open_ports = await check_open_ports(MOCK_HOST, ports)
        # The check_open_ports function calls is_port_open for each port
        # and collects results, so it should return [443] if is_port_open returns True only for port 443
        mock_ip.assert_has_calls([((MOCK_HOST, 80),), ((MOCK_HOST, 443),), ((MOCK_HOST, 8080),)])
        assert open_ports == [443]

def test_get_ssl_info():
    # Create mock datetime objects with timezone info
    past_date = datetime.datetime(2023, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    future_date = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    # Mock version to have a 'name' attribute like the actual enum
    mock_version = MagicMock()
    mock_version.name = 'v3'

    mock_cert = MagicMock()
    mock_cert.subject.rfc4514_string.return_value = "CN=example.com"
    mock_cert.issuer.rfc4514_string.return_value = "C=US,O=DigiCert Inc,CN=DigiCert SHA2 Secure Server CA"
    mock_cert.version = mock_version  # Use mock version with name
    mock_cert.not_valid_before_utc = past_date
    mock_cert.not_valid_after_utc = future_date
    mock_cert.serial_number = 12345678901234567890
    mock_cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"

    mock_socket_ctx = MagicMock()
    mock_sock = MagicMock()
    mock_sock.getpeercert.return_value = b'mock certificate bytes'
    mock_sock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 'ECDHE_RSA_WITH_AES_256_GCM_SHA384')
    mock_sock.version.return_value = 'TLSv1.3'

    with patch('ssl.create_default_context', return_value=mock_socket_ctx), \
         patch('socket.create_connection', return_value=mock_sock), \
         patch('testproxy.datetime', wraps=datetime) as mock_datetime, \
         patch('cryptography.x509.load_der_x509_certificate', return_value=mock_cert):

        # Mock current time for validity check
        current_time = datetime.datetime(2023, 6, 15, 0, 0, 0, tzinfo=datetime.timezone.utc)
        mock_datetime.datetime.now.return_value = current_time.replace(tzinfo=datetime.timezone.utc)

        ssl_info = get_ssl_info(MOCK_HOST)

        if ssl_info is None:
            pytest.fail("Expected ssl_info to be returned, but got None")
        else:
            assert ssl_info['subject'] == "CN=example.com"
            assert ssl_info['issuer'] == "C=US,O=DigiCert Inc,CN=DigiCert SHA2 Secure Server CA"
            assert ssl_info['version'] == 'v3'  # Should match the mocked version.name
            assert ssl_info['not_valid_before'] == "2023-01-01 00:00:00 UTC"
            assert ssl_info['not_valid_after'] == "2024-01-01 00:00:00 UTC"
            assert ssl_info['serial_number'] == '12345678901234567890'
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
    # Mock waf indicators dictionary (header -> waf_name mapping)
    waf_indicators = {
        'x-waf-rate-limit': 'Generic WAF',
        'cf-ray': 'Cloudflare WAF',
        'server:cloudflare': 'Cloudflare WAF',
        'x-powered-by-plesk': 'Plesk WAF',
        'x-waf-detected': 'Generic WAF'
    }

    headers_with_waf = {
        'X-WAF-Rate-Limit': '100',
        'cf-ray': '12345678901234567-IAD'
    }
    detected_wafs = detect_waf(headers_with_waf, waf_indicators)
    assert 'Generic WAF' in detected_wafs
    assert 'Cloudflare WAF' in detected_wafs

    headers_without_waf = {
        'Server': 'Apache',
        'Content-Type': 'text/html; charset=UTF-8'
    }
    detected_wafs = detect_waf(headers_without_waf, waf_indicators)
    assert len(detected_wafs) == 0

@pytest.mark.asyncio
async def test_detect_proxy():
    # Mock data and parameters
    common_ports = [80, 443, 8080]
    proxy_indicators = ['X-Forwarded-For', 'Via', 'X-Real-IP']
    waf_indicators = {
        'x-waf-rate-limit': 'Generic WAF',
        'cf-ray': 'Cloudflare WAF'
    }

    expected_cert = {
        'subject': 'CN=example.com',
        'issuer': 'C=US,O=DigiCert Inc,CN=DigiCert SHA2 Secure Server CA',
        'version': 3,
        'not_valid_before': '2023-01-01 00:00:00 UTC',
        'not_valid_after': '2024-01-01 00:00:00 UTC',
        'serial_number': 12345678901234567890,
        'signature_algorithm': 'sha256WithRSAEncryption',
        'cipher': 'TLS_AES_256_GCM_SHA384',
        'protocol': 'TLSv1.3',
        'is_valid': True
    }

    mock_http_headers = {
        'Server': 'Apache',
        'X-Forwarded-For': '10.0.0.1'
    }
    mock_https_headers = {
        'Server': 'Apache',
        'Strict-Transport-Security': 'max-age=31536000',
        'cf-ray': '12345678901234567-IAD'
    }

    with patch('socket.gethostbyname', return_value='93.184.216.34'), \
         patch('testproxy.check_open_ports', return_value=[80, 443]), \
         patch('testproxy.get_ssl_info', return_value=expected_cert), \
         patch('testproxy.secure_headers_check', side_effect=[
             (mock_http_headers, 200, []),
             (mock_https_headers, 200, [])
         ]), \
         patch('testproxy.detect_waf', side_effect=[
             [],  # WAF detection on HTTP headers
             ['Cloudflare WAF']  # WAF detection on HTTPS headers
         ]), \
         patch('testproxy.get_geoip_info', return_value={
             'country': 'US',
             'city': 'New York',
             'latitude': 40.7128,
             'longitude': -74.0060
         }), \
         patch('testproxy.grab_banner_async', side_effect=[
             None,  # Port 80 banner
             'HTTP/1.1 200 OK',  # Port 443 banner
             None   # Port 8080 banner
         ]):
        results = await detect_proxy(MOCK_HOST, common_ports, proxy_indicators, waf_indicators, verify_ssl=False)

        # Verify the results structure
        assert isinstance(results, dict)
        assert results['host'] == MOCK_HOST
        assert results['ip'] == '93.184.216.34'
        assert results['open_ports'] == [80, 443]
        assert results['ssl_info'] == expected_cert
        assert results['http_headers'] == mock_http_headers
        assert results['https_headers'] == mock_https_headers
        assert results['proxy_indicators'] == ['X-Forwarded-For']  # Only found in HTTP headers
        assert results['waf_detected'] == ['Cloudflare WAF']  # From HTTPS headers

if __name__ == "__main__":
    pytest.main()
