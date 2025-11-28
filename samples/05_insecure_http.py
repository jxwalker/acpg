"""
Sample 5: Insecure HTTP Connections
Violations: SEC-004 (HTTP instead of HTTPS)

This code demonstrates insecure network communication
using unencrypted HTTP.
"""

import requests
import urllib.request


# SEC-004: Hardcoded HTTP URLs
API_ENDPOINT = "http://api.production.com/v1"
PAYMENT_GATEWAY = "http://payments.example.com/process"
USER_SERVICE = "http://users.internal.corp/api"


def fetch_user_data(user_id):
    """VULNERABLE: Using HTTP for sensitive data."""
    # SEC-004: HTTP exposes data in transit
    url = f"http://api.example.com/users/{user_id}"
    response = requests.get(url)
    return response.json()


def submit_payment(card_data):
    """VULNERABLE: Sending payment data over HTTP."""
    # SEC-004: Payment data over HTTP is a PCI violation
    url = "http://payments.example.com/charge"
    return requests.post(url, json=card_data)


def download_config():
    """VULNERABLE: Downloading config over HTTP."""
    # SEC-004: Config could be tampered with
    url = "http://config.internal.com/settings.json"
    response = urllib.request.urlopen(url)
    return response.read()


def authenticate_user(username, password):
    """VULNERABLE: Sending credentials over HTTP."""
    # SEC-004: Credentials exposed in transit
    auth_url = "http://auth.example.com/login"
    return requests.post(auth_url, json={
        "username": username,
        "password": password
    })


def sync_with_partner_api(data):
    """VULNERABLE: Partner integration over HTTP."""
    # SEC-004: Business data exposed
    partner_url = "http://partner-api.external.com/sync"
    return requests.put(partner_url, json=data)


def health_check():
    """VULNERABLE: Even health checks should use HTTPS."""
    # SEC-004: Could be used for service discovery attacks
    urls = [
        "http://service1.internal.com/health",
        "http://service2.internal.com/health",
        "http://service3.internal.com/health",
    ]
    results = {}
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            results[url] = response.status_code == 200
        except:
            results[url] = False
    return results


class ExternalAPIClient:
    """VULNERABLE: API client using HTTP."""
    
    def __init__(self):
        # SEC-004: HTTP base URL
        self.base_url = "http://api.thirdparty.com"
    
    def get_data(self, endpoint):
        # SEC-004: All requests go over HTTP
        return requests.get(f"{self.base_url}/{endpoint}")
    
    def post_data(self, endpoint, data):
        # SEC-004: Posting sensitive data over HTTP
        return requests.post(f"{self.base_url}/{endpoint}", json=data)

