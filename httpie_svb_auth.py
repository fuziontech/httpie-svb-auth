"""
SVB API auth plugin for HTTPie.

http://docs.svbplatform.com/
Copyright (c) 2017 Silicon Valley Bank
"""
import hashlib
import hmac
import httpie.plugins
import requests
import time

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class SVBAuth:

    def __init__(self, api_key, hmac_secret):
        self.api_key = None
        self.key_id = None
        self.company_id = None

        self.hmac_secret = bytearray(hmac_secret, 'ascii') if hmac_secret else None

        if "keyid" in api_key or "companyid" in api_key and "&" in api_key:
            keys = api_key.split('&')
        else:
            keys = list(api_key)

        for key in keys:
            if "keyid=" in key:
                self.key_id = key.split("=")[-1:][0]
            elif "companyid=" in key:
                self.company_id = key.split("=")[-1:][0] 
            else:
                self.api_key = api_key

    def __call__(self, r):
        timestamp = str(int(time.time()))
        url = urlparse(r.url)

        if url.scheme != 'https':
            if '127.0.0.1' not in url.netloc and 'localhost' not in url.netloc:
                raise requests.RequestException('SVB auth requires https!')

        if r.headers.get('Content-Type', b'').startswith(b'application/json'):
            body = r.body
        else:
            body = ''

        if self.hmac_secret:
            str_to_sign = '\n'.join([timestamp,
                                    r.method.upper(),
                                    url.path,
                                    url.query,
                                    body]) \
                            .encode('ascii')
            signature = hmac.new(self.hmac_secret, str_to_sign, hashlib.sha256) \
                            .hexdigest()

            r.headers['X-Signature'] = signature
            r.headers['X-Timestamp'] = timestamp
        if self.key_id or self.company_id:
            if self.key_id:
                r.headers['X-Key-Id'] = self.key_id
            if self.company_id:
                r.headers['X-Company-Id'] = self.company_id
        else:
            r.headers['Authorization'] = 'Bearer ' + self.api_key
        return r


class SVBAuthPlugin(httpie.plugins.AuthPlugin):

    name = 'SVB API auth'
    description = 'Sign requests as required by the SVB API'
    auth_type = 'svb'

    def get_auth(self, username=None, password=None):
        return SVBAuth(username, password)
