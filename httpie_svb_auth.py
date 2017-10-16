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
        self.api_key = api_key
        self.hmac_secret = bytearray(hmac_secret, 'ascii')

    def __call__(self, r):
        timestamp = str(int(time.time()))
        url = urlparse(r.url)

        if url.scheme != 'https':
            raise requests.RequestException('SVB auth requires https!')

        if r.headers.get('Content-Type', b'').startswith(b'application/json'):
            body = r.body
        else:
            body = ''

        str_to_sign = '\n'.join([timestamp,
                                 r.method.upper(),
                                 url.path,
                                 url.query,
                                 body]) \
                          .encode('ascii')
        signature = hmac.new(self.hmac_secret, str_to_sign, hashlib.sha256) \
                        .hexdigest()

        r.headers['Authorization'] = 'Bearer ' + self.api_key
        r.headers['X-Signature'] = signature
        r.headers['X-Timestamp'] = timestamp
        return r


class SVBAuthPlugin(httpie.plugins.AuthPlugin):

    name = 'SVB API auth'
    description = 'Sign requests as required by the SVB API'
    auth_type = 'svb'

    def get_auth(self, username=None, password=None):
        return SVBAuth(username, password)
