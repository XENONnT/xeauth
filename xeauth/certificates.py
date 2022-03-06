import param
import httpx
import authlib
from authlib import jose
from authlib.jose.rfc7517.models import KeySet
import time
from contextlib import contextmanager
import logging

from .settings import config


logger = logging.getLogger(__name__)

class XeKeySet(param.Parameterized):
    oauth_domain = param.String(config.OAUTH_DOMAIN)
    cert_path = param.String(config.OAUTH_CERT_PATH)

    _keyset = param.ClassSelector(KeySet, default=KeySet({}))

    _keys_timestamp = param.Number(0)
    _keys_ttl = param.Number(300)

    def fetch_keys(self, headers={}):
        with httpx.Client(base_url=self.oauth_domain, headers=headers) as client:
            r = client.get(self.cert_path)
            r.raise_for_status()
        keys = r.json()
        self._keyset = jose.JsonWebKey.import_key_set(keys)

    def extract_claims(self, token):
        header_str = authlib.common.encoding.urlsafe_b64decode(token.split(".")[0].encode()).decode('utf-8')
        header = authlib.common.encoding.json_loads(header_str)
        key = self.find_by_kid(header["kid"])
        return jose.jwt.decode(token, key)

    def extract_verified_claims(self, token, options={}):
        try:
            claims = self.extract_claims(token)
            claims.options = options
            claims.validate()
            return claims
            
        except Exception as e:
            logger.error(f"Exception raised while validating claims: {e}")
            return jose.JWTClaims("", "")

    def validate_claims(self, token, **required_claims):
        options = {k: {"value": v, "essential": True} for k,v in required_claims.items()}
        claims = self.extract_claims(token)
        claims.options = options
        claims.validate()

    def find_by_kid(self, kid):
        if kid not in self._keyset.keys:
            self.fetch_keys()
        return self._keyset.find_by_kid(kid)

    def __getitem__(self, kid):
        return self.find_by_kid(kid)

certs = XeKeySet()
