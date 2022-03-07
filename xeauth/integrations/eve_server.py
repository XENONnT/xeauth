from eve.auth import BasicAuth, TokenAuth
from eve.utils import config
from flask import request, Response, g
from flask import abort
import xeauth


class XeTokenAuth(TokenAuth):

    @property
    def global_read_token(self):
        return config.get('API_GLOBAL_READ_TOKEN', None)

    @property
    def audience(self):
        return config.get('JWT_AUDIENCE', 'https//:api.pmts.xenonnt.org')

    def check_auth(self, token, allowed_roles, resource, method):
        if not token:
            return False
        if method in ['GET', 'HEAD'] and self.global_read_token==token:
            return True
        try:
            xeauth.certs.validate_claims(token, audience=self.audience)
        except:
            return False
        c = xeauth.certs.extract_verified_claims(token)
        roles = c.get('scope', '').split(' ')
        return any([r in allowed_roles for r in roles])