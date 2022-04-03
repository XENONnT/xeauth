import param
import httpx
import time
import getpass

from .oauth import XeAuthStep
from .token import XeToken
from .settings import config

class UserCredentialsAuth(XeAuthStep):
    username = param.String(default=None)
    password = param.String(default=None)

    auth_url = param.String(config.OAUTH_DOMAIN.rstrip('/')+'/token')
    audience = param.String(config.DEFAULT_AUDIENCE)
    scopes = param.List(config.DEFAULT_SCOPE.split(' '))
    client_id = param.String(config.DEFAULT_CLIENT_ID)
    headers = param.Dict({'content-type': 'application/x-www-form-urlencoded'})

    def prompt(self, p):
        if p.username is None:
            p.username = getpass.getuser()
        if p.password is None:
            p.password = getpass.getpass()
        return p

    def perform(self, p):
        data = dict(
            grant_type='password',
            username=p.username,
            password=p.password,
            audience=p.audience,
            scope=' '.join(p.scopes),
            client_id=p.client_id,
        )
        r = httpx.post(p.auth_url, data=data, headers=p.headers)
        r.raise_for_status()
        kwargs = r.json()
        kwargs['expires'] = time.time() + kwargs.pop('expires_in')
        return XeToken(client_id=p.client_id, **kwargs)
