import param
import httpx
import time
from .settings import config
from .tokens import XeToken


class UserCredentialsAuth(param.Parameterized):
    AUTH_URL = param.String(config.OAUTH_DOMAIN.rstrip('/')+'/token')
    audience = param.String(config.DEFAULT_AUDIENCE)
    scope = param.String(config.DEFAULT_SCOPE)
    client_id = param.String(config.DEFAULT_CLIENT_ID)
    headers = param.Dict({'content-type': 'application/x-www-form-urlencoded'})

    def login(self, username, password, audience=None, scope=None):
        if scope is None:
            scope = self.scope
        if audience is None:
            audience = self.audience

        data = dict(
            grant_type='password',
            username=username,
            password=password,
            audience=audience,
            scope=scope,
            client_id=self.client_id,
        )
        r = httpx.post(self.AUTH_URL, data=data, headers=self.headers)
        r.raise_for_status()
        kwargs = r.json()
        kwargs['expires'] = time.time() + kwargs.pop('expires_in')
        return XeToken(client_id=self.client_id, **kwargs)