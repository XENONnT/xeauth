

from tornado.auth import OAuth2Mixin
from panel.auth import OAuthIDTokenLoginHandler
from panel.config import config as pnconfig
from xeauth.settings import config as xeconfig
import logging

log = logging.getLogger(__name__)

class XenonPanelAuth(OAuthIDTokenLoginHandler, OAuth2Mixin):
    
    _AUDIENCE = xeconfig.DEFAULT_AUDIENCE

    _SCOPE = xeconfig.DEFAULT_SCOPE.split(' ')

    _USER_KEY = 'email'

    _EXTRA_TOKEN_PARAMS = {
        'grant_type':    'authorization_code',
    }
    
    _EXTRA_AUTHORIZE_PARAMS = {
        'grant_type': 'authorization_code',
    }

    _OAUTH_ACCESS_TOKEN_URL_ = 'https://{0}.auth0.com/oauth/token'
    _OAUTH_AUTHORIZE_URL_ = 'https://{0}.auth0.com/authorize'
    _OAUTH_USER_URL_ = 'https://{0}.auth0.com/userinfo?access_token='

    @property
    def _OAUTH_ACCESS_TOKEN_URL(self):
        url = pnconfig.oauth_extra_params.get('subdomain', xeconfig.AUTH0_SUBDOMAIN)
        return self._OAUTH_ACCESS_TOKEN_URL_.format(url)

    @property
    def _OAUTH_AUTHORIZE_URL(self):
        url = pnconfig.oauth_extra_params.get('subdomain', xeconfig.AUTH0_SUBDOMAIN)
        return self._OAUTH_AUTHORIZE_URL_.format(url)

    @property
    def _OAUTH_USER_URL(self):
        url = pnconfig.oauth_extra_params.get('subdomain', xeconfig.AUTH0_SUBDOMAIN)
        return self._OAUTH_USER_URL_.format(url)

    async def get_authenticated_user(self, redirect_uri, client_id, state,
                                     client_secret=None, code=None):
        """
        Fetches the authenticated user

        Arguments
        ---------
        redirect_uri: (str)
          The OAuth redirect URI
        client_id: (str)
          The OAuth client ID
        state: (str)
          The unguessable random string to protect against
          cross-site request forgery attacks
        client_secret: (str, optional)
          The client secret
        code: (str, optional)
          The response code from the server
        """
        if code:
            return await self._fetch_access_token(
                code,
                redirect_uri,
                client_id,
                client_secret
            )

        params = {
            'redirect_uri': redirect_uri,
            'client_id':    client_id,
            'client_secret': client_secret,
            'extra_params': {
                'state': state,
            },
        }
        if self._SCOPE is not None:
            params['scope'] = self._SCOPE
        if 'scope' in pnconfig.oauth_extra_params:
            params['scope'] = pnconfig.oauth_extra_params['scope']

        if self._AUDIENCE is not None:
            params['extra_params']['audience'] = self._AUDIENCE
        if 'audience' in pnconfig.oauth_extra_params:
            params['extra_params']['audience'] = pnconfig.oauth_extra_params['audience']

        log.debug("%s making authorize request" % type(self).__name__)
        self.authorize_redirect(**params)
