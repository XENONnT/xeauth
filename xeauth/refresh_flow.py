import time
import param
import httpx

from .settings import config
from .token import XeToken
from .oauth import XeAuthStep



class TokenRefresh(XeAuthStep):
    client_id = param.String(config.DEFAULT_CLIENT_ID)
    oauth_domain = param.String(config.OAUTH_DOMAIN)
    oauth_token_path = param.String(config.OAUTH_TOKEN_PATH)

    access_token = param.String(readonly=True)
    id_token = param.String(readonly=True)
    refresh_token = param.String(readonly=True)

    def perform(self, p):
        with httpx.Client(base_url=self.oauth_domain, headers=p.headers) as client:
            r = client.post(
                p.oauth_token_path,
            headers={"content-type":"application/x-www-form-urlencoded"},
            data={
                "grant_type": "refresh_token",
                "refresh_token": p.refresh_token,
                "client_id": p.client_id,
            }
            )
            r.raise_for_status()
            params = r.json()
            params["expires"] = time.time() + params.pop("expires_in", 1e6)
            params["client_id"] = p.client_id
            params['oauth_domain'] = p.oauth_domain
            params['oauth_token_path'] = p.oauth_token_path
            return XeToken(**params)
