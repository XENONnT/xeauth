import param
import time
import httpx
import json
from contextlib import contextmanager, asynccontextmanager

from .settings import config
from .utils import id_token_from_server_state

class XeToken(param.Parameterized):
    client_id = param.String(config.DEFAULT_CLIENT_ID)
    oauth_domain = param.String(config.OAUTH_DOMAIN)
    oauth_token_path = param.String(config.OAUTH_TOKEN_PATH)

    access_token = param.String()
    id_token = param.String()
    refresh_token = param.String()
    expires = param.Number()
    scope = param.String()
    token_type = param.String("Bearer")

    @property
    def expired(self):
        return time.time()>self.expires

    @classmethod
    def from_file(cls, path):
        with open(path, "r") as f:
            data = json.load(f)
        return cls(**data)

    @classmethod
    def from_panel_server(self):
        import panel as pn
        access_token = pn.state.access_token
        id_token = id_token_from_server_state()
        self.token = XeToken(access_token=access_token,
                             id_token=id_token,
                            )
        return self.token
        
    def to_file(self, path):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f)

    def to_dict(self):
        return {k:v for k,v in self.param.get_param_values() if not k.startswith("_")}

    def refresh_tokens(self, headers={}):
        with httpx.Client(base_url=self.oauth_domain, headers=headers) as client:
            r = client.post(
                self.oauth_token_path,
            headers={"content-type":"application/x-www-form-urlencoded"},
            data={
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": self.client_id,
            }
            )
            r.raise_for_status()
            params = r.json()
            params["expires"] = time.time() + params.pop("expires_in", 1e6)
            self.param.set_param(**params)    
    
    @contextmanager
    def Client(self, *args, **kwargs):
        kwargs["headers"] = kwargs.get("headers", {})
        kwargs["headers"]["Authorization"] = f"Bearer {self.access_token}"
        
        client = httpx.Client(*args, **kwargs)
        try:
            yield client
        finally:
            client.close()

    @asynccontextmanager
    async def AsyncClient(self, *args, **kwargs ):
        kwargs["headers"] = kwargs.get("headers", {})
        kwargs["headers"]["Authorization"] = f"Bearer {self.access_token}"

        client = httpx.AsyncClient(*args, **kwargs)
        try:
            yield client
        finally:
            await client.aclose()

