import time
import param
import httpx

from .settings import config
from .token import XeToken
from .oauth import XeAuthStep


class XeTokenRequest(XeAuthStep):

    oauth_domain = param.String(config.OAUTH_DOMAIN)
    oauth_token_path = param.String(config.OAUTH_TOKEN_PATH)
    user_code = param.String()
    device_code = param.String()
    client_id = param.String()
    headers = param.Dict()
    
    verification_uri = param.String()
    verification_uri_complete = param.String()
    
    expires = param.Number()
    interval = param.Number(5)

    open_browser = param.Boolean(True)
    
    def prompt(self, p):
        print(f'Please visit the following URL to complete ' 
              f'the login: {self.verification_uri_complete}', file=p.console)
        if p.open_browser:
            import webbrowser
            webbrowser.open(self.verification_uri_complete)
        return p

    def perform(self, p):
        while True:
            if time.time()>p.expires:
                raise TimeoutError("Device code hase expired but not yet authorized.")
            try:
                s = self.fetch_token(p.oauth_domain, p.oauth_token_path, 
                                     p.device_code, p.client_id, headers=p.headers)
                
                return s
            except Exception as e:
                time.sleep(p.interval)
           
    def fetch_token(self, oauth_domain, oauth_token_path, device_code, client_id, headers={}):
        with httpx.Client(base_url=oauth_domain, headers=headers) as client:
            r = client.post(
                oauth_token_path,
                
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
            )
            r.raise_for_status()
            params = r.json()
            params["expires"] = time.time() + params.pop("expires_in", 1e6)
            params["client_id"] = self.client_id
            params['oauth_domain'] = oauth_domain
            params['oauth_token_path'] = oauth_token_path
            
        return XeToken(**params)


class XeAuthCodeRequest(XeAuthStep):
    oauth_domain = param.String(config.OAUTH_DOMAIN)
    oauth_code_path = param.String(config.OAUTH_CODE_PATH)
    client_id = param.String(config.DEFAULT_CLIENT_ID) 
    scopes = param.List(config.DEFAULT_SCOPE.split(' '))
    audience = param.String(config.DEFAULT_AUDIENCE)
    extra_fields = param.Dict({})
    headers = param.Dict({})
    
    @property
    def scope_str(self):
        return ' '.join(self.scopes)
    
    def perform(self, p):
        data = {
                    "client_id": p.client_id,
                    "scope": ' '.join(p.scopes),
                    "audience": p.audience,
                    }
        data.update(p.extra_fields)
        
        with httpx.Client(base_url=p.oauth_domain, headers=p.headers) as client:
    
            r = client.post(
                p.oauth_code_path,
                data=data,
                headers={"content-type": "application/x-www-form-urlencoded"})
            
            r.raise_for_status()
            
        params = r.json()
        
        params['expires'] = time.time() + params.pop("expires_in", 1)
        params['oauth_domain'] = p.oauth_domain
        params['client_id'] = p.client_id

        return XeTokenRequest.instance(**params)

