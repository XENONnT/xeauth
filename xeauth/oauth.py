import time
import param
import httpx
from xeauth import config

from .tokens import XeToken

class XeAuthStep(param.ParameterizedFunction):
    
    def perform(self, p):
        pass
    
    def __call__(self, **params):
        p = param.ParamOverrides(self, params)
        return self.perform(p)

    
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
    
    def cli_prompt(self):
        print(f'Please visit the following URL to complete the login: {self.verification_uri_complete}')
        
    def perform(self, p):
        while True:
            if time.time()>p.expires:
                raise TimeoutError("Device code hase expired but not yet authorized.")
            try:
                s = self.fetch_token(p.oauth_domain, p.oauth_token_path, 
                                     p.device_code, p.client_id, headers=p.headers)
                return s
            except:
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
    scope = param.String(config.DEFAULT_SCOPE)
    audience = param.String(config.DEFAULT_AUDIENCE)
    extra_fields = param.Dict({})
    headers = param.Dict({})
    
    def cli_prompt(self):
        pass
    
    def perform(self, p):
        data = {
                    "client_id": p.client_id,
                    "scope": p.scope,
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

def cli_flow(**params):
    code_request = XeAuthCodeRequest.instance(**params)
    code_request.cli_prompt()
    token_request = code_request()
    token_request.cli_prompt()
    token = token_request()
    return token