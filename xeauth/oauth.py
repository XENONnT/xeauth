import os
import io
import sys
import time
import param
import httpx
from .settings import config

from .token import XeToken


class XeAuthStep(param.ParameterizedFunction):
    auto_advance = param.Boolean(True)
    prompt_response = param.Parameter(instantiate=False)
    console = param.ClassSelector(io.IOBase, default=sys.stdout, 
                                  instantiate=False, pickle_default_value=False)

    def perform(self, p):
        pass

    def prompt(self, p):
        pass
    
    def __call__(self, **params):
        p = param.ParamOverrides(self, params)
        prompt_response = self.prompt(p)
        p['prompt_response'] = prompt_response
        next = self.perform(p)
        if isinstance(next, XeAuthStep) and p.auto_advance:
            params = {k:v for k,v in params.items() if k in next.param.params()}
            next = next(**params)
        return next

    
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

    def prompt(self, p):
        pass
    
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
    

class UserCredentialsAuth(XeAuthStep):
    username = param.String()
    password = param.String()

    auth_url = param.String(config.OAUTH_DOMAIN.rstrip('/')+'/token')
    audience = param.String(config.DEFAULT_AUDIENCE)
    scopes = param.List(config.DEFAULT_SCOPE.split(' '))
    client_id = param.String(config.DEFAULT_CLIENT_ID)
    headers = param.Dict({'content-type': 'application/x-www-form-urlencoded'})

    def perform(self, p):
        data = dict(
            grant_type='password',
            username=p.username,
            password=p.password,
            audience=p.audience,
            scope=' '.join(p.scope),
            client_id=p.client_id,
        )
        r = httpx.post(p.auth_url, data=data, headers=p.headers)
        r.raise_for_status()
        kwargs = r.json()
        kwargs['expires'] = time.time() + kwargs.pop('expires_in')
        return XeToken(client_id=p.client_id, **kwargs)

