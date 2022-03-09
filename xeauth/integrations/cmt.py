import xeauth
import rframe
import httpx


class CorrectionsHttpClient:
    AUDIENCE = 'https://api.cmt.xenonnt.org'
    DEFAULT_BASE_URL = 'https://api.cmt.yossisprojects.com'
    
    def __init__(self, base_url, names, token=None):
        self._base_url = base_url
        self._names = names
        self._token = token
        
        
    @classmethod
    def login(cls, scope=None, **kwargs):
        if scope is None:
            scope = []
        elif isinstance(scope, str):
            scope = [scope]
        if not isinstance(scope, list):
            raise ValueError('scope must be a string or list of strings')
        scope += ['read:all']
        audience = kwargs.pop('audience', cls.AUDIENCE)
        base_url = kwargs.pop('base_url', cls.DEFAULT_BASE_URL)
        token = xeauth.login(audience=audience, scopes=scope, **kwargs).access_token
        names = httpx.get(base_url,
                          headers={'Authorization': f"Bearer {token}"},
                          ).json()
        return cls(base_url, names=names, token=token)
    
    def __getitem__(self, name):
        if name not in self._names:
            raise KeyError(name)
        url = f'{self._base_url}/{name}'
        headers = {'Authorization': f"Bearer {self._token}"}
        return rframe.BaseHttpClient(url, headers)
    
    def __getattr__(self, attr):
        if attr not in self._names:
            raise AttributeError(attr)
        return self[attr]

    def __dir__(self):
        return self._names + super().__dir__()
 
    def __contains__(self, name):
        return name in self._names
