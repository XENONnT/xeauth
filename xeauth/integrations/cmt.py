import xeauth
import rframe

try:
    import straxen
    KNOWN_CORRECTIONS = list(straxen.BaseCorrectionSchema._SCHEMAS)
except ImportError:
    KNOWN_CORRECTIONS = []


class CorrectionsHttpClient:
    AUDIENCE = 'https://api.cmt.xenonnt.org'
    BASE_URL = 'https://api.cmt.yossisprojects.com'
    
    def __init__(self, token):
        self.token = token

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
        xetoken = xeauth.login(audience=audience, scopes=scope, **kwargs)
        return cls(xetoken.access_token)
    
    def __getitem__(self, name):
        if KNOWN_CORRECTIONS and name not in KNOWN_CORRECTIONS:
            raise KeyError(name)
        url = f'{self.BASE_URL}/{name}'
        headers = {'Authorization': f"Bearer {self.token}"}
        return rframe.BaseHttpClient(url, headers)
    
    def __getattr__(self, attr):
        if KNOWN_CORRECTIONS and attr not in KNOWN_CORRECTIONS:
            raise AttributeError(attr)
        return self[attr]

    def __dir__(self):
        return KNOWN_CORRECTIONS + super().__dir__()
 
    def __contains__(self, name):
        if KNOWN_CORRECTIONS and name not in KNOWN_CORRECTIONS:
            return False
        return True