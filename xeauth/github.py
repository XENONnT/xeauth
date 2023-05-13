from contextlib import contextmanager
import httpx
import param
import time
from rich.console import Console
from .settings import config


class GitHubApi(param.Parameterized):
    API_URL = 'https://api.github.com'
    
    oauth_token = param.String()
    
    @contextmanager
    def Client(self, *args, **kwargs):
        kwargs["headers"] = kwargs.get("headers", {})
        kwargs["headers"]["Authorization"] = f"Bearer {self.oauth_token}"
        kwargs["headers"]["Accept"] = "application/json"
        client = httpx.Client(*args, base_url=self.API_URL, **kwargs)
        try:
            yield client
        finally:
            client.close()
    
    def get(self, path, *args, **kwargs):
        with self.Client() as client:
            response = client.get(path, *args, **kwargs)
        response.raise_for_status()
        return response.json()

    def post(self, path, *args, **kwargs):
        with self.Client() as client:
            response = client.post(path, *args, **kwargs)
        response.raise_for_status()
        return response.json()  

    @property
    def profile(self):
        return self.get('/user')
    
    @property
    def username(self):
        return self.profile.get('login')

    @property
    def organizations(self):
        return [org.get('login') for org in self.get('/user/orgs')]

    @property
    def teams(self):
        orgs = self.organizations
        teams = []
        for org in orgs:
            teams.extend([team.get('name') for team in self.get(f'/orgs/{org}/teams')])
        return teams

    @property
    def repositories(self):
        return [repo.get('name') for repo in self.get('/user/repos')]

    @property
    def starred_repositories(self):
        return [repo.get('name') for repo in self.get('/user/starred')]

    @property
    def followers(self):
        return [user.get('login') for user in self.get('/user/followers')]

    @property
    def gpg_keys(self):
        return self.get('/user/gpg_keys')


class GitHubDeviceCode(param.Parameterized):
    """GitHub device code authentication.
    """
    
    base_url = param.String(default='https://github.com/login', doc='Github auth URL')
    client_id = param.String(doc='GitHub App client ID', default=config.DEFAULT_CLIENT_ID)
    device_code = param.String(doc='GitHub device code')
    user_code = param.String(doc='GitHub user code')
    verification_uri = param.String(doc='GitHub verification URI')
    expires = param.Number(doc='Expiration time of the device code')
    interval = param.Integer(doc='Interval between polling requests')


    @classmethod
    def from_response_data(cls, client_id, data):
        return cls(**data)


    def open_browser(self):
        import webbrowser
        webbrowser.open(self.verification_uri)
    
    @property
    def prompt(self):
        return f'Go to {self.verification_uri} and enter the code: {self.user_code}'

    def await_token(self):
        while True:
            if time.time() >= self.expires:
                raise Exception("Authentication timed out. Please try again.")
            access_token = self.check_for_access_token()
            if access_token is not None:
                return access_token
            time.sleep(self.interval)
    
    def check_for_access_token(self):
        with httpx.Client(base_url=self.base_url) as client:
            response = client.post(
                '/oauth/access_token',
                data = {
                    'client_id': self.client_id,
                    'device_code': self.device_code,
                    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                    },
                headers = {"Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
            return data.get("access_token", None)


class GithubAuth(param.Parameterized):
    BASE_URL = 'https://github.com/login'
    DEFAULT_SCOPES = ("read:org", "read:user")

    oauth_token = param.String()
    
    @classmethod
    def get_device_code(cls, client_id=None, scopes=None):
        if client_id is None:
            client_id = config.DEFAULT_CLIENT_ID
        
        if client_id is None:
            raise ValueError("client_id must be provided")
       
        if scopes is None:
            scopes = cls.DEFAULT_SCOPES

        data = {'client_id': client_id}
        
        if scopes is not None:
            data['scope'] = ' '.join(scopes)

        with httpx.Client(base_url=cls.BASE_URL) as client:
            response = client.post(
                '/device/code',
                data=data,
                headers = {"Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
            data['expires'] = time.time() + data.pop('expires_in', 900)
            data['client_id'] = client_id
            data['base_url'] = cls.BASE_URL
            return GitHubDeviceCode(**data)
        
    @classmethod
    def device_login(cls, client_id, scopes=None, console=None):
        if console is None:
            console = Console()
        code = cls.get_device_code(client_id, scopes=scopes)
        console.print(code.prompt)
        token = code.await_token()
        return cls(client_id=client_id, oauth_token=token)
    
    @contextmanager
    def Client(self, *args, **kwargs):
        kwargs["headers"] = kwargs.get("headers", {})
        kwargs["headers"]["Authorization"] = f"Bearer {self.oauth_token}"
        kwargs["headers"]["Accept"] = "application/json"
        client = httpx.Client(*args, **kwargs)
        try:
            yield client
        finally:
            client.close()

    @property
    def api(self):
        return GitHubApi(oauth_token=self.oauth_token)

    @property
    def xenonnt_member(self):
        return "XENONnT" in self.api.organizations

    @property
    def xenon1t_member(self):
        return "XENON1T" in self.api.organizations

    @property
    def xenon_member(self):
        return self.xenonnt_member or self.xenon1t_member
