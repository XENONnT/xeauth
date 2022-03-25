import os
import panel as pn

import getpass
from .settings import config

# from .oauth import XeAuthSession, NotebookSession, UserCredentialsAuth
# from .user_credentials import UserCredentialsAuth
from .oauth import UserCredentialsAuth, XeAuthCodeRequest
from .certificates import certs


user_login = UserCredentialsAuth.instance(auto_advance=True)


login = XeAuthCodeRequest.instance(auto_advance=True)


def cli_login(**kwargs):
    token = login(**kwargs)
    print(f"logged in as: {token.profile.get('name', 'unknown')}")
    print(f"Access token: {token.access_token}")
    print(f"ID token: {token.id_token}")


def validate_claims(token, **claims):
    return certs.validate_claims(token, **claims)

def clear_cache():
    os.remove(config.CACHE_FILE)

def cmt_login(scopes=[], **kwargs):
    if isinstance(scopes, str):
        scopes = scopes.split(' ')
    if not isinstance(scopes, list):
        raise TypeError('scopes must be a list or string')
    scopes = set(scopes)
    scopes.add('read:all')
    scopes =  list(scopes)
    audience = kwargs.pop('audience', 'https://api.cmt.xenonnt.org')
    # base_url = kwargs.pop('base_url', DEFAULT_BASE_URL)
    return login(audience=audience, scopes=scopes, **kwargs)
