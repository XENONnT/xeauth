import os
import panel as pn

import getpass
from xeauth.settings import config
from .oauth import XeAuthSession, NotebookSession
from .user_credentials import UserCredentialsAuth
from .certificates import certs

def user_login(username=None, password=None, **kwargs):
    if username is None:
        username = input('Username: ')
    if password is None:
        password = getpass.getpass("Password: ")
    auth = UserCredentialsAuth(**kwargs)
    return auth.login(username=username, password=password)

def login(client_id=config.DEFAULT_CLIENT_ID, scopes=[], audience=config.DEFAULT_AUDIENCE,
             notify_email=None, open_browser=True, print_url=True, **kwargs):
    if isinstance(scopes, str):
        scopes = scopes.split(" ")
    scopes = list(scopes)
    session = XeAuthSession(client_id=client_id, scopes=scopes, audience=audience,  notify_email=notify_email, **kwargs)
    # return session
    return session.login(open_browser=open_browser, print_url=print_url)

def notebook_login(client_id=config.DEFAULT_CLIENT_ID, scopes=[],
                    audience=config.DEFAULT_AUDIENCE, notify_email=None, open_browser=True):
    pn.extension()
    if isinstance(scopes, str):
        scopes = scopes.split(" ")
    scopes = list(scopes)
    session = NotebookSession(client_id=client_id, scopes=scopes, audience=audience, notify_email=notify_email)
    session.login_requested(None)
    if open_browser:
        session.authorize()
    return session

def cli_login(client_id=config.DEFAULT_CLIENT_ID, scopes=[], 
                audience=config.DEFAULT_AUDIENCE, notify_email=None):
    if isinstance(scopes, str):
        scopes = scopes.split(" ")
    scopes = list(scopes)
    session = login(client_id=client_id, scopes=scopes, audience=audience, notify_email=notify_email, print_url=True)
    print("logged in as:")
    print(session.profile)
    print(f"Access token: {session.access_token}")
    print(f"ID token: {session.id_token}")

def validate_claims(token, **claims):
    return certs.validate_claims(token, **claims)

def clear_cache():
    os.remove(config.CACHE_FILE)

def cmt_login(scope=None, **kwargs):
    if scope is None:
        scope = []
    elif isinstance(scope, str):
        scope = [scope]
    if not isinstance(scope, list):
        raise ValueError('scope must be a string or list of strings')
    scope += ['read:all']
    audience = kwargs.pop('audience', 'https://api.cmt.xenonnt.org')
    # base_url = kwargs.pop('base_url', DEFAULT_BASE_URL)
    return login(audience=audience, scopes=scope, **kwargs)
