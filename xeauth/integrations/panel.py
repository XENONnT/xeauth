from xeauth.settings import config
from xeauth.github import GitHubAuth
from panel.auth import GithubLoginHandler
from tornado.httpclient import HTTPError, HTTPRequest

import panel as pn

if pn.config.oauth_key:
    config.DEFAULT_CLIENT_ID = pn.config.oauth_key


class XenonLoginHandler(GithubLoginHandler):
    """Xenon login handler.
    """
    
    _SCOPE = " ".join(["read:org", "read:user", "read:public_key", "user:email", "read:gpg_key"])

    def _on_auth(self, user_info, access_token, refresh_token=None):
        auth = GitHubAuth(oauth_token=access_token)
        if not auth.xenonnt_member:
            raise HTTPError(500, f"Github authentication failed. You are not a member of the XENONnT organization.")
