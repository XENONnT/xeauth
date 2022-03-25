import os
import param
import httpx
import time
import webbrowser
import logging
import panel as pn

from datetime import datetime
from contextlib import contextmanager, asynccontextmanager

from .settings import config
from .utils import url_link_button, id_token_from_server_state
from .certificates import certs
from .token import XeToken


logger = logging.getLogger(__name__)


class XeAuthSession(param.Parameterized):
    keyset = certs
    
    oauth_domain = param.String(config.OAUTH_DOMAIN)
    oauth_code_path = param.String(config.OAUTH_CODE_PATH)
    oauth_token_path = param.String(config.OAUTH_TOKEN_PATH)
    
    auto_persist_session = param.Boolean(False)
    token_file = param.String(config.TOKEN_FILE)
    client_id = param.String(config.DEFAULT_CLIENT_ID) 
    scopes = param.List([])
    audience = param.String(config.DEFAULT_AUDIENCE)

    notify_email = param.String(allow_None=True)

    flow = param.ClassSelector()
    
    token = param.ClassSelector(XeToken, default=None)
    state = param.Selector(["Disconnected", "Logged in", "Awaiting token",
                            "Checking token ready", "Token expired"],
                             default="Disconnected")

    def __init__(self, **params):
        super().__init__(**params)
        if os.path.isfile(self.token_file):
            self.token = XeToken.from_file(self.token_file)
            if self.logged_in:
                self.state = "Logged in"

    def login_from_server(self):
        import panel as pn

        access_token = pn.state.access_token
        id_token = id_token_from_server_state()
        self.token = XeToken(access_token=access_token,
                             id_token=id_token,
                            )
        return self.token

    @property
    def scope(self):
        scopes = set(config.DEFAULT_SCOPE.split(" ") + self.scopes)
        return " ".join(scopes)

    def login(self, open_browser=False, print_url=False, extra_headers={}, notify_email=None):
        extra_fields = {}
        if notify_email:
            extra_fields["notify_email"] = notify_email
        if self.token:
            self.state = "Logged in"
        else:
            self.token = self.flow.perform(self.oauth_domain, self.oauth_code_path, self.oauth_token_path, 
                                            self.client_id, self.scope, self.audience, headers=extra_headers,
                                            extra_fields=extra_fields,
                                        open_browser=open_browser, print_url=print_url)
            if self.token:
                self.state = "Logged in"
        return self.token

    def persist_token(self):
        if self.token_file:
            try:
                self.token.to_file(self.token_file)
            except Exception as e:
                logger.error("Exception raised while persisted token: "+str(e))

    def logout(self):
        self.token = None
        self.state = "Disconnected"
        return True

    def request_token(self, extra_headers={}):
        
        self.flow.request_token(self.oauth_domain, self.oauth_code_path, 
                                self.client_id, self.scope, self.audience, headers=extra_headers)
        self.state = "Awaiting token"

    def token_ready(self, extra_headers={}):
        if self.token is None:
            try:
                self.token = self.flow.fetch_token(self.oauth_domain,
                                         self.oauth_token_path, headers=extra_headers)
                if self.auto_persist_session:
                    self.persist_token()
                    
                self.state = "Logged in"
                return True
            except:
                pass
        return False
    
    def refresh_tokens(self, extra_headers={}):
        self.token.refresh_tokens(self.oauth_domain, self.oauth_token_path,
                                             self.client_id, headers=extra_headers)
        if self.auto_persist_session:
            self.persist_token()

    @property
    def logged_in(self):
        if self.token is None: 
            return False
        if self.token.expired:
            return False
        return True

    @property
    def id_token(self):
        return self.token.id_token

    @property
    def access_token(self):
        return self.token.access_token

    @property
    def profile(self):
        claims = self.keyset.extract_verified_claims(self.id_token)
        return {k:v for k,v in claims.items() if k not in claims.REGISTERED_CLAIMS}
    
    @property
    def claims(self):
        claims = self.keyset.extract_verified_claims(self.access_token)
        return {k:v for k,v in claims.items() if k in claims.REGISTERED_CLAIMS}

    @property
    def extra_claims(self):
        claims = self.keyset.extract_verified_claims(self.access_token)
        return {k:v for k,v in claims.items() if k not in claims.REGISTERED_CLAIMS}

    @property
    def permissions(self):
        claims = self.keyset.extract_verified_claims(self.access_token)
        return claims.get("permissions", [])

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

    def authorize(self):
        webbrowser.open(self.flow.verification_uri_complete)
        
class NotebookSession(XeAuthSession):
    message = param.String("")
    _gui = None
    _cb = None

    @property
    def gui(self):
        if self._gui is None:
            self._gui = pn.panel(self._make_gui)
        return self._gui

    def await_token_cb(self):
        if self.token_ready() and self.token:
            self._cb.stop()
        
    def login_requested(self, event):
        try:
            self.request_token()
            logger.info("Sent request...")
            self._cb = pn.state.add_periodic_callback(self.await_token_cb,
                                                    1000*self.flow.interval,
                                                    timeout=1000*max(1, int(self.flow.expires-time.time())))
        except Exception as e:
            logging.error(e)
            print(e)

    def logged_in_gui(self):
        profile = self.profile
        details = pn.Row(
            pn.pane.PNG(profile.get("picture", config.DEFAULT_AVATAR), width=60, height=60),
            pn.widgets.TextInput(name='Name', value=profile.get("name", "Unknown"), disabled=True, height=35),
            pn.widgets.TextInput(name='Email', value=profile.get("email", "Unknown"), disabled=True, height=35),
            
            height=70
        )
        token = pn.widgets.input.TextAreaInput(name='Access token', value=self.access_token, width=700, height=100)
        
        token_props = pn.Row(
            pn.widgets.TextInput(name='Scope', value=self.token.scope, disabled=True, height=35),
            pn.widgets.DatetimeInput(disabled=True, name="Expiration date",
                         value=datetime.utcfromtimestamp(self.token.expires)),
            
            width=700,
        )
        logout = pn.widgets.Button(name="Logout", button_type='warning')
        logout.on_click(lambda event: self.logout())
        return pn.Column(
                    details,
                    token,
                    token_props,
                    logout,
                    height=300,
                    width=700)

    def awaiting_token_gui(self):
        import panel as pn

        cancel = pn.widgets.Button(name="Cancel", width=50)
        cancel.on_click(lambda event: self.logout())
        authenticate = url_link_button(self.flow.verification_uri_complete, button_type='primary', width=100)
        
        waiting_ind = pn.indicators.LoadingSpinner(value=False, width=30, height=30, align="center")
        def activate(event):
            waiting_ind.value = True
        authenticate.on_click(activate)
        return pn.Row(waiting_ind, authenticate, cancel)
    
    def token_expired_gui(self):
        import panel as pn

        refresh = pn.widgets.Button(name="Renew", align="end")
        refresh.on_click(lambda e: self.refresh_tokens())
        return refresh

    @param.depends("state")
    def _make_gui(self):
        import panel as pn

        status = pn.indicators.BooleanStatus(width=20, height=20, value=True, color="danger", align="center")
        header = pn.Row(status, f"Status: {self.state}.")
        panel = pn.Column(header)
        if self.state == "Logged in":
            status.color = "success"
            panel.append(self.logged_in_gui())

        elif self.state == "Awaiting token":
            status.color = "primary"
            panel.append(self.awaiting_token_gui())

        elif self.state == "Token expired":
            status.color = "warning"
            return pn.panel(self.token_expired_gui())

        else:
            login = pn.widgets.Button(name="Login", button_type='success', width=30)
            login.on_click(self.login_requested)
            panel.append(pn.Param(self.param, parameters=["scopes", "auto_persist_session"]))
            panel.append(login)

        return panel

    def _repr_mimebundle_(self, include=None, exclude=None):
        return self.gui._repr_mimebundle_(include=include, exclude=exclude)
