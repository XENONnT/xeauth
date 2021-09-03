import panel as pn
from tornado.web import decode_signed_value


def url_link_button(url, label="Authenticate", **kwargs):
    button = pn.widgets.Button(name=label, **kwargs)
    button.js_on_click(code=f"window.open('{url}')")
    return button


def id_token_from_server_state():
    id_token = pn.state.cookies.get('id_token')
    if id_token is None or pn.config.cookie_secret is None:
        return None
    id_token = decode_signed_value(pn.config.cookie_secret, 'id_token', id_token)
    if pn.state.encryption is None:
        id_token = id_token
    else:
        id_token = pn.state.encryption.decrypt(id_token)
    return id_token.decode()