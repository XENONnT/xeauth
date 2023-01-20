def url_link_button(url, label="Authenticate", **kwargs):
    import panel as pn

    button = pn.widgets.Button(name=label, **kwargs)
    button.js_on_click(code=f"window.open('{url}')")
    return button


def id_token_from_server_state():
    import panel as pn
    from tornado.web import decode_signed_value

    id_token = pn.state.cookies.get("id_token")
    if id_token is None or pn.config.cookie_secret is None:
        return None
    id_token = decode_signed_value(pn.config.cookie_secret, "id_token", id_token)
    if pn.state.encryption is None:
        id_token = id_token
    else:
        id_token = pn.state.encryption.decrypt(id_token)
    return id_token.decode()


def new_gpg_key(name, email, passphrase="", gnu_home=None):
    import gnupg

    gpg = gnupg.GPG(gnupghome=gnu_home)

    arg = gpg.gen_key_input(
        key_type="RSA",
        key_length=2048,
        name_real=name,
        passphrase=passphrase,
        name_email=email,
    )

    key = gpg.gen_key(arg)

    if not key.status == "ok":
        raise RuntimeError("Unable to create key.")

    public_key = gpg.export_keys(key.fingerprint, False)
    return public_key
