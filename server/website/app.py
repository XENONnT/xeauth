import os
from flask import Flask


from flask import Flask, jsonify
from flask_bootstrap import Bootstrap

from authlib.integrations.flask_client import OAuth
from loginpass import create_flask_blueprint
from loginpass import Twitter, GitHub, Google
from flask_login import LoginManager

from .models import db
from .oauth2 import config_oauth
from .routes import bp as server_bp

backends = [Twitter, GitHub, Google]

login_manager = LoginManager()


def create_app(config=None):
    app = Flask(__name__)

    # load default configuration
    app.config.from_object("website.settings")

    # load environment configuration
    if "WEBSITE_CONF" in os.environ:
        app.config.from_envvar("WEBSITE_CONF")

    # load app sepcified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith(".py"):
            app.config.from_pyfile(config)

    #: you can customize this part

    @app.route("/login")
    def index():
        tpl = '<li><a href="/login/{}">{}</a></li>'
        lis = [tpl.format(b.NAME, b.NAME) for b in backends]
        return "<ul>{}</ul>".format("".join(lis))

    setup_app(app)

    return app


def handle_authorize(remote, token, user_info):
    return jsonify(user_info)


def setup_app(app):
    db.init_app(app)
    config_oauth(app)
    oauth = OAuth(app)
    app.register_blueprint(server_bp, url_prefix="")

    client_bp = create_flask_blueprint(backends, oauth, handle_authorize)
    app.register_blueprint(client_bp, url_prefix="")

    Bootstrap(app)

    login_manager.init_app(app)
