from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin,
)
from authlib.oauth2.rfc8628 import DeviceCredentialMixin
from flask_login import UserMixin
from datetime import datetime


db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)

    def __str__(self):
        return self.username

    def get_user_id(self):
        return self.id


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = "oauth2_client"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_code"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = "oauth2_token"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")


class DeviceCredential(db.Model, DeviceCredentialMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_code = db.Column(db.String(5), unique=True)
    device_code = db.Column(db.String(40))
    client_id = db.Column(db.String(40))
    scope = db.Column(db.String(800))
    verification_uri = db.Column(db.String(800))
    verification_uri_complete = db.Column(db.String(800))
    expires_in = db.Column(db.Integer)
    interval = db.Column(db.Integer)
    expiry_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_user_code(self):
        return self.user_code

    def is_expired(self):
        return datetime.utcnow() > self.expiry_date
