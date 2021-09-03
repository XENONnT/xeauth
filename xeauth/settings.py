import param
import json
import os
import getpass
from appdirs import AppDirs


DIRS = AppDirs("xeauth", "XENON")
CACHE_DIR = DIRS.user_cache_dir
if not os.path.isdir(CACHE_DIR):
    os.mkdir(CACHE_DIR)
DEFAULT_TOKEN_FILE = os.path.join(CACHE_DIR, f"{getpass.getuser()}_xetoken.json")
 

class ConfigParameter(param.Parameter):

    __slots__ = ["env_prefix", "klass"]

    def __init__(self, klass, env_prefix="", **kwargs):
        super().__init__(**kwargs)
        self.env_prefix = env_prefix
        self.klass = klass
       
    def _set_names(self, attrib_name):
        env_name = attrib_name.upper()
        env_name = self.env_prefix.upper() + "_" + env_name
        if os.getenv(env_name, ""):
            env = os.getenv(env_name, "")
            try:
                env = json.loads(env)
            except Exception as e:
                pass
            self.default = self.klass(env)
        super()._set_names(attrib_name)
        

class Config(param.Parameterized):
    OAUTH_DOMAIN = ConfigParameter(str, env_prefix="xeauth", default="https://xenon-experiment.eu.auth0.com/oauth")
    OAUTH_CODE_PATH = ConfigParameter(str, env_prefix="xeauth", default="/device/code")
    OAUTH_TOKEN_PATH = ConfigParameter(str, env_prefix="xeauth", default="/token")
    OAUTH_CERT_PATH = ConfigParameter(str, env_prefix="xeauth", default="/.well-known/jwks.json")
    AUTH0_SUBDOMAIN = ConfigParameter(str, env_prefix="xeauth", default="xenon-experiment.eu")
    DEFAULT_CLIENT_ID = ConfigParameter(str, env_prefix="xeauth", default="EC3adX50KdNHQuEmib30GCRDTFDibMK7")
    DEFAULT_AUDIENCE = ConfigParameter(str, env_prefix="xeauth", default="https://users.xenonnt.org")
    DEFAULT_SCOPE = ConfigParameter(str, env_prefix="xeauth", default="openid profile email offline_access")
    DEBUG = ConfigParameter(bool, env_prefix="xeauth", default=False)
    MAX_LOG_SIZE = 20
    MAX_MESSAGES = 3
    META_FIELDS = ["_version", "_latest_version", "_etag", "_created"]
    GUI_WIDTH = 600
    DEFAULT_AVATAR = "http://www.sibberhuuske.nl/wp-content/uploads/2016/10/default-avatar.png"
    TOKEN_FILE = ConfigParameter(str, env_prefix="xeauth", default=DEFAULT_TOKEN_FILE)

config = Config()
