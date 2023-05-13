import param
import json
import os
import getpass
from appdirs import AppDirs
import unittest


DIRS = AppDirs("xeauth", "xenon")
CACHE_DIR = DIRS.user_cache_dir
if not os.path.isdir(CACHE_DIR):
    os.mkdir(CACHE_DIR)
DEFAULT_TOKEN_FILE = os.path.join(CACHE_DIR, f"{getpass.getuser()}_xetoken.json")


class EnvConfigurable(param.Parameterized):
    """
    A class that can be used to configure its parameters from the environment.
    """

    @classmethod
    def from_env(cls, prefix="", **overrides):
        params = {}
        for name in cls.param.params():
            env_name = "_".join([prefix.upper() + name.upper()])
            val = os.getenv(env_name, None)
            if val:
                try:
                    val = json.loads(val)
                except Exception as e:
                    pass
                params[name] = val

        params.update(overrides)
        return cls(**params)


class Config(EnvConfigurable):

    DEFAULT_CLIENT_ID = param.String(default="4a7b1485afcfcfa45271")
    MONGO_URI = param.String(default="mongodb://localhost:27017")
    MONGO_USER = param.String(default="")
    MONGO_PASSWORD = param.String(default="")
    DEBUG = param.Boolean(default=False)
    MAX_LOG_SIZE = 20
    MAX_MESSAGES = 3
    META_FIELDS = ["_version", "_latest_version", "_etag", "_created"]
    GUI_WIDTH = 600
    DEFAULT_AVATAR = (
        "http://www.sibberhuuske.nl/wp-content/uploads/2016/10/default-avatar.png"
    )
    TOKEN_FILE = param.String(default=DEFAULT_TOKEN_FILE)
    GITHUB_TOKEN = param.String(default="")
    
    def mongo_collection(self, collection_name, database='xenonnt'):
        try:
            from utilix import xent_collection
            return xent_collection(collection_name, database=database)
        except:
            from pymongo import MongoClient
            client = MongoClient(self.MONGO_URI)
            db = client[database]
            if self.MONGO_USER and self.MONGO_PASSWORD:
                db.authenticate(self.MONGO_USER, self.MONGO_PASSWORD)
            return db[collection_name]

config = Config.from_env(prefix="XEAUTH")
