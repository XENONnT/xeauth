import requests
from .settings import config


def get_active_usernames():
    import utilix

    users_db = utilix.xent_collection(collection="users")

    query = {
        "active": {"$in": ["True", "true", True, 1]},
        "github": {"$nin": ["", None]},
    }

    projection = {"github": 1, "_id": 0}
    user_docs = users_db.find(query, projection)
    return [doc["github"] for doc in user_docs]


def get_group_usernames(groupname):
    import utilix

    users_db = utilix.xent_collection(collection="users")

    query = {
        "active": {"$in": ["True", "true", True, 1]},
        "github": {"$nin": ["", None]},
        "groups": groupname,
    }

    projection = {"github": 1, "groups": 1, "_id": 0}
    user_docs = users_db.find(query, projection)
    return [doc["github"] for doc in user_docs if groupname in doc["groups"]]


def get_user_keys(username, token=config.GITHUB_TOKEN, validate=True):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"

    r = requests.get(
        f"https://api.github.com/users/{username}/gpg_keys", headers=headers
    )

    if not r.ok:
        return []

    keys = r.json()
    if not isinstance(keys, list):
        return []

    if isinstance(keys, list):
        return [key for key in keys if key["can_encrypt_storage"] and key["raw_key"]]

    return []


def iter_valid_keys(token=config.GITHUB_TOKEN):
    usernames = get_active_usernames()
    for username in usernames:
        for key in get_user_keys(username, token=token):
            if not key["can_encrypt_storage"]:
                continue
            if not key["raw_key"]:
                continue
            key["username"] = username
            yield key


def get_all_valid_keys(token=config.GITHUB_TOKEN):
    keys = list(iter_valid_keys(token=token))
    return keys


def iter_valid_user_keys(token=config.GITHUB_TOKEN):
    usernames = get_active_usernames()
    for username in usernames:
        keys = get_user_keys(username, token=token)
        keys = [key for key in keys if key["can_encrypt_storage"] and key["raw_key"]]
        yield username, keys


def import_key(keydata, gnuhome=None):
    import gnupg
    gpg = gnupg.GPG(homedir=gnuhome)
    gpg.import_keys(keydata)
