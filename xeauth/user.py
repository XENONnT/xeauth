
import param

from .settings import config


class XenonUser(param.Parameterized):
    """
    XenonUser is a class that represents a user of the Xenon platform.
    """
    
    username = param.String(doc="The Xenon username of the user.")
    email = param.String(doc="The email address of the user.")
    name = param.String(doc="The full name of the user.", default=None)
    github = param.String(doc="The Github username of the user.", default=None)
    cell = param.String(doc="The cell phone number of the user.", default=None)
    groups = param.List(doc="The groups the user is a member of.", default=[])
    institute = param.String(doc="The institute the user belongs to.", default=None)
    picture_url = param.String(doc="The URL of the user's picture.",  default=None)
    lngs_ldap_email = param.String(doc="The email address of the user.", default=None)
    lngs_ldap_cn = param.String(doc="The common name of the user.", default=None)
    lngs_ldap_uid = param.String(doc="The UID of the user.", default=None)
    active = param.Boolean(doc="Whether the user is active.", default=None)
    first_name = param.String(doc="The first name of the user.", default=None)
    last_name = param.String(doc="The last name of the user.", default=None)


    @classmethod
    def from_github_username(cls, username):
        """
        Creates a XenonUser from a Github username.

        Args:
            username (str): The Github username.

        Returns:
            XenonUser: The XenonUser.
        """
        

        users_db = config.mongo_collection('users')
    
        data = users_db.find_one({'github': username})
        if data is None:
            raise ValueError(f'User {username} not found in Xenon database.')
        if not data.get('name'):
            data['name'] = data.get('first_name', '') + ' ' + data.get('last_name', '')
        data['active'] = data.get('active', False) in [True, 'True', 'true']
        data = {k: v for k,v in data.items() if k in cls.param.params()}
        return cls(**data)
