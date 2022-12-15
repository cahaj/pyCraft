import requests
import json
import uuid
import re
from .exceptions import YggdrasilError

#: The base url for Ygdrassil requests
AUTH_SERVER = "https://authserver.mojang.com"
SESSION_SERVER = "https://sessionserver.mojang.com/session/minecraft"
# Need this content type, or authserver will complain
CONTENT_TYPE = "application/json"
HEADERS = {"content-type": CONTENT_TYPE}
#Other urls
PROFILE_INFO = "https://api.minecraftservices.com/minecraft/profile"


class Profile(object):
    """
    Container class for a MineCraft Selected profile.
    See: `<http://wiki.vg/Authentication>`_
    """
    def __init__(self, id_=None, name=None):
        self.id_ = id_
        self.name = name

    def to_dict(self):
        """
        Returns ``self`` in dictionary-form, which can be serialized by json.
        """
        if self:
            return {"id": self.id_,
                    "name": self.name}
        else:
            raise AttributeError("Profile is not yet populated.")

    def __bool__(self):
        bool_state = self.id_ is not None and self.name is not None
        return bool_state

    # Python 2 support
    def __nonzero__(self):
        return self.__bool__()


class AuthenticationToken(object):
    """
    Represents an authentication token.

    See http://wiki.vg/Authentication.
    """
    AGENT_NAME = "Minecraft"
    AGENT_VERSION = 1

    def __init__(self, username=None, email=None, password=None, access_token=None, client_token=None):
        """
        Constructs an `AuthenticationToken` based on `access_token` and
        `client_token`.

        Parameters:
            access_token - An `str` object containing the `access_token`.
            client_token - An `str` object containing the `client_token`, useless as MSA takes no client_token parameter.

        Returns:
            A `AuthenticationToken` with `access_token` and `client_token` set.
        """
        self.username = username
        self.email = email
        self.password = password
        self.access_token = access_token
        self.client_token = client_token
        self.profile = Profile()

    @property
    def authenticated(self):
        """
        Attribute which is ``True`` when the token is authenticated and
        ``False`` when it isn't.
        """
        if not self.username:
            return False

        if not self.access_token:
            return False


        if not self.profile:
            return False

        return True

    def authenticate(self, email, password):
        """
        Authenticates the user against MSA using
        `email` and `password` parameters.

        Parameters:
            email - An `str` object with the email
            password - An `str` object with the password.

        Returns:
            Returns `True` if successful.
            Otherwise it will raise an exception.

        Raises:
            minecraft.exceptions.YggdrasilError
        """
        self.password = password
        self.email = email

        msa = MSAuth(email=self.email, password=self.password)
        res = msa.login()

        _raise_from_response(res)

        json_resp = res.json()

        self.access_token = json_resp["access_token"]
        
        getprofile = _get_profile(access_token=self.access_token)
        profile = getprofile.json()

        self.username = profile["name"]
        self.client_token = None
        self.profile.id_ = profile["id"]
        self.profile.name = profile["name"]

        return True

    def refresh(self):
        """
        Acts the same as `AuthenticationToken.authenticate()`

        `AuthenticationToken.email` and `AuthenticationToken.password` must be set!

        Returns:
            Returns `True` if successful.
            Otherwise it will raise an exception.

        Raises:
            minecraft.exceptions.YggdrasilError
        """
        if self.email is None:
            raise ValueError("'email' not set!'")

        if self.password is None:
            raise ValueError("'password' is not set!")

        msa = MSAuth(email=self.email, password=self.password)
        res = msa.login()

        _raise_from_response(res)

        json_resp = res.json()

        self.access_token = json_resp["access_token"]
        
        getprofile = _get_profile(access_token=self.access_token)
        profile = getprofile.json()

        self.username = profile["name"]
        self.client_token = None
        self.profile.id_ = profile["id"]
        self.profile.name = profile["name"]

        return True

    def validate(self):
        """
        Validates the AuthenticationToken.

        `AuthenticationToken.access_token` must be set!

        Returns:
            Returns `True` if `AuthenticationToken` is valid.
            Otherwise returns `requests.Request` json body
        """
        if self.access_token is None:
            raise ValueError("'access_token' not set!")

        res = _get_profile(access_token=self.access_token)

        if res.status_code == 200:
            return True
        else:
            return res.json()

    @staticmethod
    def sign_out(username, password):
        """
        MSA has no sign out option.

        Returns:
            Always returns `True`.
        """

        return True

    def invalidate(self):
        """
        MSA has no sign out option.

        Returns:
            Always returns `True`.

        """

        return True

    def join(self, server_id):
        """
        Informs the Mojang session-server that we're joining the
        MineCraft server with id ``server_id``.

        Parameters:
            server_id - ``str`` with the server id

        Returns:
            ``True`` if no errors occured

        Raises:
            :class:`minecraft.exceptions.YggdrasilError`

        """
        if not self.authenticated:
            err = "AuthenticationToken hasn't been authenticated yet!"
            raise YggdrasilError(err)

        res = _make_request(SESSION_SERVER, "join",
                            {"accessToken": self.access_token,
                             "selectedProfile": self.profile.to_dict(),
                             "serverId": server_id})

        if res.status_code != 204:
            _raise_from_response(res)
        return True


def _make_request(server, endpoint, data):
    """
    Fires a POST with json-packed data to the given endpoint and returns
    response.

    Parameters:
        endpoint - An `str` object with the endpoint, e.g. "authenticate"
        data - A `dict` containing the payload data.

    Returns:
        A `requests.Request` object.
    """
    res = requests.post(server + "/" + endpoint, data=json.dumps(data),
                        headers=HEADERS, timeout=15)
    return res


def _raise_from_response(res):
    """
    Raises an appropriate `YggdrasilError` based on the `status_code` and
    `json` of a `requests.Request` object.
    """
    if res.status_code == requests.codes['ok']:
        return None

    exception = YggdrasilError()
    exception.status_code = res.status_code

    try:
        json_resp = res.json()
        if not ("error" in json_resp and "errorMessage" in json_resp):
            raise ValueError
    except ValueError:
        message = "[{status_code}] Malformed error message: '{response_text}'"
        message = message.format(status_code=str(res.status_code),
                                 response_text=res.text)
        exception.args = (message,)
    else:
        message = "[{status_code}] {error}: '{error_message}'"
        message = message.format(status_code=str(res.status_code),
                                 error=json_resp["error"],
                                 error_message=json_resp["errorMessage"])
        exception.args = (message,)
        exception.yggdrasil_error = json_resp["error"]
        exception.yggdrasil_message = json_resp["errorMessage"]
        exception.yggdrasil_cause = json_resp.get("cause")

    raise exception

def _get_profile(access_token: str):
    """
    GET -> https://api.minecraftservices.com/minecraft/profile

    Parameters:
        endpoint - An `str` object with the endpoint, e.g. "authenticate"
        data - A `dict` containing the payload data.

    Returns:
        A `requests.Request` object.
    """
    auth = "Bearer %s" % access_token
    headers = {"content-type": CONTENT_TYPE, "Authorization": auth}
    res = requests.get(url=PROFILE_INFO, headers=headers)

    return res

class MSAuth():
    def __init__(self, email: str, password: str) -> None:
        self.email = email
        self.password = password
        self.s = requests.Session()

    def oauth2(self):
        params = {
            "client_id": "000000004C12AE6F",
            "redirect_uri": "https://login.live.com/oauth20_desktop.srf",
            "scope": "service::user.auth.xboxlive.com::MBI_SSL",
            "display": "touch",
            "response_type": "token",
            "locale": "en",
        }

        resp = self.s.get("https://login.live.com/oauth20_authorize.srf", params=params)
        # Parses the values via regex since the HTML can't be parsed
        value = re.search(r'value="(.+?)"', resp.text)[0].replace('value="', "")[:-1]
        url = re.search(r"urlPost:'(.+?)'", resp.text)[0].replace("urlPost:'", "")[:-1]

        return [value, url]

    def microsoft(self, value, url):
        headers = {"Content-Type": "application/x-www-form-urlencoded"
        }

        payload = {
                    "login": self.email,
                    "loginfmt": self.email,
                    "passwd": self.password,
                    "PPFT": value,
                }

        resp = self.s.post(url, data=payload, headers=headers, allow_redirects=True)
        if "access_token" not in resp.url:
            print("Login fail")
            print(resp.url)
            if b"Sign in to" in resp.content:
                print("Sign in to")
            if b"Help us" in resp.content:
                print("Help us")

        raw_login_data = resp.url.split("#")[1]
        login_data = dict(item.split("=") for item in raw_login_data.split("&")) # create a dictionary of the parameters
        login_data["access_token"] = requests.utils.unquote(login_data["access_token"]) # URL decode the access token
        login_data["refresh_token"] = requests.utils.unquote(login_data["refresh_token"]) # URL decode the refresh token
        return login_data

    def xboxlive(self, access_token):
        json_data = {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": access_token,
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
        }

        resp = self.s.post("https://user.auth.xboxlive.com/user/authenticate", json=json_data)

        xbl_token = resp.json()["Token"]
        user_hash = resp.json()["DisplayClaims"]["xui"][0]["uhs"]
        return [xbl_token, user_hash]

    def xsts(self, xbl_token):
        payload = {
            "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT",
        }

        resp = self.s.post("https://xsts.auth.xboxlive.com/xsts/authorize", json=payload)

        return resp.json()["Token"]

    def minecraft(self, user_hash, xsts_token):
        payload = {
            "identityToken": f"XBL3.0 x={user_hash};{xsts_token}",
            "ensureLegacyEnabled": True,
        }

        resp = self.s.post("https://api.minecraftservices.com/authentication/login_with_xbox", json=payload)

        return resp

    def login(self):
        value, url = self.oauth2()
        login_data = self.microsoft(value, url)
        access_token = login_data["access_token"]
        xbl_token, user_hash = self.xboxlive(access_token)
        xsts_token = self.xsts(xbl_token)
        res = self.minecraft(user_hash, xsts_token)

        return res

