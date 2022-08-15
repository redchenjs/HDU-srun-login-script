import requests
import time
import re

from ._decorators import *

from .encryption.srun_md5 import *
from .encryption.srun_sha1 import *
from .encryption.srun_base64 import *
from .encryption.srun_xencode import *

timestamp = int(time.time())

header = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'
}


class LoginManager:
    def __init__(self,
                 url_login_page="https://login.hdu.edu.cn/srun_portal_pc?ac_id=0&theme=pro",
                 url_get_challenge_api="https://login.hdu.edu.cn/cgi-bin/get_challenge",
                 url_login_api="https://login.hdu.edu.cn/cgi-bin/srun_portal",
                 n="200",
                 vtype="1",
                 acid="0",
                 enc="srun_bx1"
                 ):
        # urls
        self.url_login_page = url_login_page
        self.url_get_challenge_api = url_get_challenge_api
        self.url_login_api = url_login_api

        # other static parameters
        self.n = n
        self.vtype = vtype
        self.ac_id = acid
        self.enc = enc

    def login(self, username, password):
        self.username = username
        self.password = password

        self.get_ip()
        self.get_token()
        self.get_login_responce()

    def get_ip(self):
        print("Step 1: Get local ip returned from srun server.")
        self._get_login_page()
        self._resolve_ip_from_login_page()
        print("------------------------------------------------")

    def get_token(self):
        print("Step 2: Get token by resolving challenge result.")
        self._get_challenge()
        self._resolve_token_from_challenge_response()
        print("------------------------------------------------")

    def get_login_responce(self):
        print("Step 3: Login and resolve response.")
        self._generate_encrypted_login_info()
        self._send_login_info()
        self._resolve_login_responce()
        print("The login result is: " + self._login_result)
        print("------------------------------------------------")

    def _is_defined(self, varname):
        """
        Check whether variable is defined in the object
        """
        allvars = vars(self)
        return varname in allvars

    @infomanage(
        callinfo="Getting login page",
        successinfo="Successfully get login page",
        errorinfo="Failed to get login page, maybe the login page url is not correct"
    )
    def _get_login_page(self):
        self._page_response = requests.get(self.url_login_page, headers=header)

    @checkvars(
        varlist="_page_response",
        errorinfo="Lack of login page html. Need to run '_get_login_page' in advance to get it"
    )
    @infomanage(
        callinfo="Resolving IP from login page html",
        successinfo="Successfully resolve IP",
        errorinfo="Failed to resolve IP"
    )
    def _resolve_ip_from_login_page(self):
        self.ip = re.search('ip     : "(.*?)"',
                            self._page_response.text).group(1)

    @checkip
    @infomanage(
        callinfo="Begin getting challenge",
        successinfo="Challenge response successfully received",
        errorinfo="Failed to get challenge response, maybe the url_get_challenge_api is not correct."
        "Else check params_get_challenge"
    )
    def _get_challenge(self):
        """
        The 'get_challenge' request aims to ask the server to generate a token
        """
        params_get_challenge = {
            'callback': "jQuery112409851480530977974_" + str(timestamp),
            'username': self.username,
            'ip': self.ip,
            '_': int(time.time())
        }

        self._challenge_response = requests.get(
            self.url_get_challenge_api, params=params_get_challenge, headers=header)

    @checkvars(
        varlist="_challenge_response",
        errorinfo="Lack of challenge response. Need to run '_get_challenge' in advance"
    )
    @infomanage(
        callinfo="Resolving token from challenge response",
        successinfo="Successfully resolve token",
        errorinfo="Failed to resolve token"
    )
    def _resolve_token_from_challenge_response(self):
        self.token = re.search('"challenge":"(.*?)"',
                               self._challenge_response.text).group(1)

    @checkip
    def _generate_info(self):
        info_params = {
            'username': self.username,
            'password': self.password,
            'ip': self.ip,
            'acid': self.ac_id,
            'enc_ver': self.enc
        }
        info = re.sub("'", '"', str(info_params))
        self.info = re.sub(" ", '', info)

    @checkinfo
    @checktoken
    def _encrypt_info(self):
        self.encrypted_info = "{SRBX1}" + \
            get_base64(get_xencode(self.info, self.token))

    @checktoken
    def _generate_md5(self):
        self.md5 = get_md5("", self.token)

    @checkmd5
    def _encrypt_md5(self):
        self.encrypted_md5 = "{MD5}" + self.md5

    @checktoken
    @checkip
    @checkencryptedinfo
    def _generate_chksum(self):
        self.chkstr = self.token + self.username
        self.chkstr += self.token + self.md5
        self.chkstr += self.token + self.ac_id
        self.chkstr += self.token + self.ip
        self.chkstr += self.token + self.n
        self.chkstr += self.token + self.vtype
        self.chkstr += self.token + self.encrypted_info

    @checkchkstr
    def _encrypt_chksum(self):
        self.encrypted_chkstr = get_sha1(self.chkstr)

    def _generate_encrypted_login_info(self):
        self._generate_info()
        self._encrypt_info()
        self._generate_md5()
        self._encrypt_md5()

        self._generate_chksum()
        self._encrypt_chksum()

    @checkip
    @checkencryptedmd5
    @checkencryptedinfo
    @checkencryptedchkstr
    @infomanage(
        callinfo="Begin to send login info",
        successinfo="Login info send successfully",
        errorinfo="Failed to send login info"
    )
    def _send_login_info(self):
        login_info_params = {
            'callback': "jQuery112409851480530977974_" + str(timestamp),
            'action': "login",
            'username': self.username,
            'password': self.encrypted_md5,
            'os': "Linux",
            'name': "Linux",
            'double_stack': 0,
            'chksum': self.encrypted_chkstr,
            'info': self.encrypted_info,
            'ac_id': self.ac_id,
            'ip': self.ip,
            'n': self.n,
            'type': self.vtype,
            '_': int(time.time())
        }
        self._login_responce = requests.get(
            self.url_login_api, params=login_info_params, headers=header)

    @checkvars(
        varlist="_login_responce",
        errorinfo="Need _login_responce. Run _send_login_info in advance"
    )
    @infomanage(
        callinfo="Resolving login result",
        successinfo="Login result successfully resolved",
        errorinfo="Cannot resolve login result. Maybe the srun response format is changed"
    )
    def _resolve_login_responce(self):
        self._login_result = re.search(
            '"suc_msg":"(.*?)"', self._login_responce.text).group(1)
