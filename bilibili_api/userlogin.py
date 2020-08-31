r"""
模块：userlogin
功能：进行登录操作
项目GitHub地址：https://github.com/Passkou/bilibili_api
项目主页：https://passkou.com/bilibili_api
"""
import json, time, requests, logging, os, copy
from . import utils, exceptions, common, user, Verify

API = utils.get_api()
DEFAULT_HEADERS = utils.DEFAULT_HEADERS
request_settings = utils.request_settings

logger = logging.getLogger("login")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s][%(levelname)s] %(message)s"))
logger.addHandler(handler)

def logout(verify: utils.Verify):
    """
    使用Verify登出账号
    :param verify:
    """
    api = API['userlogin']['logout']
    resp = requests.get(api["url"], cookies=verify.get_cookies())
    if(resp.status_code != 200):
        logger.error(f"登出错误，状态码:{resp.status_code}")
        return
    logger.info("登出成功，原Verify将不再可用")

def login_QR():
    """
    使用二维码登录外部API, 返回Verify
    :return:
    """
    return Login().login_QR()

class Login:
    """
    登录方法类，目前仅支持扫码
    为了保证Session连贯性重写HTTP操作
    """

    def __init__(self, debug=False):
        self.session=requests.Session()
        logger.setLevel(logging.DEBUG if debug else logging.INFO)

    def login_QR(self):
        """
        使用二维码方法登录，返回Verify
        :return:
        """
        resp = self.__QR_get_url()
        QRcode = resp['data']['url']
        oauthKey =  resp['data']['oauthKey']
        logger.info(f'请打开以下网址并扫码:\nhttps://cli.im/api/qrcode/code?text={QRcode}&mhid=tBGUXwHukskhMHYvKtVWOaw')
        try:
            self.__QR_get_info(oauthKey)
        except exceptions.LoginException as e:
            logger.error(str(e))
            return None
        cookies=self.session.cookies
        logger.debug(f'获取到Cookie:\n{cookies}')
        return Verify(sessdata = cookies['SESSDATA'], csrf = cookies['bili_jct'])

    def __QR_get_url(self):
        """
        获取二维码
        :return:
        """
        api = API['userlogin']['QRcode']['get_url']
        return self.get(api['url'])

    def __QR_get_info(self, oauthKey: str):
        """
        获取扫码状态
        :param oauthKey: 使用__QR_get_url获得
        :return:
        """
        api = API['userlogin']['QRcode']['get_info']
        while True:
            resp = self.post(url=api['url'], data={'oauthKey': oauthKey})
            if(resp['status']):
                logger.info("登录成功")
                return resp['data']
            if(resp['data'] == -1): raise exceptions.LoginException(-1, "oauthKey密钥错误")
            if(resp['data'] == -2): raise exceptions.LoginException(-2, "扫码超时")
            if(resp['data'] == -4): logger.debug("未扫描")
            elif(resp['data'] == -5): logger.debug("扫描成功，未确认")
            time.sleep(3) # 必要，不然会被B站风控（血的教训）

    def request(self, method: str, url: str, params=None, data=None, cookies=None, headers=None, **kwargs):
        """
        由于登录请求包的特殊性，专用HTTP请求
        :param method:
        :param url:
        :param params:
        :param data:
        :param cookies:
        :param headers:
        :param kwargs:
        :return:
        """
        if params is None:
            params = {}
        if data is None:
            data = {}
        if cookies is None:
            cookies = {}
        if headers is None:
            headers = copy.deepcopy(DEFAULT_HEADERS)
        st = {
            "url": url,
            "params": params,
            "cookies": cookies,
            "headers": headers,
            "verify": request_settings["use_https"],
            "data": data,
            "proxies": request_settings["proxies"]
        }
        st.update(kwargs)

        req = self.session.request(method, **st)

        if req.ok:
            content = req.content.decode("utf8")
            if req.headers.get("content-length") == 0:
                return None
            if 'jsonp' in params and 'callback' in params:
                con = json.loads(re.match(".*?({.*}).*", content, re.S).group(1))
            else:
                con = json.loads(content)
            if 'code' in con and con["code"] != 0:
                if "message" in con:
                    msg = con["message"]
                elif "msg" in con:
                    msg = con["msg"]
                else:
                    msg = "请求失败，服务器未返回失败原因"
                raise exceptions.BilibiliException(con["code"], msg)
            return con
        else:
            raise exceptions.NetworkException(req.status_code)


    def get(self, url, params=None, cookies=None, headers=None, **kwargs):
        """
        由于登录请求包的特殊性，专用GET请求
        :param url:
        :param params:
        :param cookies:
        :param headers:
        :param kwargs:
        :return:
        """
        resp = self.request("GET", url=url, params=params, cookies=cookies, headers=headers, **kwargs)
        return resp


    def post(self, url, cookies=None, data=None, headers=None, **kwargs):
        """
        由于登录请求包的特殊性，专用POST请求
        :param url:
        :param cookies:
        :param data:
        :param headers:
        :param kwargs:
        :return:
        """
        resp = self.request("POST", url=url, data=data, cookies=cookies, headers=headers, **kwargs)
        return resp