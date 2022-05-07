# -*- coding: utf-8 -*-

# 打卡脚修改自ZJU-nCov-Hitcarder的开源代码，感谢这位同学开源的代码

import requests
import json
import re
import datetime
import time
import sys
import ddddocr


class DaKa(object):
    """Hit card class

    Attributes:
        username: (str) 浙大统一认证平台用户名（一般为学号）
        password: (str) 浙大统一认证平台密码
        login_url: (str) 登录url
        base_url: (str) 打卡首页url
        save_url: (str) 提交打卡url
        self.headers: (dir) 请求头
        sess: (requests.Session) 统一的session
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.login_url = "https://zjuam.zju.edu.cn/cas/login?service=https%3A%2F%2Fhealthreport.zju.edu.cn%2Fa_zju%2Fapi%2Fsso%2Findex%3Fredirect%3Dhttps%253A%252F%252Fhealthreport.zju.edu.cn%252Fncov%252Fwap%252Fdefault%252Findex"
        self.base_url = "https://healthreport.zju.edu.cn/ncov/wap/default/index"
        self.save_url = "https://healthreport.zju.edu.cn/ncov/wap/default/save"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"
        }
        self.sess = requests.Session()

    def login(self):
        """Login to ZJU platform"""
        res = self.sess.get(self.login_url, headers=self.headers)
        execution = re.search(
            'name="execution" value="(.*?)"', res.text).group(1)
        res = self.sess.get(
            url='https://zjuam.zju.edu.cn/cas/v2/getPubKey', headers=self.headers).json()
        n, e = res['modulus'], res['exponent']
        encrypt_password = self._rsa_encrypt(self.password, e, n)

        data = {
            'username': self.username,
            'password': encrypt_password,
            'execution': execution,
            '_eventId': 'submit'
        }
        res = self.sess.post(url=self.login_url, data=data, headers=self.headers)

        # check if login successfully
        if '统一身份认证' in res.content.decode():
            raise LoginError('登录失败，请核实账号密码重新登录')
        return self.sess

    def post(self):
        """Post the hitcard info"""
        res = self.sess.post(self.save_url, data=self.info, headers=self.headers)
        return json.loads(res.text)

    def get_date(self):
        """Get current date"""
        today = datetime.date.today()
        return "%4d%02d%02d" % (today.year, today.month, today.day)

    def getCap(self):
        captcha_url = 'https://healthreport.zju.edu.cn/ncov/wap/default/code'
        ocr = ddddocr.DdddOcr()

        # 设置 cookie
        cookie_dict = {'eai-sess': 'xxxxxxxxxxxxxxxxxxxxxxxxx'}
        self.sess.cookies = requests.cookies.cookiejar_from_dict(cookie_dict)
        # headers = {
        #     'accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        #     'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        #     'accept-encoding': 'gzip, deflate, br',
        #     'accept-language': 'zh-CN,zh;q=0.9',
        #     # 'cookies': "UUkey=d1da8dbba9615d22aada045b55dfdf80; _pm0=LqYPI/LKC2ywk/py3jWzWzgKbG7oemmzvah6t5ZyI7E=; _ga_MWF1PQPJ1G=GS1.1.1645427272.2.1.1645427361.0; _ga=GA1.3.982320635.1630220073; BSFIT_pi620=; BSFIT_mjvys=; BSFIT_h9oq/=; BSFIT_16jgo=; BSFIT_i1yu/=; BSFIT_qpkBr=; BSFIT_jAhq6=; BSFIT_nl5/D=+p9d+/kd+S+Prpk3+n,+/n0F/Ew+/Eerj; Hm_lvt_35da6f287722b1ee93d185de460f8ba2=1650181662,1650372014,1650379670,1650952508; Hm_lvt_fe30bbc1ee45421ec1679d1b8d8f8453=1651135879; BSFIT_hojBi=; sudy_ck=1217FE1E8FB488B79051BF9DBFE85E61998399B74C571D73ADB484B09400A25FAD03709E2AABA05FCDF0FFC3E93A07A9551F55B2C4400C50F2114ACC7C40DBBF434ECB043354687DDB1D364FDA9E435D; _csrf=S8mwplVi9KWoF2WQ0TlCeIyKFfa6YWb1wPo5qvZHAEw=; _pv0=k8SP5WS7AK/JtmEi0Wzprl5VZnAAbevVn5TInLzuTpoDvKoE3pbwOup+1BI0nxS1tPoSrc4btq2Hv7ZRx1YV8e+GNneORD53IOBXKiUf4JAcUfdnWEU2P1kwWfde8QOUCJPXC2abKKX+h1uyGBsQMqbtpM04l8+TR78kmYv0kmKAd8jy2VmnUl0hfpWM3WFCTbmMcUY+HdLMfLR5RAPisqAmC8KZOeM8/xsgOlFYtCj31GXoegHLa7LgdLbkysago/6e/Aijljx/ZsWP4Wy/GLufm4KGSH2PfT9RwTsWCdjcQXVyQyyu8WzP8J+624DpPvRLGqAIwK8MXjAZWFmz3q/gZqxrbhB0y0vkf+LAcYNc6gkCxZrVOZGRzbsUDOTsSolN5sWaDfSCogf1lg62thlBNZ7Fg2mDYcBL3rxnOtE=; _pf0=kzzJAap65cCVqaKJKc/JQr7vQSFDbUca0YFbdw6WYJo=; _pc0=ZhowFVGAMLPBiozd6AcL3whIqXFBtgHBjW9GakLhV6tVI4aQ+uwK5i72wHH+/vXj; iPlanetDirectoryPro=MXHuWmX2b6UqtZdPrkbjfCXRxSNhwHkPH/fGHYi4QinZWai2DW9ppE7f2OLLlhb9xPRQnLp10JQ6Mx2gG9jQ7p5ES/bB/lHTOKV3/fzAUOUtFpSSVGC+g7+XaP4mVLGIfU0P0rnqh5ZuRhwC4Wc9UvGbH/8ILb55acTwOusgJWOCgMpeJq3G4NNQyOKLvBdc5SnbBRtjKPASg5GptucfrklCyQcYC4HXGfogZtW4VjttFv/oM5cdUbMp7l74/9b2PEC51X2BJJO7i+cMb1JgQLHOMfDAPpDtDGYM6qncFsHMugR9LZs2MeUkUc4P2rD6wSFIEsrCz8N533Iygijzq4T6UScrD6ohtFmYnvmnBl0=; eai-sess=5cnlcsbgedufqs1fdf9ap01g52; Hm_lvt_48b682d4885d22a90111e46b972e3268=1649494238,1650423551,1651926860; Hm_lpvt_48b682d4885d22a90111e46b972e3268=1651927709",
        #     'referer': 'https://healthreport.zju.edu.cn/ncov/wap/default/index',
        #     'sec-ch-ua-platform': "Windows",
        #     'sec-fetch-dest': 'image',
        #     'sec-fetch-mode': "no-cors",
        #     'sec-fetch-site': 'same-origin',
        # }

        resp = self.sess.get(url=captcha_url, headers=self.headers)
        captcha = ocr.classification(resp.content)
        print(captcha)
        return captcha

    def get_info(self, html=None):
        """Get hitcard info, which is the old info with updated new time."""
        if not html:
            res = self.sess.get(self.base_url, headers=self.headers)
            html = res.content.decode()

        try:
            old_infos = re.findall(r'oldInfo: ({[^\n]+})', html)
            if len(old_infos) != 0:
                old_info = json.loads(old_infos[0])
            else:
                raise RegexMatchError("未发现缓存信息，请先至少手动成功打卡一次再运行脚本")

            new_info_tmp = json.loads(re.findall(r'def = ({[^\n]+})', html)[0])
            new_id = new_info_tmp['id']
            name = re.findall(r'realname: "([^\"]+)",', html)[0]
            number = re.findall(r"number: '([^\']+)',", html)[0]
        except IndexError:
            raise RegexMatchError('Relative info not found in html with regex')
        except json.decoder.JSONDecodeError:
            raise DecodeError('JSON decode error')

        new_info = old_info.copy()
        new_info['id'] = new_id
        new_info['name'] = name
        new_info['number'] = number
        new_info["date"] = self.get_date()
        new_info["created"] = round(time.time())
        new_info["address"] = "浙江省杭州市西湖区"
        new_info["area"] = "浙江省 杭州市 西湖区"
        new_info["province"] = new_info["area"].split(' ')[0]
        new_info["city"] = new_info["area"].split(' ')[1]
        # form change
        new_info["campus"] = "玉泉校区"
        new_info['jrdqtlqk[]'] = 0
        new_info['jrdqjcqk[]'] = 0
        new_info['sfsqhzjkk'] = 1   # 是否申领杭州健康码
        new_info['sqhzjkkys'] = 1   # 杭州健康吗颜色，1:绿色 2:红色 3:黄色
        new_info['sfqrxxss'] = 1    # 是否确认信息属实
        new_info['jcqzrq'] = ""
        new_info['gwszdd'] = ""
        new_info['szgjcs'] = ""
        new_info['verifyCode'] = self.getCap()
        self.info = new_info
        return new_info

    def _rsa_encrypt(self, password_str, e_str, M_str):
        password_bytes = bytes(password_str, 'ascii')
        password_int = int.from_bytes(password_bytes, 'big')
        e_int = int(e_str, 16)
        M_int = int(M_str, 16)
        result_int = pow(password_int, e_int, M_int)
        return hex(result_int)[2:].rjust(128, '0')


# Exceptions
class LoginError(Exception):
    """Login Exception"""
    pass


class RegexMatchError(Exception):
    """Regex Matching Exception"""
    pass


class DecodeError(Exception):
    """JSON Decode Exception"""
    pass


def main(username, password):
    """Hit card process

    Arguments:
        username: (str) 浙大统一认证平台用户名（一般为学号）
        password: (str) 浙大统一认证平台密码
    """
    print("\n[Time] %s" %
          datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print("🚌 打卡任务启动")

    dk = DaKa(username, password)

    print("登录到浙大统一身份认证平台...")
    try:
        dk.login()
        print("已登录到浙大统一身份认证平台")
    except Exception as err:
        print(str(err))
        raise Exception

    print('正在获取个人信息...')
    try:
        dk.get_info()
        print('已成功获取个人信息')
    except Exception as err:
        print('获取信息失败，请手动打卡，更多信息: ' + str(err))
        raise Exception

    print('正在为您打卡打卡打卡')
    try:
        res = dk.post()
        if str(res['e']) == '0':
            print('已为您打卡成功！')
        else:
            print(res['m'])
    except Exception:
        print('数据提交失败')
        raise Exception


if __name__ == "__main__":
    username = sys.argv[1]
    password = sys.argv[2]
    try:
        main(username, password)
    except Exception:
        exit(1)
