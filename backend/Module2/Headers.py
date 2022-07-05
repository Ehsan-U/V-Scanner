import ast
import importlib
import subprocess
import requests_html
import requests
from rich.console import Console
# install()
r = Console()
from . import wpdetect
from urllib.parse import urlparse


import logging
# ################logging#############
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# formatter = logging.Formatter("%(name)s %(levelname)s %(funcName)s %(message)s")
# handler = logging.FileHandler("/home/ubuntu/FYP/logs/Headers.log",mode="w")
# handler.setFormatter(formatter)
# logger.addHandler(handler)
###################################

class Header_Manipulation():

    def __init__(self,url):
        # self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
        self.user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36'
        self.url = urlparse(url).scheme+"://"+urlparse(url).netloc
        self.retry = 0
        self.headers_info = {"Raw-Headers":"","Security-Headers":{},"Server":[False],"Technology":[False],"Framework":[False],"Cookies":{'trans_https':False,'httponly':False,'samesite':False,"cookies":False}}

    def check_headers(self):
        session = requests_html.HTMLSession()
        security_headers = ['X-Frame-Options','Content-Security-Policy','Strict-Transport-Security','X-Content-Type-Options','X-XSS-Protection']
        try:
            resp = session.get(self.url, headers={'User-Agent': self.user_agent}, timeout=2, allow_redirects=True)
        except:
            r.print_exception()
            # logger.exception("Error in check_headers (Headers)")
            if self.retry <3:
                self.retry+=1
                self.check_headers()
            else:
                r.print("Headers Cant be extracted! timeout")
                # logger.info("Headers cant be extracted! timeout (Headers)")
                return None
        else:
            #r.print(resp.status_code)
            if resp.status_code == 200:
                site_headers = resp.headers.keys()
                # will check raw & security headers
                self.headers_info["Raw-Headers"] = dict(resp.headers)
                for header in security_headers:
                    # if X-XSS value is 0 ,means disable hy
                    if header == "X-XSS-Protection":
                        if header.lower() not in [sh.lower() for sh in site_headers]:
                            self.headers_info['Security-Headers'][header] = False
                        else:
                            value = resp.headers.get(header)
                            # print('\n\n\n',value)
                            if "0" in str(value):
                                self.headers_info['Security-Headers'][header] = False
                            else:
                                self.headers_info['Security-Headers'][header] = True
                    else:
                        if header.lower() not in [sh.lower() for sh in site_headers]:
                            self.headers_info['Security-Headers'][header] = False
                        else:
                            self.headers_info['Security-Headers'][header] = True
                self.check_meta()
                if "Set-Cookie".lower() in [sh.lower() for sh in site_headers]:
                    try:
                        self.check_cookies(resp)
                    except:
                        r.print_exception()
                        # logger.exception("Error in check_cookies()  (Headers)")
                        # r.print("error in check_headers")
                # r.save_html("/home/lubuntu/FYP/logs/headers_logs.html")
                return self.senstive_info(resp)
            else:
                # r.save_html("/home/lubuntu/FYP/logs/headers_logs.html")
                return self.headers_info


    def check_cookies(self,resp):
        secures = ['httponly','samesite','secure']
        try:
            cookie = resp.headers.get("Set-Cookie")
        except:
            r.print_exception()
            # logger.exception("Set-cookie missing check_cookies() (Headers)")
        else:
            self.headers_info['Cookies']['cookies'] = True
            if secures[2] in cookie.lower():
                # indicate that site is https
                self.headers_info['Cookies']['trans_https'] = True
            if secures[0] in cookie.lower():
                self.headers_info['Cookies']['httponly'] = True
            if secures[1] in cookie.lower():
                if "samesite=none" in cookie.lower():
                    self.headers_info['Cookies']['samesite'] = True
                elif "samesite=lax" in cookie.lower():
                    self.headers_info['Cookies']['samesite'] = True
                elif "samesite=strict" in cookie.lower():
                    self.headers_info['Cookies']['samesite'] = True

    # find used technology
    def find_technology(self,resp,tech_used,site_headers):
        self.headers_info["Technology"][0] = True
        if tech_used == "ASP.NETcookies":
            self.headers_info["Technology"].append("ASP.NET")
        elif tech_used == "JSESSIONIDcookies":
            self.headers_info["Technology"].append("Java Servlet (J2EE)")
        elif tech_used == "ci_sessioncookies":
            self.headers_info["Technology"].append("Codeignitor (PHP Framework)")
        else:
            self.headers_info["Technology"].append(resp.headers.get(tech_used))
        self.headers_info["Technology"].append("The server is leaking the senstive information about technology used")
        # if technology is ASP then we are trying to figure out its version info
        try:
            tech_used = resp.headers.get(tech_used)
            if tech_used.lower() == "ASP.NET".lower():
                asp_version = "X-AspNet-Version"
                if asp_version.lower() in site_headers:
                    try:
                        # ASP.NET 4.0
                        self.headers_info["Technology"][1] = self.headers_info["Technology"][1]+" "+resp.headers.get(asp_version)
                    except:
                        r.print_exception()
                        # logger.exception("Error in find_technology() (Headers)")
        # it runs when 'ASP.NETcookies'
        # we are sure about tech that it is ASP.NET
        except:
            asp_version = "X-AspNet-Version"
            if asp_version.lower() in site_headers:
                try:
                    self.headers_info["Technology"][1] = self.headers_info["Technology"][1]+" "+resp.headers.get(asp_version)
                except:
                    r.print_exception()
                    print("error in find_technology")
                    # logger.exception("Error in technology() (Headers)")

    # check for senstive data exposure
    def senstive_info(self,resp):
        site_headers = [header.lower() for header in resp.headers.keys()]
        tech_used = "X-Powered-By"
        try:
            cookie = resp.headers.get("Set-Cookie").lower()
        except:
            cookie = None
        # checking technology via x-powered header
        if tech_used.lower() in site_headers:
            try:
                self.find_technology(resp,tech_used,site_headers)
            except:
                r.print_exception()
                # logger.exception('Error in senstive_info() (Headers)')
        # checking technology via cookies
        elif cookie:
            asp_tech = "ASP.NET"
            java_tech = "JSESSIONID"
            php_tech = "ci_session"
            if asp_tech.lower() in cookie:
                self.find_technology(resp,asp_tech+"cookies",site_headers)
            elif java_tech.lower() in cookie:
                self.find_technology(resp,java_tech+"cookies",site_headers)
            elif php_tech.lower() in cookie:
                self.find_technology(resp,php_tech+"cookies",site_headers)

        # checking server via Server header
        try:
            server = "Server"
            if server.lower() in site_headers:
                self.headers_info["Server"][0] = True
                self.headers_info["Server"].append(resp.headers.get(server))
                self.headers_info["Server"].append("The server is leaking the senstive information about itself")
            else:
                pass
        except:
            r.print_exception()
            print("error in senstive_info")
            # logger.exception("Error in senstive_info() (Headers)")
        # checking framework via X-Generator header
        try:
            x_g = "X-Generator"
            if x_g.lower() in site_headers:
                self.headers_info["Framework"][0] = True
                self.headers_info["Framework"].append(resp.headers.get(x_g))
                self.headers_info["Framework"].append("The server is leaking the senstive information about technology")
        except:
            r.print_exception()
            print("error in senstive_info")
            # logger.exception("Error in senstive_info() (Headers)")
        # checking for wordpress existence
        if not self.headers_info["Technology"][0]:
            if wpdetect.wp_check(self.url):
                self.headers_info["Technology"][0] = True
                self.headers_info["Technology"].append("Wordpress")
                self.headers_info["Technology"].append("The server is leaking the senstive information about technology")
        outputt = subprocess.check_output(['python3', 'builtw.py', '-u', f'{self.url}', '-a', f'{self.user_agent}'],shell=False)
        site_data = ast.literal_eval(outputt.decode("utf-8"))
        if bool(site_data):
            print('FLAG TRUE')
            if not self.headers_info["Technology"][0]:
                try:
                    # return None if not found
                    tech = site_data.get("web-frameworks")
                    if tech:
                        self.headers_info["Technology"][0] = True
                        self.headers_info["Technology"].append(tech[0])
                        self.headers_info["Technology"].append("The server is leaking the senstive information about technology")
                except:
                    r.print_exception()
                    print("error in senstive_info")
                    # logger.exception("Error in senstive_info() (Headers)")
            if not self.headers_info["Framework"][0]:
                try:
                    # return None if not found
                    frameworks = site_data.get("javascript-frameworks")
                    if frameworks:
                        self.headers_info["Framework"][0] = True
                        self.headers_info["Framework"].append(frameworks[0])
                        self.headers_info["Framework"].append("The server is leaking the senstive information about technology")
                except:
                    r.print_exception()
                    print("error in senstive_info")
                    # logger.exception("Error in senstive_info() (Headers)")
            if not self.headers_info["Server"][0]:
                try:
                    # return None if not found
                    server = site_data.get("web-servers")
                    if server:
                        self.headers_info["Server"][0] = True
                        self.headers_info["Server"].append(server[0])
                        self.headers_info["Server"].append("The server is leaking the senstive information about itself")
                except:
                    r.print_exception()
                    print("error in senstive_info")
                    # logger.exception("Error in senstive_info() (Headers)")

        
        return self.headers_info

    # checking csp in meta tags
    def check_meta(self):
        # print("\nchecking meta tags")
        csp = 'http-equiv="Content-Security-Policy"'
        security_headers = self.headers_info['Security-Headers']
        for head,val in security_headers.items():
            if head == "Content-Security-Policy" and val == False:
                try:
                    resp = requests.get(self.url,timeout=2,headers={'User-Agent':self.user_agent}).text
                except:
                    pass
                else:
                    if csp.lower() in resp.lower():
                        self.headers_info['Content-Security-Policy'] = True

# c = Header_Manipulation('http://www.vivendi.com/en/')
# header_info = c.check_headers()


"""senstive info exposure"""
# X-Powered-By
# cookies
# Server': 'Microsoft-IIS/8.5'
# 'Set-Cookie': 'ASP.NET_SessionId=wikwoxzuoipxpsn0uzlxh10e; path=/; HttpOnly; SameSite=Lax',
# 'X-AspNet-Version': '4.0.30319'
# 'X-Powered-By': 'ASP.NET'
# X-Generator  (framework,CMS)
# JSESSIONID (JAVA, servlet)
# ci_session (codeignitor,php framework)
# detect wordpress or not

#requests.exceptions.SSLError
