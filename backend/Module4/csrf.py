from cmath import pi
import hashlib
from requests_html import HTMLSession
from rich.console import Console
from scrapy.selector import Selector
from urllib.parse import urlparse,urljoin
from . import tokens

import logging
###############logging##############
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# formatter = logging.Formatter("%(name)s %(levelname)s %(funcName)s %(message)s")
# handler = logging.FileHandler("/home/ubuntu/FYP/logs/csrf.log",mode='w')
# handler.setFormatter(formatter)
# logger.addHandler(handler)
####################################

class CSRF():
    def __init__(self):
        self.con = Console()

    def check_csrf(self,forms_d,vulnerabilities,headers_info,depth):
        # print("\rCSRF starting",end="")
        self.vulnerabilities = vulnerabilities
        # if samesite not present in cookies then check csrf-token
        if not headers_info.get("Cookies").get("samesite"):
            forms_d = self.decide_limits(forms_d,depth)
            forms = forms_d.get("forms")
            links = forms_d.get("links")
            for form,url in zip(forms,links):
                flag = False
                inp_name = []
                # self.con.print(form.attrib.get("method").lower())
                if form.attrib.get("method",'GET').lower() == "get":
                    try:
                        for input in form.xpath(".//input"):
                            if input.attrib.get("type") == "hidden":
                                inp_name.append(input.attrib.get("name",'').lower())
                        for token in tokens.csrf_token_names:
                            if token.lower() in inp_name:
                                # token value must be greater than 5
                                self.con.print(f"[green][bold]CSRF Token Present")
                                # logger.info("CSRF Token present")
                                # mean csrf attack not possible       
                                flag = True
                                break
                    except:
                        self.con.print_exception()
                        # logger.exception("Error in check_csrf()")
                        continue
                    else:
                        if not flag:
                            # mean csrf exist
                            self.vulnerabilities.get("CSRF")["status"] = True
                            self.con.print(f"[bold green][+] CSRF Discovered {url}")
                            # logger.info(f"CSRF found {url}")
                            self.vulnerabilities.get("CSRF")['f-links'].append(url)
        else:
            pass
        

    def decide_limits(self,forms_d,depth):
        if depth:
            if forms_d != None and len(forms_d.get("forms")) > 0:
                links = forms_d.get("links")[:100]
                forms = forms_d.get("forms")[:100]
                # self.r.print("forms leng",len(forms))
                return {"forms":forms,'links':links}
        else:
            if forms_d != None and len(forms_d.get("forms")) > 0:
                links = forms_d.get("links")[:50]
                forms = forms_d.get("forms")[:50]
                return {"forms":forms,'links':links}

# con = Console()
# c = CSRF()
# s = HTMLSession()
# resp = s.get("")
# con.print(resp.headers)
# sel = Selector(text=resp.text)
# form = sel.xpath("//form")
# c.check_csrf(None,s,form)
