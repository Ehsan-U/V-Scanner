from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import datetime as dt
import os
import socket
from urllib.parse import urlparse # stream implementation
from django.http import HttpResponse
from django.template.loader import get_template
import jinja2
import matplotlib
import matplotlib.pyplot as plt
import time
import pytz
# grequests is the reason of System error or too many files
from Module2.Headers import Header_Manipulation
from rich.console import Console
from requests.exceptions import ConnectionError
import json
import threading
from Main_Crawler import FYP_Crawler
from Module1.xss import Xss
from Module3.sqli import SQLi
from Module4.csrf import CSRF
from Module5.PortScanner import PortScanner
import copy
import re
from requests_html import HTMLSession
from weasyprint import HTML
from sklearn.metrics import accuracy_score
from flask import Flask, jsonify,request
from fastapi import FastAPI
from pydantic import BaseModel

class Controller():
    def __init__(self):
        self.responses = []
        self.jquery_data = {}

    def chk_headers(self,url):
        checker = Header_Manipulation(url)
        return checker.check_headers()

    def main(self,url,depth,start_time,start_counter):
        crawl = FYP_Crawler(url,depth)
        headers_info = self.chk_headers(url)
        xs = Xss()
        sqli = SQLi()
        csrf = CSRF()
        p_scan = PortScanner(url)
        lock = threading.Lock()
        try:
            # print("\r[+] Crawling",end="")
            crawl.manage_req(lock)
            # headers manipulation *returns missing security headers
            vulnerabilities = crawl.vulnerabilities
            crawled_links = len(crawl.urls.get("urls"))
            urls = list(crawl.urls.get("urls"))[:50]
            param_urls = list(crawl.param_links.get("param_urls"))
            forms_d = crawl.forms
            # xss,sqli links
            if len(param_urls) > 0:
                print("Checking Links")
                # logger.info("Checking Links")
                # asyncio.run(xs.main(param_urls,None,vulnerabilities,depth,headers_info))
                xs.main(param_urls,None,vulnerabilities,depth,headers_info,lock)
                vulnerabilities = xs.vulnerabilities
                # asyncio.run(sqli.main(param_urls,None,vulnerabilities,depth))
                sqli.main(param_urls,None,vulnerabilities,depth,lock)
                vulnerabilities = sqli.vulnerabilities
            # xss,sqli,csrf forms
            if len(forms_d.get("forms")) > 0:
                print("Checking Forms")
                # logger.info("Checking Forms")
                # asyncio.run(xs.main(None,forms_d,vulnerabilities,depth,headers_info))
                xs.main(None,forms_d,vulnerabilities,depth,headers_info,lock)
                vulnerabilities = xs.vulnerabilities
                # asyncio.run(sqli.main(None,forms_d,vulnerabilities,depth))
                sqli.main(None,forms_d,vulnerabilities,depth,lock)
                vulnerabilities = sqli.vulnerabilities
                csrf.check_csrf(forms_d,vulnerabilities,headers_info,depth)
                vulnerabilities = csrf.vulnerabilities
            else:
                vulnerabilities["CSRF"]["status"] = False
            # port scanner
            print('port-scanning started')
            ports = p_scan.start_scan()
            print("port-scanning finished")
            jq = self.jq(urls)
            # clickjacking
            if not headers_info['Security-Headers']["X-Frame-Options"]:
                vulnerabilities["ClickJacking"]["status"] = True
            # generate report
            vulners = copy.deepcopy(vulnerabilities)
            headers = copy.deepcopy(headers_info)
            ports_copy = copy.deepcopy(ports)
            jquery_copy = copy.deepcopy(self.jquery_data)
            end = time.perf_counter()-float(start_counter)

            self.to_pdf(url,vulners,headers,start_time,end,ports_copy,jquery_copy,crawled_links)
            print("Finishing")
            # logger.info("Finishing")
            return vulnerabilities,headers_info,ports,self.jquery_data
        except:
            return [{"cause":'timeout'}]

    def jq(self,urls):
        flag = False
        session = HTMLSession()
        with ThreadPoolExecutor(max_workers=50) as exec:
            responses = exec.map(self.do_req,urls)
        self.responses = responses
        self.check_jquery(flag)

    def do_req(self,url):
        session = HTMLSession()
        user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36"
        resp = session.get(url,headers={"User-Agent":user_agent})
        return resp

    def check_jquery(self,flag):
        regx = re.compile(r"(?:jquery-)(.*[0-9./])\.js|(?:jquery-)(.*[0-9./])(?:\.min.js)|(?:google.*jquery/)(.*[0-9])|(?:jquery-)(.*[0-9./])\.slim\.min\.js|(?:jquery\.min\.js.*ver=)(.*?)[' \"]|(?:jquery-)(.*[0-9./])\.slim\.js")
        for resp in self.responses:
            try:
                # groups() return tuple
                jq_ver = regx.search(resp.text).groups()
                # con.print(jq_ver)
                for val in jq_ver:
                    # for ignoring None
                    if val != None:
                        if val.strip() != "3.6.0":
                            # con.print("[+] Outdated Version Detected",val)
                            self.jquery_data['Jquery'] = ['outdated',val]
                            flag = True
                            break
                        elif val.strip() == "3.6.0":
                            # con.print("[+] Up to date Version",val)
                            self.jquery_data['Jquery'] = ['up-to-date',val]
                            flag = True
                            break
            except:
                # con.print_exception()
                continue
            else:
                if flag:
                    break
        if not flag:
            self.jquery_data['Jquery'] = None

    def to_pdf(self,target,vulners,headers,start,end,ports,jquery,crawled_links):
        ip = socket.gethostbyname(urlparse(target).netloc)
        xss = vulners.get('XSS')
        sqli = vulners.get('SQLi')
        csrf = vulners.get("CSRF")
        cj = vulners.get("ClickJacking")
        duration = self.cal_duration(end)
        security_headers = headers['Security-Headers']
        for header,value in zip(security_headers.keys(),security_headers.values()):
            if value:
                security_headers[header] = "Found"
            else:
                security_headers[header] = "Missing"
        cookies = headers['Cookies']
        head_copy = copy.deepcopy(headers)
        ports_copy = copy.deepcopy(ports)
        chaart = self.gen_chart(vulners,head_copy,ports_copy,copy.deepcopy(jquery))
        # dynamic data
        grade = self.find_score(security_headers,cookies,target,[xss,sqli])
        severity = self.cal_severity(grade)
        security_headers = self.change_security_headers_key(security_headers)
        # data for technology
        if urlparse(target).scheme == "https":
            Protocol = False
        else:
            Protocol = 'HTTP'
        if head_copy['Framework'][0]:
            Framework = head_copy['Framework'][1]
        else:
            Framework = False
        if head_copy['Server'][0]:
            Server = head_copy['Server'][1]
        else:
            Server = False
        if head_copy['Technology'][0]:
            Technology = head_copy['Technology'][1]
        else:
            Technology = False
        Os = ports['port-scanner'].get("os",'Unknown')
        if jquery['Jquery']:
            jq_version = {"status":jquery['Jquery'][0],"version":jquery['Jquery'][1]}
        else:
            jq_version = False
        if head_copy['Cookies']['cookies']:
            cookies_copy = copy.deepcopy(cookies)
            cookies_copy['Secure'] = cookies_copy.pop('trans_https')
            cookies_copy['HttpOnly'] = cookies_copy.pop('httponly')
            cookies_copy['SameSite'] = cookies_copy.pop('samesite')
        else:
            cookies_copy = None

        warningss = {"Protocol":Protocol,"Framework":Framework,"Server":Server,"Technology":Technology,'Jquery':jq_version,"OS":Os,'Cookies':cookies_copy}
        # cookies already there above
        template_loader = jinja2.FileSystemLoader("/")
        template_Env = jinja2.Environment(loader=template_loader)
        template_file = "/home/ubuntu/backend/Misc/report.html"
        template = template_Env.get_template(template_file)
        output = template.render(
            host = target,
            target_ip = ip,
            severity = severity,
            date = self.get_date(),
            start = start,
            crawled_links = crawled_links,
            end = self.get_time(),
            duration = duration,
            security_headers = security_headers,
            xss = xss,
            sqli = sqli,
            csrf = csrf,
            cj = cj,
            ports = ports,
            warningss = warningss
        )
        # delete already present files
        filehtml = "/home/ubuntu/backend/report.html"
        filepdf = "/home/ubuntu/backend/report.pdf"
        if os.path.exists(filehtml) and os.path.exists(filepdf):
            os.remove(filehtml)
            os.remove(filepdf)
            print("Files deleted")
            # logger.info('[+] File deleted')
        else:
            print("Files not present")
            # logger.info("[+] File not present")
        html_path = f'/home/ubuntu/backend/report.html'
        html_file = open(html_path, 'w')
        html_file.write(output)
        html_file.close()
        # issue of report
        HTML('/home/ubuntu/backend/report.html').write_pdf('/home/ubuntu/backend/report.pdf', stylesheets=['/home/ubuntu/FYP/static/css/report.css'])
        # save vulnerable inputs
        self.save_inputs(xss,sqli,csrf)

    def get_date(self,):
        date = datetime.now()
        month = date.strftime("%B")
        return datetime.now().strftime(f"{month} %d, %Y")

    def cal_severity(self,grade):
        if grade == "F" or grade == "E":
            severity = {'status':"High","color":"#e83737"}
            return severity
        elif grade == "D" or grade == "C":
            severity = {'status':"Medium","color":"#4682B4"}
            return severity
        elif grade == "B" or grade == "A":
            severity = {'status':"Low","color":"#67b6f7"}
            return severity
        elif grade == "A+":
            severity = {'status':"Secured","color":"green"}
            return severity

    def change_security_headers_key(self,sec_headers):
        sec_headers['csp'] = sec_headers['Content-Security-Policy']
        # sec_headers['rf'] = sec_headers['Referrer-Policy']
        sec_headers['hsts'] = sec_headers['Strict-Transport-Security']
        sec_headers['contenttype'] = sec_headers['X-Content-Type-Options']
        sec_headers['xframe'] = sec_headers['X-Frame-Options']
        sec_headers['xssprotection'] = sec_headers['X-XSS-Protection']
        del sec_headers['Content-Security-Policy']
        # del sec_headers['Referrer-Policy']
        del sec_headers['Strict-Transport-Security']
        del sec_headers['X-Content-Type-Options']
        del sec_headers['X-Frame-Options']
        del sec_headers['X-XSS-Protection']
        return sec_headers

    def cal_duration(self,end):
        minutes = str(dt.timedelta(seconds=end))[2:7]
        if minutes[0] == "0":
            m = minutes[1]
        else:
            m = minutes[0:2]
        if minutes[3] == "0":
            s = minutes[4]
        else:
            s = minutes[3:5]
        return f"{m} min, {s} sec"


    def find_score(self,sec_headers,cookies,target,vulners):
        # return if any of vuln exist
        for vuln in vulners:
            if vuln.get('status'):
                grade = "F"
                return grade
        ideal = [1,1,1,1,1,1]
        findings = []
        if cookies.get("cookies"):
            # if cookies are present then add one more into ideal
            ideal.append(1)
            # when both True then cookie will be considered safe
            if (cookies.get("httponly") and cookies.get("samesite")):
                safe_cookies = True
            else:
                safe_cookies = False
        else:
            pass
        # check protocol
        scheme = urlparse(target).scheme
        if scheme == "https":
            findings.append(1)
        else:
            findings.append(0)
        # 5 headers
        for val in sec_headers.values():
            if val == "Missing":
                findings.append(0)
            else:
                findings.append(1)
        # if True then 1
        # findings will be 7 when cookies True else keep them 6 ,so it solve the error of [6,7]
        if cookies.get('cookies'):
            if safe_cookies:
                findings.append(1)
            else:
                findings.append(0)
        grade = ''
        score = accuracy_score(ideal,findings)
        # grades when cookies present (ideal = 7)
        if cookies.get("cookies"):
            if score >= 0.85:
                grade = "A+"
            elif score >= 0.71:
                grade = "A"
            elif score >= 0.57:
                grade = "B"
            elif score >= 0.42:
                grade = "C"
            elif score >= 0.28:
                grade = "D"
            elif score >= 0.14:
                grade = "E"
            else:
                grade = "F"
            return grade
        # grades when cookies are not present (ideal = 6)
        else:
            if score >= 0.83:
                grade = "A+"
            elif score >= 0.66:
                grade = "A"
            elif score >= 0.5:
                grade = "B"
            elif score >= 0.33:
                grade = "C"
            elif score >= 0.16:
                grade = "D"
            else:
                grade = "F"
            print("missing cookie")
            return grade

    def get_time(self,):
        timezone = pytz.timezone("Asia/Karachi")
        dt = datetime.now(timezone)
        return dt.strftime("%Y:%m:%d %H:%M:%S")

    def save_inputs(self,xss,sqli,csrf):
        v_inputs = {
            "xss":{"vulnerable parameters":[xss['p-links']],"vulnerable_forms":xss['f-links']},
            "sqli":{"vulnerable parameters":[sqli['p-links']],"vulnerable_forms":sqli['f-links']},
            "csrf":{"vulnerable_forms":[csrf['f-links']]}
        }
        with open("/home/ubuntu/backend/vulnerable_inputs.json",'w') as f:
            json.dump(v_inputs,f)

    ##### Generate Chart #####
    def gen_chart(self,vulners,headers,ports,jquery):
        matplotlib.use('Agg')
        xss = vulners.get('XSS')
        sqli = vulners.get('SQLi')
        csrf = vulners.get("CSRF")
        cj = vulners.get("ClickJacking")

        vulners = [xss,sqli]
        sec_headers = headers["Security-Headers"]
        cookies = headers["Cookies"]
        for header,value in zip(sec_headers.keys(),sec_headers.values()):
            if value:
                sec_headers[header] = "Found"
            else:
                sec_headers[header] = "Missing"
        risky_ports = ["21", "23", "25", "53", "139", "445", "1433", "1434", "3306", "3389"]
        ports = ports['port-scanner']
        Technologies = {}
        if headers["Framework"][0]:
                Technologies["Framework"] = headers["Framework"][1]
        if headers["Server"][0]:
            Technologies["Server"] = headers["Server"][1]
        if headers["Technology"][0]:
            Technologies["Backend"] = headers["Technology"][1]
        Technologies['OS'] = ports.get("os",'Unknown')
        Technologies["Jquery"] = jquery

        sizes = self.find_ratings(vulners,sec_headers,risky_ports,csrf,cj,ports,Technologies)
        labels = ["High","Medium","Low","Info"]
        colors = ["#e83737","#4682B4","#67b6f7","#b2b2a0"]
        fig1,ax1 = plt.subplots()
        ax1.pie(sizes,labels=labels,colors=colors,autopct='%1.1f%%',shadow=True,startangle=90)
        ax1.axis("equal")
        plt.legend()
        plt.savefig("/home/ubuntu/FYP/chart.png",bbox_inches='tight')
        plt.close(fig1)

    def find_ratings(self,vulners,security_headers,risky_ports,csrf,cj,ports,Technologies):
        ratings = {"High":0,"Medium":0,"Low":0,"Info":0}
        # high ratings
        for v in vulners:
            if v.get("status"):
                ratings["High"] +=1
            if Technologies.get("Jquery") != None:
                ratings["High"] +=1
        # medium ratings
        # print(security_headers)
        for val in security_headers.values():
            if val == "Missing":
                ratings['Medium'] +=1
        for port in ports.keys():
            if port in risky_ports:
                ratings['Medium'] +=1
            # low ratings
            else:
                ratings['Low'] +=1
        if csrf.get("status"):
            ratings['Medium'] +=1
        if cj.get("status"):
            ratings['Medium'] +=1
        # Info ratings
        for val in Technologies.values():
            # skip unknown value
            if val != "Unknown":
                ratings['Info'] +=1
        return ratings.values()


############## API ################
class Item(BaseModel):
    start_time: str
    start_counter: str
    target: str
    depth: str

app = FastAPI()
@app.post('/result/')
def result(item:Item):
    start_time = item.start_time
    start_counter = item.start_counter
    url = item.target
    depth = item.depth.lower()
    if depth.lower() == 'true':
        depth = True
    elif depth.lower() == 'false':
        depth = False
    controller = Controller()
    try:
        results = controller.main(url,depth,start_time,start_counter)
    except Exception as e:
        print(e)
        results = [{"cause":'timeout'}]
    finally:
        return results

if __name__=='__main__':
    app.run(debug=True,port=8081)