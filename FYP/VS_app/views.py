
from time import perf_counter
import time
from django.shortcuts import render,redirect
import requests
import socket
from datetime import datetime
import datetime as  dt
from urllib.parse import urlparse
from .forms import CustomForm
import json
import pytz
from rich.console import Console
r = Console()
from weasyprint import HTML, CSS
from sklearn.metrics import accuracy_score
from django.template.loader import get_template
from django.http import HttpResponse, JsonResponse,FileResponse
import matplotlib.pyplot as plt
import copy
import os
import hashlib
from filelock import FileLock


def home(request):
    return render(request,"before.html")

def result(request):
    if request.method.lower() == 'post':
        req_url = request.POST.get("search").strip().encode('utf-8')
        filename = hashlib.md5(req_url).hexdigest()
        datafile = f'/home/lubuntu/PycharmProjects/V/FYP/result_data/{filename}.json'
        data = get_data(request)
        lock = FileLock(datafile,timeout=2)
        with lock:
            if os.path.exists(datafile):
                os.remove(datafile)
            with open(datafile,'w') as f:
                json.dump(data,f)
        return HttpResponse('OK')
    elif request.method.lower() == 'get':
        req_url = request.GET.get("target",'None').encode('utf-8')
        filename = hashlib.md5(req_url).hexdigest()
        datafile = f'/home/lubuntu/PycharmProjects/V/FYP/result_data/{filename}.json'
        if os.path.exists(datafile):
            with open(datafile,'r') as f:
                data = json.load(f)
            if data != "Timeout" and data != "Down":
                try:
                    metadata = zip(data[0].keys(),data[0].values())
                    raw_headers = zip(data[1].keys(),data[1].values())
                    security_headers = zip(data[2].keys(),data[2].values())
                    technologiese = zip(data[3].keys(),data[3].values())
                    grade = data[4]
                    # vulnerabilities
                    xss = data[5]
                    sqli = data[6]
                    csrf = data[7]
                    cj = data[8]
                    ports = data[9]
                    cookies = data[10]
                    # risky ports
                    risky_p = data[11]
                except Exception as e:
                    r.print_exception()
                    print(f"error in {e}")
                    context = {"code":[5,0,4],"error":"Timeout"}
                    return render(request,"error.html",context)
                else:
                    context = {"Metadata":metadata,"Raw_headers":raw_headers,"Security_headers":security_headers,"Technologies":technologiese,"Grade":grade,"xss":xss,"sqli":sqli,'csrf':csrf,'cj':cj,'ports':ports,'cookies':cookies,"risky_p":risky_p}
                    return render(request,"after.html",context)    
            elif data == 'Down':
                context = {"code":[5,0,3],"error":"Target Down"}
                return render(request,"error.html",context)
            else:
                context = {"code":[5,0,4],"error":"Timeout"}
                return render(request,"error.html",context)
        else:
            context = {"code":[5,0,4],"error":"Timeout"}
            return render(request,"error.html",context)

def validate_url(url):
	try:
		resp = requests.get(url,headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36"},timeout=5)
	except (Exception, ConnectionError):
		return False
	else:
		if resp.status_code == 200:
			return True
		else:
			return False

def get_data(request):
    # for duration
    start_counter = time.perf_counter()
    start_time = get_time()
    target = request.POST.get("search").strip()
    mode = request.POST.get("selection")
    if mode == "deep":
        deep = True
    else:
        deep = False
        # if x-xss protection missing do xss otherwise dont
    parsed_t = urlparse(target)
    scheme =parsed_t.scheme
    domain = parsed_t.netloc
    path = parsed_t.path
    url = scheme+"://"+domain+path
    body_data = {"depth":deep,"target":url,"start_time":start_time,"start_counter":start_counter}
    api = f"http://127.0.0.1:8081/result/"
    valid = validate_url(url)
    # backend
    if valid:
        try:
            print('VALID')
            response = requests.post(api,timeout=300,json=body_data)
        except:
            r.print_exception()
            # logger.exception("Error in calling main() API")
            results = [{"cause":'timeout'}]
        else:
            results = json.loads(response.text)
    else:
        results = [{"cause":'down'}]
    data = results
    try:
        if data[0].get("cause",'None') == "down":
            print("\nI'M DOWN")
            return "Down"
        elif data[0].get("cause",'None') == "timeout":
            print("\nI'M Timeout")
            return "Timeout"
        else:
            #r.print(data)
            print("\nI'M RUNNING")

            xss = data[0].get("XSS").get("status")
            sqli = data[0].get("SQLi").get("status")
            csrf = data[0].get("CSRF").get('status')
            cj = data[0].get("ClickJacking").get('status')

            status = data[0].get("XSS").get("status")
            no_links = len(data[0].get("XSS").get("p-links"))+len(data[0].get("XSS").get("f-links"))
            p_links = data[0].get("XSS").get("p-links")
            f_links = data[0].get("XSS").get("f-links")
            xss = {"status":status,"no_links":no_links,'p_links':p_links,'f_links':f_links}

            status = data[0].get("SQLi").get("status")
            no_links = len(data[0].get("SQLi").get("p-links")) + len(data[0].get("SQLi").get("f-links"))
            p_links = data[0].get("SQLi").get("p-links")
            f_links = data[0].get("SQLi").get("f-links")
            sqli = {"status": status, "no_links": no_links,'p_links':p_links,'f_links':f_links}

            status = data[0].get("CSRF").get("status")
            no_links = len(data[0].get("CSRF").get("f-links"))
            f_links = data[0].get("CSRF").get("f-links")
            csrf = {"status": status, "no_links": no_links,'f-links':f_links}

            status = data[0].get("ClickJacking").get("status")
            cj = {"status":status,"no_links":""}

            ports = data[2]['port-scanner']

            raw_headers = data[1]["Raw-Headers"]
            security_headers = data[1]["Security-Headers"]
            cookies = data[1]["Cookies"]
            for header,value in zip(security_headers.keys(),security_headers.values()):
                if value:
                    security_headers[header] = "Found"
                else:
                    security_headers[header] = "Missing"
            Technologies = {}
            # check if framework found
            if data[1]["Framework"][0]:
                Technologies["Framework"] = data[1]["Framework"][1]
            if data[1]["Server"][0]:
                Technologies["Server"] = data[1]["Server"][1]
            if data[1]["Technology"][0]:
                Technologies["Backend"] = data[1]["Technology"][1]
            Technologies['OS'] = data[2]["port-scanner"].get("os",'Unknown')
            jquery = data[3]['Jquery']
            Technologies["Jquery"] = jquery
            # report metadata
            ip = socket.gethostbyname(urlparse(target).netloc)
            end_time = get_time()
            metadata = {'Target':target,'IP':ip,"Report-Time":end_time}
            vulners = [xss, sqli]
            grade = find_score(security_headers,copy.deepcopy(cookies),target,vulners)
            risky_ports = ["21", "23", "25", "53", "139", "445", "1433", "1434", "3306", "3389"]

            return metadata,raw_headers,security_headers,Technologies,grade,xss,sqli,csrf,cj,ports,cookies,risky_ports
    except:
        r.print_exception()
        print("error in get_data")
        return "Timeout"


def error(request):
    return render(request,'error.html')

def get_time():
    timezone = pytz.timezone("Asia/Karachi")
    dt = datetime.now(timezone)
    return dt.strftime("%Y:%m:%d %H:%M:%S")

def find_score(sec_headers,cookies,target,vulners):
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

def fetch_pdf(request):
    if request.method.lower() == 'post':
        if request.headers.get("Host") == '127.0.0.1:8000':
            target = request.POST.get("report").strip()
            pdf = f"/home/lubuntu/PycharmProjects/V/backend/reports/{urlparse(target).netloc}.pdf"
            return FileResponse(open(pdf,"rb"),as_attachment=True,filename=f"{urlparse(target).netloc}.pdf",content_type="application/pdf")
        else:
            context = {"code":[4,0,4],"error":"Not Found"}
            return render(request,"404.html",context)
    else:
        context = {"code":[4,0,4],"error":"Not Found"}
        return render(request,"404.html",context)
    
def v_inputs(request):
    if request.method.lower() == 'post':
        if request.headers.get("Host") == '127.0.0.1:8000':
            target = request.POST.get("v_inputs").strip()
            vulner_inputs = f"/home/lubuntu/PycharmProjects/V/backend/v_inputs/{urlparse(target).netloc}.json"
            opened = open(vulner_inputs,'r')
            content_type = 'application/json'
            response = HttpResponse(opened,content_type=content_type)
            response['Content-Disposition'] = f"attachment; filename={urlparse(target).netloc}.json"
            opened.close()
            return response
        else:
            context = {"code":[4,0,4],"error":"Not Found"}
            return render(request,"404.html",context)
    else:
        context = {"code":[4,0,4],"error":"Not Found"}
        return render(request,"404.html",context)

def error_404(request,exception):
    context = {"code":[4,0,4],"error":"Not Found"}
    return render(request,"404.html",context)
####################### Main ###########################
