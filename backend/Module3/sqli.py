from urllib.parse import urljoin,urlparse,parse_qs
# from rich import console
from rich.console import Console
import threading
from requests_html import HTMLSession
import queue
from . import dbms
# install()

import logging
###############logging##############
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# formatter = logging.Formatter("%(name)s %(levelname)s %(funcName)s %(message)s")
# handler = logging.FileHandler("/home/ubuntu/FYP/logs/sqli.log",mode='w')
# handler.setFormatter(formatter)
# logger.addHandler(handler)
####################################

class SQLi():
    def __init__(self):
        self.queue = queue.Queue()

    def main(self,urls,forms_d,vulnerabilities,depth):
        self.vulnerabilities = vulnerabilities
        lock = threading.Lock()
        session = HTMLSession()
        if urls:
            urls = self.decide_limits(urls,forms_d,depth)
            flag = 'url'
        elif forms_d:
            forms_d = self.decide_limits(urls,forms_d,depth)
            flag = 'form'
        self.fill_Q(urls,forms_d)
        self.run(session,flag,lock)
    
    def fill_Q(self,urls,forms):
        if urls:
            for url in urls:
                self.queue.put(url)
        elif forms:
            for form,url in zip(forms["forms"],forms["links"]):
                self.queue.put((form,url))

    def decide_limits(self,urls,forms_d,depth):
        if depth:
            if urls != None and len(urls) > 0:
                urls = urls[:500]
                return urls
            elif forms_d != None and len(forms_d.get("forms")) > 0:
                links = forms_d.get("links")[:250]
                forms = forms_d.get("forms")[:250]
                # self.r.print("forms leng",len(forms))
                return {"forms":forms,'links':links}
        else:
            if urls != None and len(urls) > 0:
                urls = urls[:250]
                return urls
            elif forms_d != None and len(forms_d.get("forms")) > 0:
                links = forms_d.get("links")[:150]
                forms = forms_d.get("forms")[:150]
                return {"forms":forms,'links':links}

    def verify_injection(self,url,session,user_agent):
        resp = session.get(url,headers={'User-Agent':user_agent})
        # here url is without any payload injection
        if resp.status_code == 500:
            return False
        elif resp.status_code == 200:
            return True

    def get_errors(self):
        errors = []
        for item in dbms.SQL_ERRORS_STR:
            errors.append(item[0].lower())
        return errors

    def injection(self,session,item,flag,lock):
        user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36'
        payload = u"a'b\"c'd\""
        errors = self.get_errors()
        if flag == 'url':
            url = item
            try:
                original_url = url
                query = urlparse(url).query
                modified_query = query.replace("=","=1")
                param_values = list(parse_qs(modified_query).values())
                for pvm in param_values:
                    modified_query = modified_query.replace(pvm[0],payload)
                url = url.replace(urlparse(url).query,modified_query)
                resp = session.get(url,headers={"User-Agent":user_agent})
                # handling internal error & redirection, (indicators of sqli)
                if resp.status_code == 500:
                    print("[+] 500 received")
                    # logger.info("[+] 500 received")
                    if self.verify_injection(original_url,session,user_agent):
                        print(f"[+] SQL injection Found in link (inference) {url}")
                        # logger.info(f"SQL Injection found in link (inference) {url}")
                        lock.acquire(2)
                        self.vulnerabilities['SQLi']['status'] = True
                        self.vulnerabilities['SQLi']['p-links'].append(original_url)
                        lock.release()
                    else:
                        pass
                else:
                    for error in errors:
                        if error in resp.text.lower():
                            print(f"[+] SQL injection Found in link")
                            # logger.info("SQL Injection found in link")
                            lock.acquire(2)
                            self.vulnerabilities['SQLi']['sure'] = True
                            self.vulnerabilities['SQLi']['status'] = True
                            self.vulnerabilities['SQLi']['p-links'].append(original_url)
                            lock.release()
                            break
                        else:
                            continue
            except:
                print("[+] error in injection (url)")

        elif flag == 'form':
            form,url = item
        # checking xss via forms
            try:
                data = {}
                # extracting data from form
                if form.attrib.get("method"):
                    method = form.attrib.get("method").lower()
                else:
                    method = "POST".lower()
                if form.attrib.get("action"):
                    post_url = urljoin(url,form.attrib.get("action"))
                else:
                    post_url = url
                # filling values to all inputs of forms
                submit = False
                for input in form.xpath(".//input"):
                    if input.attrib.get("type") == "text":
                        data[f'{input.attrib.get("name")}'] = payload
                    elif input.attrib.get("type") == "password":
                        data[f"{input.attrib.get('name')}"] = "password"
                        #handling hidden field
                    elif input.attrib.get("type") == "hidden":
                        try:
                            value = input.attrib.get("value")
                        except:
                            try:
                                data[f"{input.attrib.get('name')}"] = ""
                            except:
                                data[""] = ""
                        else:
                            data[f"{input.attrib.get('name')}"] = value
                    elif input.attrib.get("type") == "submit":
                        submit = True
                        try:
                            value = input.attrib.get("value")
                        except:
                            data[f"{input.attrib.get('name')}"] = 'submit'
                        else:
                            data[f"{input.attrib.get('name')}"] = value
                    else:
                        data[f"{input.attrib.get('name')}"] = ''
                # handling button input
                if not submit:
                    try:
                        value = form.xpath(".//button").attrib.get("value")
                    except:
                        data[f"{form.xpath('.//button').attrib.get('name')}"] = 'submit'
                    else:
                        data[f"{form.xpath('.//button').attrib.get('name')}"] = value
                # handling select input
                if form.xpath(".//select"):
                    try:
                        name = form.xpath(".//select").attrib.get("name")
                    except:
                        name = ''
                    data[name] = payload
                # post request
                if method == 'post':
                    resp = session.post(url,headers={"User-Agent":user_agent},data=data)
                # get request
                elif method == "get":
                    resp = session.get(url,headers={"User-Agent":user_agent},params=data)
                # handling internal error , (indicators of sqli)
                if resp.status_code == 500:
                    if self.verify_injection(url,session,user_agent):
                        print(f"[+] SQL injection Found in form (inference)")
                        # logger.info("SQL Injection found in form (inference)")
                        lock.acquire(2)
                        self.vulnerabilities['SQLi']['status'] = True
                        self.vulnerabilities['SQLi']['f-links'].append(url)
                        lock.release()
                    else:
                        pass
                else:
                    for error in errors:
                        if error in resp.text.lower():
                            print(f"[+] SQL Injection Discovered in form {url}")
                            # logger.info(f"SQL Injection found in form {url}")
                            lock.acquire(2)
                            self.vulnerabilities['SQLi']['sure'] = True
                            self.vulnerabilities['SQLi']['status'] = True
                            self.vulnerabilities['SQLi']['f-links'].append(url)
                            lock.release()
                            break
                        else:
                            continue
            except:
                print("[+] error in injection (forms)")
 

    def run(self,session,flag,lock):
        threads = []
        for i in range(50):
            item = self.queue.get()
            t = threading.Thread(target=self.injection,args=(session,item,flag,lock))
            t.daemon = True
            threads.append(t)
            t.start()
            if self.queue.empty():
                break
        for th in threads:
            th.join()
        if not self.queue.empty():
            self.run(session,flag,lock)
#     def __init__(self):
#         self.payload = u"a'b\"c'd\""
#         self.errors = self.get_errors()
#         self.user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36'
#         self.r = Console()
#         self.max_workers = 100
#         self.i = 0

#     def get_errors(self):
#         errors = []
#         for item in dbms.SQL_ERRORS_STR:
#             errors.append(item[0].lower())
#         return errors

#     async def main(self,urls,forms_d,vulnerabilities,depth):
#         # print("\rSQLi starting",end="")
#         # self.r.print("STARTING SQLI")
#         session = AsyncHTMLSession()
#         self.vulnerabilities = vulnerabilities
#         task_queue = Queue(maxsize=100)
#         qevent = asyncio.Event()
#         qevent.clear()
#         # print("qevent False")
#         if urls:
#             urls = self.decide_limits(urls,forms_d,depth)
#             flag = 'url'
#         elif forms_d:
#             forms_d = self.decide_limits(urls,forms_d,depth)
#             flag = 'form'
#         tasks = [asyncio.create_task(self.fill_Q(urls,qevent,task_queue,forms_d))]
#         for _ in range(self.max_workers):
#             task = asyncio.create_task(self.injection(task_queue,session,flag))
#             tasks.append(task)
#         await qevent.wait()
#         # print("qevent finished")
#         await task_queue.join()
#         # self.r.print("DOne")
#         for task in tasks:
#             task.cancel()
#         await asyncio.gather(*tasks,return_exceptions=True)
    
#     async def fill_Q(self,urls,qevent,task_queue,forms_d):
#         if urls:
#             for url in urls:
#                 await task_queue.put(url)
#         elif forms_d:
#             forms = forms_d.get("forms")
#             links = forms_d.get("links")
#             for form,link in zip(forms,links):
#                 await task_queue.put((form,link))
#             # self.r.print("forms",task_queue.qsize())
#         qevent.set()
        

#     def decide_limits(self,urls,forms_d,depth):
#         if depth:
#             if urls != None and len(urls) > 0:
#                 urls = urls[:1000]
#                 return urls
#             elif forms_d != None and len(forms_d.get("forms")) > 0:
#                 links = forms_d.get("links")[:500]
#                 forms = forms_d.get("forms")[:500]
#                 # self.r.print("forms leng",len(forms))
#                 return {"forms":forms,'links':links}
#         else:
#             if urls != None and len(urls) > 0:
#                 urls = urls[:500]
#                 return urls
#             elif forms_d != None and len(forms_d.get("forms")) > 0:
#                 links = forms_d.get("links")[:250]
#                 forms = forms_d.get("forms")[:250]
#                 return {"forms":forms,'links':links}

#     async def verify_injection(self,url,session):
#         resp = await session.head(url,headers={'User-Agent':self.user_agent})
#         # here url is without any payload injection
#         if resp.status_code == 500:
#             return False
#         elif resp.status_code == 200:
#             return True

#     async def injection(self,task_queue,session,flag):
#         # for verify_injection
#         if flag == "url":
#             while True:
#                 try:
#                     url = await task_queue.get()
#                     # self.r.print(url)
#                     original_url = url
#                     query = urlparse(url).query
#                     modified_query = query.replace("=","=1")
#                     param_values = list(parse_qs(modified_query).values())
#                     for pvm in param_values:
#                         modified_query = modified_query.replace(pvm[0],self.payload)
#                     url = url.replace(urlparse(url).query,modified_query)
#                     resp = await session.get(url,headers={"User-Agent":self.user_agent})
#                     # handling internal error & redirection, (indicators of sqli)
#                     if resp.status_code == 500:
#                         self.r.print("[+] 500 received")
#                         # logger.info("[+] 500 received")
#                         if await self.verify_injection(original_url,session):
#                             self.r.print(f"[green bold]SQL injection Found in link (inference) {url}")
#                             # logger.info(f"SQL Injection found in link (inference) {url}")
#                             self.vulnerabilities['SQLi']['status'] = True
#                             self.vulnerabilities['SQLi']['p-links'].append(original_url)
#                         else:
#                             pass
#                     else:
#                         for error in self.errors:
#                             if error in resp.text.lower():
#                                 self.r.print(f"[green bold]SQL injection Found in link")
#                                 # logger.info("SQL Injection found in link")
#                                 self.vulnerabilities['SQLi']['sure'] = True
#                                 self.vulnerabilities['SQLi']['status'] = True
#                                 self.vulnerabilities['SQLi']['p-links'].append(original_url)
#                                 break
#                             else:
#                                 continue
#                 except asyncio.CancelledError:
#                     # self.r.print_exception()
#                     pass
#                 finally:
#                     task_queue.task_done()

#         elif flag == "form": 
#             while True:
#                 try:
#                     form,url = await task_queue.get()
#                     # self.r.print(form,url)
#                     data = {}
#                     # extracting data from form
#                     # method
#                     if form.attrib.get("method"):
#                         method = form.attrib.get("method").lower()
#                     else:
#                         method = "POST".lower()
#                     if form.attrib.get("action"):
#                         post_url = urljoin(url,form.attrib.get("action"))
#                     else:
#                         post_url = url
#                     # filling values to all inputs of forms
#                     submit = False
#                     for input in form.xpath(".//input"):
#                         if input.attrib.get("type") == "text":
#                             data[f'{input.attrib.get("name")}'] = self.payload
#                         elif input.attrib.get("type") == "password":
#                             data[f"{input.attrib.get('name')}"] = "password"
#                             #handling hidden field
#                         elif input.attrib.get("type") == "hidden":
#                             try:
#                                 value = input.attrib.get("value")
#                             except:
#                                 try:
#                                     data[f"{input.attrib.get('name')}"] = ""
#                                 except:
#                                     data[""] = ""
#                             else:
#                                 data[f"{input.attrib.get('name')}"] = value
#                         elif input.attrib.get("type") == "submit":
#                             submit = True
#                             try:
#                                 value = input.attrib.get("value")
#                             except:
#                                 data[f"{input.attrib.get('name')}"] = 'submit'
#                             else:
#                                 data[f"{input.attrib.get('name')}"] = value
#                         else:
#                             data[f"{input.attrib.get('name')}"] = ''
#                     # handling button input
#                     if not submit:
#                         try:
#                             value = form.xpath(".//button").attrib.get("value")
#                         except:
#                             data[f"{form.xpath('.//button').attrib.get('name')}"] = 'submit'
#                         else:
#                             data[f"{form.xpath('.//button').attrib.get('name')}"] = value
#                     # handling select input
#                     if form.xpath(".//select"):
#                         try:
#                             name = form.xpath(".//select").attrib.get("name")
#                         except:
#                             name = ''
#                         data[name] = self.payload
#                     # post request
#                     if method == 'post':
#                         resp = await session.post(url,headers={"User-Agent":self.user_agent},data=data)
#                     # get request
#                     elif method == "get":
#                         resp = await session.get(url,headers={"User-Agent":self.user_agent},params=data)
#                     # handling internal error , (indicators of sqli)
#                     if resp.status_code == 500:
#                         if await self.verify_injection(url,session):
#                             self.r.print(f"[green bold]SQL injection Found in form (inference)")
#                             # logger.info("SQL Injection found in form (inference)")
#                             self.vulnerabilities['SQLi']['status'] = True
#                             self.vulnerabilities['SQLi']['f-links'].append(url)
#                         else:
#                             pass
#                     else:
#                         for error in self.errors:
#                             if error in resp.text.lower():
#                                 self.r.print(f"[green bold]SQL Injection Discovered in form {url}")
#                                 # logger.info(f"SQL Injection found in form {url}")
#                                 self.vulnerabilities['SQLi']['sure'] = True
#                                 self.vulnerabilities['SQLi']['status'] = True
#                                 self.vulnerabilities['SQLi']['f-links'].append(url)
#                                 break
#                             else:
#                                 continue
#                 except asyncio.CancelledError:
#                     # self.r.print_exception()
#                     pass
#                 # else:
#                 #     self.i+=1
#                 #     self.r.print(self.i)
#                 finally:
#                     task_queue.task_done()
#     #
# # import requests_html
# # session = requests_html.HTMLSession()
# # s = SQLi()
# # r = session.get("http://192.168.62.128/mutillidae/index.php?page=user-info.php")
# # sel = Selector(text=r.text)
# # form = sel.xpath("//form")
# # s.injection("http://192.168.62.128/mutillidae/index.php?page=user-info.php",None,session,form)
