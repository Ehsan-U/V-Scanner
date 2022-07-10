from concurrent.futures import thread
from requests_html import HTMLSession
from urllib.parse import urlparse,parse_qs
from colorama import Fore,init
import asyncio
# from rich.traceback import install
from rich.console import Console
from urllib.parse import urljoin
import threading
import queue
import logging
###############logging##############
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# formatter = logging.Formatter("%(name)s %(levelname)s %(funcName)s %(message)s")
# handler = logging.FileHandler("/home/ubuntu/FYP/logs/xss.log",mode='w')
# handler.setFormatter(formatter)
# logger.addHandler(handler)
####################################

class Xss():
    def __init__(self):
        self.queue = queue.Queue()

    def main(self,urls,forms_d,vulnerabilities,depth,headers,lock):
        self.vulnerabilities = vulnerabilities
        if not headers['Security-Headers']['X-XSS-Protection']:
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
                #urls = urls[:500]
                return urls
            elif forms_d != None and len(forms_d.get("forms")) > 0:
                # links = forms_d.get("links")[:250]
                links = forms_d.get("links")
                # forms = forms_d.get("forms")[:250]
                forms = forms_d.get("forms")
                # self.r.print("forms leng",len(forms))
                return {"forms":forms,'links':links}
        else:
            if urls != None and len(urls) > 0:
                #urls = urls[:250]
                return urls
            elif forms_d != None and len(forms_d.get("forms")) > 0:
                # links = forms_d.get("links")[:150]
                # forms = forms_d.get("forms")[:150]
                links = forms_d.get("links")
                forms = forms_d.get("forms")
                return {"forms":forms,'links':links}

    def start_xss(self,session,item,flag,lock):
        user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36'
        payload = '<script>alert(9)</script>'
        if flag == 'url':
            url = item
            try:
                original_url = url
                # post_url and data not present (None)
                parsed_url = urlparse(original_url)
                # returns query part as str
                url_query = parsed_url.query
                # handling parameters with no values
                modified_url_query = url_query.replace("=","=1")
                # returns dict, key(paramter) and value (parameter corresponding value)
                query_dict = parse_qs(modified_url_query)
                #print(query_dict)
                # replacing the parameters values with payload
                # [['param_val1'],['param_val2']]
                param_values = list(query_dict.values())
                for pmv in param_values:
                    # injecting payload into each paramter value
                    modified_url_query = modified_url_query.replace(pmv[0],payload)
                # replacing url query with modified query
                url = url.replace(urlparse(url).query,modified_url_query)
                resp = session.get(url,headers={"User-Agent":user_agent})
                if payload in resp.text.lower():
                    print(f"\n[+] XSS Discovered in Parameter {url}")
                    # logger.info(f"[+] XSS Discovered in Parameter {url}")
                    lock.acquire(2)
                    self.vulnerabilities["XSS"]["status"] = True
                    self.vulnerabilities["XSS"]["p-links"].append(original_url)
                    lock.release()
                else:
                    pass
            except:
                print("[+] error in start_xss (url)")

        elif flag == 'form':
            form,url = item
        # checking xss via forms
            try:
                data = {}
                # get method from attribute
                if form.attrib.get("method"):
                    method = form.attrib.get("method").lower()
                # if not method attribute not found then use POST
                else:
                    method = "POST".lower()
                # extract url from action attr for form submission
                try:
                    post_url = urljoin(url,form.attrib.get("action"))
                # if action attr not found then use current page url as POST_url
                except:
                    post_url = url
                # filling values to all inputs of forms
                submit = False
                for input in form.xpath(".//input"):
                    if input.attrib.get("type") == "text":
                        data[f'{input.attrib.get("name")}'] = payload
                    elif input.attrib.get("type") == "password":
                        data[f"{input.attrib.get('name')}"] = "password"
                    elif input.attrib.get("type") == "hidden":
                        try:
                            value = input.attrib.get("value")
                        except:
                            data[f"{input.attrib.get('hidden')}"] = ""
                        else:
                            data[f"{input.attrib.get('hidden')}"] = value
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
                # self.r.print(data)
                if payload in resp.text.lower():
                    print(f"\n[+] XSS Discovered in Form {url}")
                    #print(data)
                    lock.acquire(2)
                    self.vulnerabilities["XSS"]["status"] = True
                    self.vulnerabilities["XSS"]["f-links"].append(url)
                    lock.release()
                else:
                    pass
            except Exception as e:
                print("[+] error in start_xss (forms)")
                print(e)
 

    def run(self,session,flag,lock):
        threads = []
        # try 
        # threadpool
        for i in range(50):
            item = self.queue.get()
            t = threading.Thread(target=self.start_xss,args=(session,item,flag,lock))
            t.daemon = True
            threads.append(t)
            t.start()
            if self.queue.empty():
                break
        for th in threads:
            th.join()
        if not self.queue.empty():
            self.run(session,flag,lock)

    # async def main(self,urls,forms_d,vulnerabilities,depth,headers):
    #     # print("\rXSS starting",end="")
    #     # self.r.print(forms_d)
    #     # check xss when protection not present
    #     self.vulnerabilities = vulnerabilities
    #     if not headers['Security-Headers']['X-XSS-Protection']:
    #         session = AsyncHTMLSession()
    #         task_queue = Queue(maxsize=100)
    #         qevent = asyncio.Event()
    #         # set to False
    #         qevent.clear()
    #         # print("qeveent False")
    #         if urls:
    #             urls = self.decide_limits(urls,forms_d,depth)
    #             flag = 'url'
    #         elif forms_d:
    #             forms_d = self.decide_limits(urls,forms_d,depth)
    #             flag = 'form'
    #         tasks = [asyncio.create_task(self.fill_Q(urls,qevent,task_queue,forms_d))]
    #         for _ in range(self.max_workers):
    #                 task = asyncio.create_task(self.start_xss(task_queue,session,flag))
    #                 tasks.append(task)
    #         # waiting filling event to complete
    #         await qevent.wait()
    #         # print("qevent finish")
    #         # block until all queue items are processed
    #         await task_queue.join()
    #         # print("items processed")
    #         for task in tasks:
    #             task.cancel()
    #         # gather output
    #         await asyncio.gather(*tasks,return_exceptions=True)

    # async def fill_Q(self,urls,qevent,task_queue,forms):
    #     # will fill 20 urls into queue due to limit
    #     # then will go into wait
    #     # when 20 will be processed then come back here and continue work more 20
    #     if urls:
    #         for url in urls:
    #             await task_queue.put(url)
    #     elif forms:
    #         for form,url in zip(forms["forms"],forms["links"]):
    #             # self.r.print(form,url)
    #             await task_queue.put((form,url))
    #     # will run when all urls processed
    #     qevent.set()
    #     # print("qevent set True")

    # def decide_limits(self,urls,forms_d,depth):
    #     if depth:
    #         if urls != None and len(urls) > 0:
    #             urls = urls[:1000]
    #             return urls
    #         elif forms_d != None and len(forms_d.get("forms")) > 0:
    #             links = forms_d.get("links")[:500]
    #             forms = forms_d.get("forms")[:500]
    #             # self.r.print("forms leng",len(forms))
    #             return {"forms":forms,'links':links}
    #     else:
    #         if urls != None and len(urls) > 0:
    #             urls = urls[:500]
    #             return urls
    #         elif forms_d != None and len(forms_d.get("forms")) > 0:
    #             links = forms_d.get("links")[:250]
    #             forms = forms_d.get("forms")[:250]
    #             return {"forms":forms,'links':links}

    # async def start_xss(self,task_queue,session,flag):
    #     if flag == "url":
    #         while True:
    #             try:
    #                 url = await task_queue.get()
    #                 original_url = url
    #                 # post_url and data not present (None)
    #                 parsed_url = urlparse(original_url)
    #                 # returns query part as str
    #                 url_query = parsed_url.query
    #                 # handling parameters with no values
    #                 modified_url_query = url_query.replace("=","=1")
    #                 # returns dict, key(paramter) and value (parameter corresponding value)
    #                 query_dict = parse_qs(modified_url_query)
    #                 #print(query_dict)
    #                 # replacing the parameters values with payload
    #                 # [['param_val1'],['param_val2']]
    #                 param_values = list(query_dict.values())
    #                 for pmv in param_values:
    #                     # injecting payload into each paramter value
    #                     modified_url_query = modified_url_query.replace(pmv[0],self.payload)
    #                 # replacing url query with modified query
    #                 url = url.replace(urlparse(url).query,modified_url_query)
    #                 try:
    #                     resp = await session.get(url,headers={'User-Agent':self.user_agent},allow_redirects=False)
    #                 except:
    #                     self.r.print_exception()
    #                     # logger.exception("Error in start_xss()")
    #                 else:
    #                     if self.payload in resp.text.lower():
    #                         print(f"\n[+] {Fore.GREEN}XSS Discovered in Parameter {url}{Fore.RESET}")
    #                         # logger.info(f"[+] XSS Discovered in Parameter {url}")
    #                         self.vulnerabilities["XSS"]["status"] = True
    #                         self.vulnerabilities["XSS"]["p-links"].append(original_url)
    #                     else:
    #                         pass
    #                 # self.i +=1
    #                 # print(f"{self.i} item processed")
    #             except asyncio.CancelledError:
    #                 # self.r.print_exception()
    #                 pass
    #             finally:
    #                 task_queue.task_done()
    #     elif flag == "form":
    #     # checking xss via forms
    #         while True:
    #             try:
    #                 data = {}
    #                 form,url = await task_queue.get()
    #                 # get method from attribute
    #                 if form.attrib.get("method"):
    #                     method = form.attrib.get("method").lower()
    #                 # if not method attribute not found then use POST
    #                 else:
    #                     method = "POST".lower()
    #                 # extract url from action attr for form submission
    #                 try:
    #                     post_url = urljoin(url,form.attrib.get("action"))
    #                 # if action attr not found then use current page url as POST_url
    #                 except:
    #                     post_url = url
    #                 # filling values to all inputs of forms
    #                 submit = False
    #                 for input in form.xpath(".//input"):
    #                     if input.attrib.get("type") == "text":
    #                         data[f'{input.attrib.get("name")}'] = self.payload
    #                     elif input.attrib.get("type") == "password":
    #                         data[f"{input.attrib.get('name')}"] = "password"
    #                     elif input.attrib.get("type") == "hidden":
    #                         try:
    #                             value = input.attrib.get("value")
    #                         except:
    #                             data[f"{input.attrib.get('hidden')}"] = ""
    #                         else:
    #                             data[f"{input.attrib.get('hidden')}"] = value
    #                     elif input.attrib.get("type") == "submit":
    #                         submit = True
    #                         try:
    #                             value = input.attrib.get("value")
    #                         except:
    #                             data[f"{input.attrib.get('name')}"] = 'submit'
    #                         else:
    #                             data[f"{input.attrib.get('name')}"] = value
    #                     else:
    #                         data[f"{input.attrib.get('name')}"] = ''
    #                 # handling button input
    #                 if not submit:
    #                     try:
    #                         value = form.xpath(".//button").attrib.get("value")
    #                     except:
    #                         data[f"{form.xpath('.//button').attrib.get('name')}"] = 'submit'
    #                     else:
    #                         data[f"{form.xpath('.//button').attrib.get('name')}"] = value
    #                 # handling select input
    #                 if form.xpath(".//select"):
    #                     try:
    #                         name = form.xpath(".//select").attrib.get("name")
    #                     except:
    #                         name = ''
    #                     data[name] = self.payload
    #                 # post request
    #                 if method == 'post':
    #                     resp = await session.post(url,headers={"User-Agent":self.user_agent},data=data)
    #                 # get request
    #                 elif method == "get":
    #                     resp = await session.get(url,headers={"User-Agent":self.user_agent},params=data)
    #                 # self.r.print(data)
    #                 if self.payload in resp.text.lower():
    #                     print(f"\n[+] {Fore.GREEN}XSS Discovered in Form {url}{Fore.RESET}")
    #                     #print(data)
    #                     self.vulnerabilities["XSS"]["status"] = True
    #                     self.vulnerabilities["XSS"]["f-links"].append(url)
    #                 else:
    #                     pass
    #             except asyncio.CancelledError:
    #                 # self.r.print_exception()
    #                 pass
    #             finally:
    #                 task_queue.task_done()
        # r.save_html("/home/lubuntu/FYP/logs/xss_logs.html")
