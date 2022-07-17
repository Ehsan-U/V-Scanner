
# from rich.traceback import install
from rich.console import Console
# install()
r = Console()
from rich.table import Table
from random import random
import re
import sys
import threading
from queue import Queue
import time
from requests_html import HTMLSession
from requests.exceptions import ConnectionError, ConnectTimeout, ReadTimeout
from scrapy.selector import Selector
from urllib.parse import urlparse,urljoin,parse_qs
from colorama import init,Fore
from importlib_metadata import posixpath
from Misc import ignored_extensions
import hashlib


# import logging
# ###############logging##############
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# formatter = logging.Formatter("%(name)s %(levelname)s %(funcName)s %(message)s")
# handler = logging.FileHandler("/home/ubuntu/FYP/logs/crawler.log",mode='w')
# handler.setFormatter(formatter)
# logger.addHandler(handler)
####################################

class FYP_Crawler():
    def __init__(self,url,depth):
        self.start= time.perf_counter()
        self.target = url
        self.queue = Queue()
        self.urls = {"urls":set(),"hashes":[]}
        # 50 forms (latter used for csrf token checking)
        self.forms = {"forms":list(),'links':list(),"hashes":[]}
        # for storing orginal param links
        self.param_links = {"param_urls":set(),"hashes":[]}
        # for storing custom made param links
        self.check = True
        self.vulnerabilities = {
            "XSS":{'status':False,'p-links':[],'f-links':[],'data':[]},
            "SQLi":{'status':False,'p-links':[],'f-links':[],"sure":False,'data':[]},
            "CSRF":{"status":False,'f-links':[]},
            "ClickJacking":{"status":False}
            }
        self.allowed = urlparse(self.target).netloc
        # count how many links extracted from each response
        self.depth = depth

    # manage requests
    def manage_req(self,lock,url=None):
        session = HTMLSession()
        # first time follow given target
        if not url:
            if urlparse(url).query:
                self.param_links["param_urls"].add(url)            
            self.do_req(self.target,session,lock)
        # recursively follow urls
        elif url:
            lock.acquire(2)
            allowd = self.allowed
            lock.release()
                # allow only target domain
            if allowd == urlparse(url).netloc:
                self.do_req(url,session,lock)
            else:
                print(f"\n{Fore.RED}[+] Request Not Allowed {url}{Fore.RESET}")
                # logger.info("[+] Request Not Allowed")
        else:
            pass

    def test_url(self,url):
        path = urlparse(url).path
        # will return tuple ("/eg/eg/eg",".pdf")
        # extracting extension from url
        ext = posixpath.splitext(path)[1].lower()
        #lock.acquire(2)
        IGNORED_EXTENSIONS = ignored_extensions.IGNORED_EXTENSIONS
        #lock.release()
        for e in IGNORED_EXTENSIONS:
            if e == ext[1:]:
                return False
        return True

    # send requests
    def do_req(self,url,session,lock,try_once=True):
        allow_url = self.test_url(url)
        if allow_url:
            try:
                user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36'
                response = session.get(url,timeout=5,headers={"User-Agent":user_agent},allow_redirects=False)
            except (ConnectionError, ConnectTimeout, ReadTimeout) as e:
                print(f"\nCheck Your Internet {e} {url}")
                # logger.exception("Check Your Internet")
                # print("\nTry again in 5 sec")
                # logger.info("Try again in 5 sec")
                # time.sleep(5)
                pass
                if try_once:
                    self.do_req(url,session,lock,False)
                else:
                    return None
            else:
                print(f"\n[+] Request Sent to {url}")
                # logger.info(f"[+] Request Sent to {url}")
                # sending response to the parse for extracting links
                print(f"\n[+] Sending For Parsing {url}")
                # logger.info(f"[+] Sending For Parsing {url}")
                self.parse(url,response,lock,session)
        else:
            pass

    # parse the response
    def parse(self,url,response,lock,session):
        # limit on crawling max pages
        # creating selector object
        if not response.text == None:
            body = response.text
            selectr = Selector(text=body)

            if selectr.xpath("//a/@href"):
                self.extract_links(response,selectr,"//a/@href",lock,session)
            if selectr.xpath("//img/@src"):
                self.extract_links(response,selectr,"//img/@src",lock,session)
            if selectr.xpath("//frame/@src"):
                self.extract_links(response,selectr,"//frame/@src",lock,session)
            if selectr.xpath("//link/@href"):
                self.extract_links(response,selectr,"//link/@href",lock,session)

            # run once for each response
            self.extract_links_from_javascript(response,lock,session)
            lock.acquire(2)
            #print(f"{response.url} >> {self.count}")
            #count how many link extracted from each response
            check = self.check
            lock.release()
            # extracting forms
            if "</form>" in response.text:
                print(f"\n[+] Form Found {url}")
                # logger.info(f"[+] Form Found {url}")
                self.extract_forms(url,response,session,lock)
            # will run once to enable threading
            if check:
                if not self.queue.empty():
                    #print("\n[+] Starting Threading \n")
                    self.check = False
                    self.run(lock)
            #print(f"parse {response.url}")
        else:
            print("\n Response None ")
            # logger.info("Response None")

    # link extractor
    def extract_links(self,response,selectr,href,lock,session):
        # print("[+] Extracting links")
        for link in selectr.xpath(href).getall():
            url = urljoin(response.url,link)
            if self.test_url(url):
                lock.acquire(2)
                depth = self.depth
                if depth:
                    to_crawl = 5000
                else:
                    to_crawl = 500
                allowed = self.allowed
                urls = self.urls.get("urls")
                target = self.target
                lock.release()
                #if (allowed == urlparse(url).netloc and not url in urls) and (url != target) and (not ".ico" in url and not ".css" in url and not ".jpg" in url and not ".png" in url and not ".gif" in url and not ".pdf" in url and not ".jpeg" in url):
                if (allowed == urlparse(url).netloc and not url in urls) and (url != target):
                    lock.acquire(2)
                    if urlparse(url).query:
                        # print("checking uniqueness")
                        is_unique,url_id = self.unique(url)
                        # print("checking uniqueness done")
                        if is_unique:
                            if len(urls) < to_crawl:
                                self.urls['hashes'].append(url_id)
                                self.urls['urls'].add(url)
                                self.queue.put(url)
                                
                                self.param_links['hashes'].append(url_id)
                                self.param_links["param_urls"].add(url)
                        else:
                            pass
                    else:
                        if len(urls) < to_crawl:
                            self.urls['urls'].add(url)
                            self.queue.put(url)
                            
                    lock.release()
                    # if url has parameter
                    # if urlparse(url).query:
                    #     # process query link
                    #     self.query_link(url,lock)
                else:
                    continue
            else:
                continue

    # for extracting links from javascript e.g <scripts>
    def extract_links_from_javascript(self,response,lock,session):
        # print("[+] Extracting JS links")
        try:
            reg_obj = re.compile(r'(?:href = ")([a-zA-Z0-9.=?/_]*)')
            # returns list of strings
            links = set(reg_obj.findall(response.text))
            for link in links:
                url = urljoin(response.url,link)
                if self.test_url(url):
                    lock.acquire(2)
                    depth = self.depth
                    if depth:
                        to_crawl = 5000
                    else:
                        to_crawl = 500
                    allowed = self.allowed
                    urls = self.urls.get('urls')
                    target = self.target
                    lock.release()
                    #if (allowed == urlparse(url).netloc and not url in urls) and (url != target) and (not ".ico" in url and not ".css" in url and not ".jpg" in url and not ".png" in url and not ".gif" in url and not ".pdf" in url and not ".jpeg" in url):
                    if (allowed == urlparse(url).netloc and not url in urls) and (url != target):
                        print(f"\n[+] Regex link Found >> {url}")
                        # logger.info(f"[+] Regex link found >> {url}")
                        lock.acquire(2)
                        if urlparse(url).query:
                            # print("checking uniqueness")
                            is_unique,url_id = self.unique(url)
                            # print("checking uniqueness done")
                            if is_unique:
                                if len(urls) < to_crawl:
                                    self.urls['hashes'].append(url_id)
                                    self.urls['urls'].add(url)
                                    self.queue.put(url)
                                    
                                    self.param_links['hashes'].append(url_id)
                                    self.param_links["param_urls"].add(url)
                            else:
                                pass
                        else:
                            if len(urls) < to_crawl:
                                self.urls['urls'].add(url)
                                self.queue.put(url)
                                
                        lock.release()
                        # if url has parameter
                        # if urlparse(url).query:
                        #     # process query link
                        #     self.query_link(url,lock)
            #print(f"extract_links_from_javascript {response.url}")
        except:
            r.print_exception()
            # logger.exception("Error in Javascript link extraction")
    def unique(self,url):
        # returns query part as str
        # ignore fragment
        if "#" in url:
            url = url.split("#")[0]
        else:
            pass
        url_query = urlparse(url).query
        # handling parameters with no values
        url_query = url_query.replace("=", "=1")
        # returns dict, with key (paramter) value (corresponding parameter value)
        # e.g {"id":['value']}
        param_dict = parse_qs(url_query)
        # will return parameters as str
        # http://lms.ue.edu.pk/id=1&name=ehsan >> idehsan
        param_str = "".join(param_dict.keys())
        # building the url again
        # replace orig url query with param_str
        url = url.replace(urlparse(url).query,param_str)
        # unique value of url
        url_id = hashlib.md5(url.encode("utf-8")).hexdigest()
        # lock.acquire(2)
        if not url_id in self.urls.get('hashes') and not url_id in self.param_links.get("hashes"):
            # lock.release()
            return True,url_id
        else:
            # lock.release()
            return False,None

    # extract links that contain parameters
    # def query_link(self, url, lock):
    #     is_unique,url_id = self.unique(url,lock)
    #     if is_unique:
    #         lock.acquire(2)
    #         self.param_links['hashes'].append(url_id)
    #         self.param_links["param_urls"].add(url)
    #         lock.release()

    def extract_forms(self,url,response,session,lock):
        selector = Selector(text=response.text)
        # extract forms
        forms = selector.xpath("//form")
        lock.acquire(5)
        if len(self.forms.get("forms")) <=50:
            for form in forms:
                f_id = hashlib.md5(form.get().encode("utf-8")).hexdigest()
                if not f_id in self.forms.get("hashes"):
                    self.forms['hashes'].append(f_id)
                    self.forms['forms'].append(form)
                    self.forms['links'].append(url)
                else:
                    pass
        lock.release()

    # threading
    def run(self,lock):
        mythreads = []
        # quantity of threads depends on queue size
        # number of threads starts = queue size
        # then break the loop
        for i in range(120):
            url = self.queue.get()
            #print(f"Thread {i} started")
            t = threading.Thread(target=self.manage_req,args=(lock,url),daemon=True)
            mythreads.append(t)
            t.start()
            # its important!!!
            # break from loop when queue empty otherwise script stuck at last item
            # self.queue.task_done()
            if self.queue.empty():
                #print("\nQueue Empty!!!\n")
                break
        for thr in mythreads:
            thr.join()
        # check whether queue is empty, if not then continue
        if not self.queue.empty():
            end = time.perf_counter() - self.start
            if not self.depth and len(self.urls) <= 500:
                self.run(lock)
            elif self.depth and end < 300.0:
                if len(self.urls) <=5000:
                    self.run(lock)
                else:
                    print("\nTime Shortage\n")
        # r.save_html("/home/lubuntu/FYP/logs/crawler_logs.html")


# #
# checker = Header_Manipulation("https://ue.edu.pk")
# headers = checker.check_headers()
# start = time.perf_counter()
# crawl = FYP_Crawler("https://ue.edu.pk/",False,False,headers)
# lock = threading.Lock()
# try:
#     crawl.manage_req(lock)
#     print("\nFinishing")
#     #pprint(crawl.vulnerabilities)
#     print(time.perf_counter()-start)
# except (KeyboardInterrupt) as e:
#     print(f"\nQuiting..{e}")
#     print(f"\n{len(crawl.urls)}")
#     sys.exit()
