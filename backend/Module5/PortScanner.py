
import json
import select
import socket
import threading
import time
from urllib.parse import urlparse
from itsdangerous import exc
from rich.console import Console
import scapy.all as sc
import queue
import logging
###############logging##############
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# formatter = logging.Formatter("%(name)s %(levelname)s %(funcName)s %(message)s")
# handler = logging.FileHandler("/home/ubuntu/FYP/logs/port_scanner.log",mode='w')
# handler.setFormatter(formatter)
# logger.addHandler(handler)
####################################

class PortScanner():
    def __init__(self,url):
        self.HOST = socket.gethostbyname(urlparse(url).netloc)
        self.result = {}
        self.queue = queue.Queue()

    def main(self):
        lock = threading.Lock()
        self.fill_Q()
        self.run(lock)
        self.detect_os()

    def fill_Q(self):
        ports = self.load_ports()
        for port in ports:
            self.queue.put(port)

    def load_ports(self):
        with open("/home/ubuntu/backend/ports.json","r") as f:
            top_1000_str = json.load(f)
            # return list
            ports = json.loads(top_1000_str)
            print('loaded')
        return ports

    def connection(self,host,port,lock):
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                result = s.connect_ex((host,port))
                if result == 0:
                    print(port,' OPEN')
                    try:
                        banner = s.recv(1024).decode()
                    except:
                        banner = 'None'
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'None'
                    lock.acquire(2)
                    self.result[f"{port}"] = {"status":'Open',"service":service,'banner':banner}
                    lock.release()
                else:
                    # print(port,' CLOSED')
                    pass
            except:
                pass
                
    def detect_os(self):
        l3 = sc.IP(dst=self.HOST)
        l4 = sc.TCP(dport=80,sport=sc.RandShort(),flags="S")
        pkt = l3/l4
        try:
            ans = sc.sr1(pkt,timeout=2,verbose=False)
            if "SA" in str(ans['TCP'].flags):
                if ans["IP"].ttl > 64 and ans["IP"].ttl <=128:
                    self.result["os"] = 'Windows'
                elif ans["IP"].ttl <= 64:
                    self.result["os"] = "Linux"
                elif ans["IP"].ttl > 128 and ans["IP"].ttl <=255:
                    self.result["os"] = "Cisco"
                else:
                    self.result["os"] = "Unknown"
        except:
            pass

    def start_scan(self):
        try:
            self.main()
        except:
            return {"port-scanner":self.result}
        else:
            return {"port-scanner":self.result}
        

    def run(self,lock):
        host = self.HOST
        threads = []
        for i in range(100):
            port = self.queue.get()
            t = threading.Thread(target=self.connection,args=(host,port,lock))
            t.daemon = True
            threads.append(t)
            t.start()
            if self.queue.empty():
                break
        for th in threads:
            th.join()
        if not self.queue.empty():
            self.run(lock)


    # async def main(self):
    #     # print("\rPort scanning starting",end="")
    #     try:
    #         # queue for tasks
    #         task_queue = asyncio.Queue(maxsize=self.MAX_WORKERS)
    #         # queue for complete tasks
    #         # out_queue = asyncio.Queue()
    #         scan_completed = asyncio.Event()
    #         # flag set to False
    #         scan_completed.clear()
    #         tasks = []
    #         # filling task added
    #         qfill_task = asyncio.create_task(self.task_master(task_queue,scan_completed))
    #         tasks.append(qfill_task)
    #         # connection task
    #         for _ in range(self.MAX_WORKERS):
    #             task = asyncio.create_task(self.connection(task_queue))
    #             tasks.append(task)
    #         # wait until filling complete
    #         await scan_completed.wait()
    #         # wait until all (tasks) processed
    #         await task_queue.join()
    #         # cancel tasks that are not complete yet
    #         for task in tasks:
    #             task.cancel()
    #         print("gathering output")
    #         # logger.info("gathering output")
    #         # cancel() will raise exception CancellError, so return_exception should must True     
    #         await asyncio.gather(*tasks,return_exceptions=True)
    #         # print(task_queue.qsize())
    #     except Exception as e:
    #         print(e)

    # def load_ports(self):
    #     with open("/home/ubuntu/PycharmProjects/V/FYP/backend/ports.json","r") as f:
    #         top_1000_str = json.load(f)
    #         # return list
    #         ports = json.loads(top_1000_str)
    #         print('loaded')
    #     return ports
    # # fill queue
    # async def task_master(self,task_queue,scan_completed):
    #     top_1000 = self.load_ports()
    #     for port in top_1000:
    #         await task_queue.put(port)
    #     # flag set to True
    #     scan_completed.set()

    # async def connection(self,task_queue):
    #     while True:
    #         port = await task_queue.get()
    #         conn = asyncio.open_connection(self.HOST,port)
    #         try:
    #             # for closed ports it will not wait for 10, only for that expected to open
    #             reader,writer = await asyncio.wait_for(conn,1)
    #             service = socket.getservbyport(port)
    #             self.result[f"{port}"] = {"status":'Open',"service":service,'banner':'None'}
    #         except Exception as e:
    #             # task_queue.task_done()
    #             # print(port)
    #             pass
    #         else:
    #             # task_queue.task_done()
    #             self.con.print(f"{port}")
    #             writer.write_eof()
    #             self.con.print(f"{port} done")
    #             if not reader.at_eof():
    #                 # oh issue resolved, it was stuck here because mene ny read pe timeout ni lgaya tha
    #                 banner = await asyncio.wait_for(reader.read(100),1)
    #                 if banner:
    #                     self.result[f"{port}"]['banner'] = banner.decode()
                
    #             # Indicate that a formerly enqueued task is complete
    #             # if program stuck, its due to wrong placement of below line
    #         finally:
    #             task_queue.task_done()
                

    # def detect_os(self):
    #     l3 = sc.IP(dst=self.HOST)
    #     l4 = sc.TCP(dport=80,sport=sc.RandShort(),flags="S")
    #     pkt = l3/l4
    #     try:
    #         ans = sc.sr1(pkt,timeout=2,verbose=False)
    #         if "SA" in str(ans['TCP'].flags):
    #             if ans["IP"].ttl > 64 and ans["IP"].ttl <=128:
    #                 self.result["os"] = 'Windows'
    #             elif ans["IP"].ttl <= 64:
    #                 self.result["os"] = "Linux"
    #             elif ans["IP"].ttl > 128 and ans["IP"].ttl <=255:
    #                 self.result["os"] = "Cisco"
    #             else:
    #                 self.result["os"] = "Unknown"
    #     except:
    #         pass

    # def start_scan(self):
    #     try:
    #         asyncio.run(self.main())
    #         # asyncio.run(self.main())
    #         self.detect_os()
    #     except:
    #         self.con.print_exception()
    #         return {"port-scanner":self.result}
    #     else:
    #         # self.con.print(self.result)
    #         return {"port-scanner":self.result}
        
