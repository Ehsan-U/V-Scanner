# import posixpath
# from urllib.parse import urlparse
# import Misc.ignored_extensions as ignored_extensions
# import pytest

# @pytest.mark.is_url_allowed
# def test_url(url="https://lms.ue.edu.pk/sample.pdf"):
#         path = urlparse(url).path
#         # will return tuple ("/eg/eg/eg",".pdf")
#         # extracting extension from url
#         ext = posixpath.splitext(path)[1].lower()
#         #lock.acquire(2)
#         IGNORED_EXTENSIONS = ignored_extensions.IGNORED_EXTENSIONS
#         #lock.release()
#         for e in IGNORED_EXTENSIONS:
#             if e == ext[1:]:
#                 allow = False
#                 break
#             else:
#                 allow = True
#         assert allow == True
# from itertools import count
# from multiprocessing import Process

# counter = count(0)
# def get_Tech():
#     from builtwith import builtwith
#     resp = builtwith("https://www.olx.com.pk/")
#     print(resp)
# print(__name__)
# if __name__ == '__main__':
#     p1 = Process(target=get_Tech,name='tech')
#     p1.start()
#     p1.join(timeout=2)
#     p1.terminate()
# if p1.exitcode == 0:
#     print("YES")
# elif p1.exitcode == None:
#     print("NO")
# from requests_html import HTMLSession
# s = HTMLSession()
# proxy = {
#     'http':'147.182.207.3:3128',
#     'https':'147.182.207.3:3128',
# }
# resp = s.get('https://httpbin.org/ip',proxies=proxy)
# print(resp.text)
# import socket
# def connection(host,port):
#     port = 2121
#     host = "45.60.24.237"
#     s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#     s.settimeout(1)
#     try:
#         result = s.connect((host,port))
#         print('sss')
#         # if result == 0:
#         #     print(port,' OPEN')
#         # else:
#         #     print(port,' CLOSED')
#         #     pass
#     except:
#         pass

# connection(None,None)