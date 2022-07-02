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
import requests
resp = requests.get("http://www.aiou.edu.pk/")
print(resp.text)