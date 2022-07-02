from urllib import request
from requests_html import HTMLSession
from urllib.parse import parse_qs, urlparse


user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
wp_domains = []
s = HTMLSession()

def wp_check(url):
    parsed_url = urlparse(url)
    url = parsed_url.scheme+"://"+parsed_url.netloc
    url = url + "/wp-admin/"
    return is_wp(url)
    
def is_wp(url):
    r = s.get(url,allow_redirects=True).text
    if "Powered by WordPress".lower() in r.lower():
        return True
    else:
        return False
