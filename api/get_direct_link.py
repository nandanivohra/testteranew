from http.server import BaseHTTPRequestHandler
import json
import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import unquote, quote
import traceback
import sys
from concurrent.futures import ThreadPoolExecutor

def get_formatted_size(size: int) -> str:
    return "{:.2f} GB".format(size / (1024 ** 3)) if size >= 1024 ** 3 else "{:.2f} MB".format(size / (1024 ** 2)) if size >= 1024 ** 2 else "{:.2f} KB".format(size / 1024) if size >= 1024 else f"{size} B"

class TERABOX:
    def __init__(self, url: str, ndus: str):
        self.surl = url.split("?surl=")[-1].rsplit("/", 1)[-1]
        if self.surl[0] != "1":
            self.surl = "1" + self.surl
        self.headerList = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127",
                           'Accept-Encoding': 'gzip, deflate, sdch',
                            'Accept-Language': 'en-US,en;q=0.8',
                            'Upgrade-Insecure-Requests': '1',
                            "Content-Type": "application/x-www-form-urlencoded",
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                            'Cache-Control': 'max-age=0',
                            'Connection': 'keep-alive',
                            'Server': 'dubox'}
        self.cookies = {"ndus": ndus}
        self.client = None
        self.jsToken = None
        self.sign = None
        self.timestamp = None
        self.to_file = None
        self.to_fs = None

    async def initialize_client(self):
        self.client = httpx.AsyncClient(headers=self.headerList, cookies=self.cookies)

    def encrypt1(self, j, r):
        a = [0] * 256
        p = [0] * 256
        o = ""
        v = len(j)

        for q in range(256):
            a[q] = ord(chr(j[(q % v)]))
            p[q] = q

        u = 0
        for q in range(256):
            u = (u + p[q] + a[q]) % 256
            t = p[q]
            p[q] = p[u]
            p[u] = t

        i = 0
        u = 0
        for q in range(len(r)):
            i = (i + 1) % 256
            u = (u + p[i]) % 256
            t = p[i]
            p[i] = p[u]
            p[u] = t
            k = p[((p[i] + p[u]) % 256)]
            o += chr(r[q] ^ k)

        return o

    def encrypt2(self, t):
        s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        t_len = len(t)
        o = 0
        e = ""

        while o < t_len:
            n = ord(t[o])
            o += 1

            if o == t_len:
                e += s[n >> 2]
                e += s[(n & 0x3) << 4]
                e += "=="
                break

            a = ord(t[o])
            o += 1

            if o == t_len:
                e += s[n >> 2]
                e += s[((n & 0x3) << 4) | ((a & 0xF0) >> 4)]
                e += s[(a & 0xF) << 2]
                e += "="
                break

            c = ord(t[o])
            o += 1

            e += s[n >> 2]
            e += s[((n & 0x3) << 4) | ((a & 0xF0) >> 4)]
            e += s[((a & 0xF) << 2) | ((c & 0xC0) >> 6)]
            e += s[c & 0x3F]

        return e
    
    async def get_jsToken(self):
        response = await self.client.get("https://www.terabox1024.com/main?category=3&vmode=grid")
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for fs in soup.find_all('script'):
                fstring = fs.string
                if fstring and fstring.startswith('try {eval(decodeURIComponent'):
                    self.jsToken = fstring.split('%22')[1]
                    return self.jsToken
        raise Exception("Unable to extract jsToken")
    
    async def get_surl_data(self):
        res = await self.client.get(f"https://nephobox.com/api/shorturlinfo?type=0&root=1&shorturl={self.surl}")
        res = res.json()
        if res["errno"] != 0:
            print(str(res))
            raise Exception("Unable to get surl data")
        if int(res["list"][0]["isdir"]) == 1:
            raise Exception("Can't download folders")
        return res
    
    async def get_sign(self):
        res = await self.client.get("https://www.terabox1024.com/api/home/info?app_id=250528&web=1&channel=dubox&clienttype=0")
        if res.status_code != 200:
            print(res.text)
            raise Exception("Unable to get sign")
        res = res.json()["data"]
        self.sign = self.encrypt2(self.encrypt1(res["sign3"].encode(), res["sign1"].encode()))
        self.timestamp = res["timestamp"]
    
    async def get_dlink(self):
        await self.get_sign()
        res = await self.client.post(f"https://www.terabox1024.com/api/download?app_id=250528&web=1&channel=dubox&clienttype=0&jsToken={self.jsToken}&fidlist=%5B{self.to_fs}%5D&type=dlink&vip=2&sign={quote(self.sign)}&timestamp={self.timestamp}")
        res = res.json()
        if res["errno"] != 0:
            print(res)
            raise Exception("Unable to get dlink")
        return res["dlink"][0]["dlink"]
    
    async def get_data(self):
        try:
            await self.initialize_client()
            surl_d = await self.get_surl_data()
            surl_data = surl_d['list'][0]
            await self.get_jsToken()
            res = await self.client.post(f"https://www.terabox.app/share/transfer?app_id=250528&web=1&channel=dubox&clienttype=0&jsToken={self.jsToken}&ondup=newcopy&async=2&scene=purchased_list&shareid={surl_d['shareid']}&from={surl_d['uk']}",
                                    data={"fsidlist":f'["{surl_data["fs_id"]}"]',
                                            "path":"/"})
            res = res.json()
            if res["errno"] != 0:
                print("Id: ", self.surl, "\n", res)
                raise Exception("Unable to copy file")
            res = res["extra"]["list"][0]
            self.to_fs = res["to_fs_id"]
            self.to_file = quote(res["to"]).replace("/", "%2F")
            dlink = await self.get_dlink()
            data = {
                "file_name": surl_data["server_filename"],
                "link": dlink,
                "direct_link": dlink,
                "thumb": surl_data["thumbs"]["url3"],
                "size": get_formatted_size(int(surl_data["size"])),
                "sizebytes": int(surl_data["size"]),
            }
        except Exception as e:
            raise e
        finally:
            if self.client:
                await self.client.aclose()
        return data

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON data")
            return

        url = data.get('url')
        ndus = 'YVdDweMteHuiVYLbP69_hrP22GWkojmjB_Swa9lY'  # Replace with your actual ndus value

        if not url:
            self.send_error(400, "Missing URL parameter")
            return

        try:
            def run_async_code():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                terabox = TERABOX(url, ndus)
                return loop.run_until_complete(terabox.get_data())

            with ThreadPoolExecutor() as executor:
                result = executor.submit(run_async_code).result()

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        except Exception as e:
            error_message = f"An error occurred: {str(e)}\n\nTraceback:\n{''.join(traceback.format_exception(type(e), e, e.__traceback__))}"
            print(error_message, file=sys.stderr)
            
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e), "traceback": error_message}).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header("Access-Control-Allow-Headers", "X-Requested-With, Content-Type")
        self.end_headers()
