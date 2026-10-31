#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tidecoin Stratum-to-GBT Solo Mining Proxy (bugfix v9, dual-stack)

相对 v8 的关键修复：
  ★ cb1/cb2 使用精确边界，不再依赖魔数 42
  ★ witness commitment 全程贯通（update / submit / 拼块）
  ★ submit 拼块使用含 witness 的 coinbase 序列化
  ★ 删除 difficulty *10 残留，share 难度与网络难度分离
  ★ merkle branch 输出显示序 hex（主流矿工约定）
  ★ merkle branch 奇数补齐前先判索引，避免越界
  ★ RPC cookie 重载路径明确化
  ★ 保留原有调试开关

本版新增：
  ★ Stratum 监听改为双栈（IPv4 + IPv6 同时监听）
"""

import json, socket, threading, struct, requests, ctypes, time, hashlib, os, traceback

# ==================== 配置 ====================
# RPC：取决于节点 rpcbind。
#   节点只监听 IPv4 -> "http://127.0.0.1:7585"
#   节点监听 IPv6 -> "http://[::1]:7585"
RPC_URL = "http://127.0.0.1:7585"
COOKIE_PATH = os.environ.get("TDC_COOKIE", os.path.expanduser("~/.tidecoin/.cookie"))
RPC_USER = os.environ.get("TDC_RPC_USER")
RPC_PASS = os.environ.get("TDC_RPC_PASS")
TDC_ADDRESS = "TYOURTDCADDRESS"

# Stratum 监听："::" + IPV6_V6ONLY=0 实现双栈（IPv4/IPv6 同一端口）
STRATUM_HOST, STRATUM_PORT = "::", 3333

EXTRANONCE1 = "08000000"
EXTRANONCE2_SIZE = 4
COINBASE_TAG = b"/TidecoinProxy/"
OK_DIFF_BEISHU = 80000

# share 难度：
#   None  -> 使用网络难度（solo 极端模式：找到块才算 share）
#   数字  -> 固定 share 难度（推荐，例如 0.1 或 1.0）
# 注意：share 难度应 ≤ 网络难度；设为网络难度的 1/N 可让矿工持续提交 share。
SHARE_DIFF = 0.0002

DEBUG_PRINT_SHARES = True
DEBUG_DETAIL = False
DEBUG_STRATUM = False
NONCE_FORMAT = "int"   # "int" = 大端 hex 整型回传 | "bytes" = 原始 header 字节 hex

# ==================== Yespower 库绑定 ====================
class YespowerTIDE:
    def __init__(self, lib_path="./libyespower_tide.so"):
        self.lib = ctypes.CDLL(lib_path)
        self.lib.yespower_tide_hash.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.yespower_tide_hash.restype = ctypes.c_int

    def hash(self, header_bytes: bytes) -> bytes:
        assert len(header_bytes) == 80
        inp = (ctypes.c_ubyte * 80).from_buffer_copy(header_bytes)
        out = (ctypes.c_ubyte * 32)()
        if self.lib.yespower_tide_hash(inp, out) != 0:
            raise RuntimeError("yespower_tide_hash failed")
        return bytes(out)

# ==================== 工具函数 ====================
def bits_to_target(bits_hex: str) -> int:
    b = int(bits_hex, 16); e = b >> 24; m = b & 0x007fffff
    return m >> (8 * (3 - e)) if e <= 3 else m << (8 * (e - 3))

def target_to_difficulty(target: int) -> float:
    diff1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    return diff1 / target if target else 0.0

def double_sha256(d: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(d).digest()).digest()

def swap4(b: bytes) -> bytes:
    """Swap bytes inside every 32-bit word (stratum prevhash order)."""
    return b''.join(b[i:i+4][::-1] for i in range(0, len(b), 4))

def serialize_height(h: int) -> bytes:
    if h == 0: return b'\x00'
    r = bytearray()
    while h > 0:
        r.append(h & 0xff); h >>= 8
    if r[-1] & 0x80:
        r.append(0x00)
    return bytes([len(r)]) + bytes(r)

def varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def merkle_root(hashes):
    if not hashes: return b'\x00' * 32
    hashes = list(hashes)
    while len(hashes) > 1:
        if len(hashes) % 2: hashes.append(hashes[-1])
        hashes = [double_sha256(hashes[i] + hashes[i+1]) for i in range(0, len(hashes), 2)]
    return hashes[0]

def compute_merkle_branch(hashes, index=0):
    """返回内部序（小端）的 branch 列表。奇数补齐前先判断索引，避免越界。"""
    branch = []
    hashes = list(hashes)
    while len(hashes) > 1:
        if len(hashes) % 2:
            hashes.append(hashes[-1])
        sibling = hashes[index ^ 1] if (index ^ 1) < len(hashes) else hashes[-1]
        branch.append(sibling)
        hashes = [double_sha256(hashes[i] + hashes[i+1]) for i in range(0, len(hashes), 2)]
        index //= 2
    return branch

def assemble_header(version, prev, merkle, ntime_bytes, bits_bytes, nonce_bytes):
    assert len(prev) == 32 and len(merkle) == 32
    assert len(ntime_bytes) == 4 and len(bits_bytes) == 4 and len(nonce_bytes) == 4
    return struct.pack("<I", version & 0xffffffff) + prev + merkle + ntime_bytes + bits_bytes + nonce_bytes

def build_coinbase(height, value, script, en1, en2, tag=COINBASE_TAG, witness_commitment=None):
    """构造 coinbase。

    返回 dict:
      - tx_nowitness: 不含 marker/flag/witness 的序列化（用于计算 txid）
      - txid:         double_sha256(tx_nowitness)
      - tx_witness:   含 witness 的序列化（用于打包进区块）
      - cb1:          scriptSig 中 en2 之前的固定前缀（height 结束处）
      - cb2:          scriptSig 中 en2 之后的固定后缀
      - ss_len:       scriptSig 总长度
    """
    height_ser = serialize_height(height)
    ss = height_ser + en1 + en2 + tag
    if not (2 <= len(ss) <= 106):
        raise ValueError(f"scriptSig 长度越界: {len(ss)}")

    outputs = [(value, script)]
    if witness_commitment:
        wc = bytes.fromhex(witness_commitment) if isinstance(witness_commitment, str) else witness_commitment
        outputs.append((0, wc))

    def ser_outputs():
        return varint(len(outputs)) + b''.join(
            struct.pack('<Q', v) + varint(len(s)) + s for v, s in outputs)

    prefix = struct.pack('<I', 1)
    vin = varint(1) + b'\x00' * 32 + b'\xff\xff\xff\xff' + varint(len(ss)) + ss + b'\xff\xff\xff\xff'
    locktime = b'\x00\x00\x00\x00'

    tx = prefix + vin + ser_outputs() + locktime
    txid = double_sha256(tx)

    if witness_commitment:
        tx_witness = (prefix + b'\x00\x01' + vin + ser_outputs() +
                      varint(1) + varint(32) + b'\x00' * 32 + locktime)
    else:
        tx_witness = tx

    # 精确切分：cb1 = 到 height 结束（含 height varint 及其字节）
    # 结构：[version 4][vin_cnt 1][prevout 32][prevout_idx 4][ss_len varint][ss...]
    ss_data_start = 4 + 1 + 32 + 4 + len(varint(len(ss)))
    cb1_end = ss_data_start + len(height_ser)
    cb1 = tx[:cb1_end]
    cb2_start = cb1_end + len(en1) + len(en2)
    cb2 = tx[cb2_start:]

    return {
        "tx_nowitness": tx,
        "txid": txid,
        "tx_witness": tx_witness,
        "cb1": cb1,
        "cb2": cb2,
        "ss_len": len(ss),
    }

# ==================== RPC 客户端 ====================
class RPC:
    def __init__(self):
        self.s = requests.Session()
        self.lock = threading.Lock()
        self.auth = None
        self.load_auth()

    def load_auth(self):
        """每次调用都尝试重读 cookie 文件；读不到再退回 user/pass。"""
        try:
            with open(COOKIE_PATH, "r") as f:
                data = f.read().strip()
            if ":" in data:
                self.auth = tuple(data.split(":", 1))
                return
        except OSError:
            pass
        if RPC_USER is not None:
            self.auth = (RPC_USER, RPC_PASS or "")
        else:
            self.auth = None

    def call(self, m, p=None):
        payload = {"jsonrpc": "1.0", "id": "proxy", "method": m, "params": p or []}
        with self.lock:
            for attempt in (0, 1):
                if self.auth is None:
                    self.load_auth()
                try:
                    r = self.s.post(RPC_URL, auth=self.auth or ("", ""),
                                    json=payload, timeout=30)
                except requests.RequestException as e:
                    print(f"[RPC] {m} 连接失败: {e}")
                    return None
                if r.status_code in (401, 403) and attempt == 0:
                    print(f"[RPC] {m} 认证失败，重新读取 cookie ...")
                    self.load_auth()
                    continue
                try:
                    res = r.json()
                except ValueError:
                    print(f"[RPC] {m} 返回非 JSON (HTTP {r.status_code})")
                    return None
                if res.get("error"):
                    print(f"[RPC] {m}: {res['error']}")
                    return None
                return res.get("result")
        return None

    def gbt(self):
        return self.call("getblocktemplate", [{"rules": ["segwit"]}])
    def submit(self, hexblock):
        return self.call("submitblock", [hexblock])
    def getrawtx(self, txid):
        return self.call("getrawtransaction", [txid, False])
    def validateaddress(self, addr):
        return self.call("validateaddress", [addr])

# ==================== Stratum 客户端 ====================
class Client(threading.Thread):
    def __init__(self, conn, addr, proxy):
        super().__init__(daemon=True)
        self.conn, self.proxy = conn, proxy
        # IPv6 accept 返回 4 元组，归一化为 (host, port) 便于日志
        self.addr = addr[:2] if isinstance(addr, tuple) and len(addr) >= 2 else addr
        self.buf = b""
        self.auth = False
        self.en1 = bytes.fromhex(EXTRANONCE1)
        self.slock = threading.Lock()

    def run(self):
        try:
            while True:
                d = self.conn.recv(4096)
                if not d:
                    break
                self.buf += d
                while b"\n" in self.buf:
                    line, self.buf = self.buf.split(b"\n", 1)
                    if line.strip():
                        try:
                            self.handle(json.loads(line))
                        except Exception as e:
                            print(f"[Client] handle 异常: {e}")
                            traceback.print_exc()
        except Exception as e:
            print(f"[Client] recv 异常: {e}")
        finally:
            print(f"[Client] 断开 {self.addr}")
            try:
                self.conn.close()
            except Exception:
                pass
            self.proxy.remove(self)

    def send(self, o):
        try:
            s = json.dumps(o)
            if DEBUG_STRATUM:
                print(f"[SEND->{self.addr}] {s[:500]}{'...' if len(s) > 500 else ''}")
            with self.slock:
                self.conn.sendall((s + "\n").encode())
        except Exception as e:
            print(f"[SEND] 异常: {e}")

    def handle(self, msg):
        m, i = msg.get("method"), msg.get("id")
        if DEBUG_STRATUM:
            print(f"[RECV<-{self.addr}] method={m} id={i} params={str(msg.get('params'))[:300]}")

        if m == "mining.subscribe":
            self.send({
                "id": i,
                "result": [
                    [["mining.set_difficulty", "d1"], ["mining.notify", "j1"]],
                    self.en1.hex(),
                    EXTRANONCE2_SIZE
                ],
                "error": None
            })
        elif m == "mining.authorize":
            self.auth = True
            self.send({"id": i, "result": True, "error": None})
            self.proxy.send_diff_and_job(self)
        elif m == "mining.submit":
            p = msg.get("params", [])
            if len(p) >= 5:
                ok = self.proxy.submit(self, p[1], p[2], p[3], p[4])
                self.send({"id": i, "result": bool(ok),
                           "error": None if ok else [23, "low difficulty share", None]})
            else:
                self.send({"id": i, "result": False, "error": [20, "bad params", None]})
        elif m == "mining.extranonce.subscribe":
            self.send({"id": i, "result": True, "error": None})

    def job(self, j):
        self.send({"id": None, "method": "mining.notify", "params": [
            j["id"],
            swap4(j["prev_bytes"]).hex(),
            j["cb1"].hex(), j["cb2"].hex(), j["branch"],
            "%08x" % (j["vi"] & 0xffffffff),
            j["bits_hex"],
            "%08x" % (j["ntime_int"]),
            True
        ]})

# ==================== 代理主控 ====================
class Proxy:
    def __init__(self):
        self.rpc = RPC()
        self.pow = YespowerTIDE("./libyespower_tide.so")
        self.clients, self.cl = [], threading.Lock()
        self.cur, self.jl = None, threading.Lock()
        self.cnt = 0
        self.net_target = 0
        self.net_diff = 0.0
        self.share_diff = 0.0
        self.share_target = 0
        self.script = self._resolve_script(TDC_ADDRESS)

    def _resolve_script(self, addr):
        info = self.rpc.validateaddress(addr)
        if not info:
            raise RuntimeError(f"validateaddress 失败: {addr}")
        spk = info.get("scriptPubKey")
        if not spk:
            raise RuntimeError(f"validateaddress 未返回 scriptPubKey: {info}")
        print(f"[Addr] {addr} -> scriptPubKey={spk}")
        return bytes.fromhex(spk)

    def add(self, c):
        with self.cl:
            self.clients.append(c)

    def remove(self, c):
        with self.cl:
            if c in self.clients:
                self.clients.remove(c)

    def send_diff_and_job(self, c):
        with self.jl:
            j = self.cur
            diff = self.share_diff
        print(f"[send_diff_and_job] cur={'None' if j is None else j['id']} diff={diff}")
        if j is not None:
            c.send({"id": None, "method": "mining.set_difficulty", "params": [diff * OK_DIFF_BEISHU]})
            c.job(j)
        else:
            print("[send_diff_and_job] ★ cur 为 None，未发送任何任务！")

    def broadcast(self, j):
        with self.cl:
            cs = list(self.clients)
        print(f"[broadcast] job={j['id']} 客户端数={len(cs)} 已授权={sum(1 for c in cs if c.auth)}")
        for c in cs:
            if c.auth:
                c.job(j)

    def update(self):
        t = self.rpc.gbt()
        if not t:
            print("[update] ★ GBT 返回空！")
            return
        try:
            h, v = t["height"], t["version"]
            prev_hex = t["previousblockhash"]
            with self.jl:
                if self.cur and self.cur.get("prevhex") == prev_hex:
                    return

            prev_bytes = bytes.fromhex(prev_hex)[::-1]
            bits = t["bits"]
            ntime_int = t["curtime"]
            val = t.get("coinbasevalue", 0)
            txs = t.get("transactions", [])
            wcm = t.get("default_witness_commitment")

            en1 = bytes.fromhex(EXTRANONCE1)
            dummy_en2 = b'\x00' * EXTRANONCE2_SIZE
            cb_info = build_coinbase(h, val, self.script, en1, dummy_en2,
                                     witness_commitment=wcm)
            cbh = cb_info["txid"]

            txids = [bytes.fromhex(x["txid"])[::-1] for x in txs]
            branch_hashes = compute_merkle_branch([cbh] + txids, 0)
            branch_hex = [bh[::-1].hex() for bh in branch_hashes]

            raw = []
            for x in txs:
                if "data" in x:
                    raw.append(bytes.fromhex(x["data"]))
                else:
                    d = self.rpc.getrawtx(x["txid"])
                    if not d:
                        print(f"[update] getrawtransaction 失败: {x['txid']}")
                        return
                    raw.append(bytes.fromhex(d))

            self.cnt += 1
            jid = f"job{self.cnt}"
            bi = int(bits, 16)
            j = {
                "id": jid,
                "prevhex": prev_hex,
                "prev_bytes": prev_bytes,
                "cb1": cb_info["cb1"],
                "cb2": cb_info["cb2"],
                "branch": branch_hex,
                "ver": "%08x" % (v & 0xffffffff),
                "bits_hex": bits,
                "ntime_int": ntime_int,
                "height": h,
                "val": val,
                "txh": txids,
                "vi": v,
                "bits_bytes": struct.pack("<I", bi),
                "script": self.script,
                "raw": raw,
                "wcm": wcm,
                "cbh_dummy": cbh,
                "txids_hex": [x["txid"] for x in txs],
            }
            with self.jl:
                self.cur = j
                self.net_target = bits_to_target(bits)
                self.net_diff = target_to_difficulty(self.net_target)
                if SHARE_DIFF is None:
                    self.share_diff = self.net_diff
                else:
                    self.share_diff = float(SHARE_DIFF)
                self.share_target = int(0x00000000FFFF0000000000000000000000000000000000000000000000000000 / self.share_diff) if self.share_diff > 0 else self.net_target

            print(f"[Job] 区块 {h} jid={jid} net_diff={self.net_diff:.6f} "
                  f"share_diff={self.share_diff:.6f} 交易={len(txs)} "
                  f"witness_commitment={'有' if wcm else '无'}")
            if DEBUG_DETAIL:
                print(f"[Job] cb1={j['cb1'].hex()} cb2={j['cb2'].hex()}")
                print(f"[Job] branch={j['branch']}")

            for c in self.clients:
                if c.auth:
                    c.send({"id": None, "method": "mining.set_difficulty",
                            "params": [self.share_diff * OK_DIFF_BEISHU]})
            self.broadcast(j)
        except Exception as e:
            print(f"[Job] 异常: {e}")
            traceback.print_exc()

    def submit(self, c, jid, en2_hex, ntime_hex, nonce_hex):
        with self.jl:
            j = self.cur
            share_tgt = self.share_target
            net_tgt = self.net_target
            net_diff = self.net_diff
        if not j or j["id"] != jid:
            print(f"[Submit] job 不匹配: cur={'None' if j is None else j['id']} got={jid}")
            return False
        try:
            en2 = bytes.fromhex(en2_hex)
            if len(en2) != EXTRANONCE2_SIZE:
                print(f"[Submit] en2 长度错误: {len(en2)}")
                return False

            cb_info = build_coinbase(j["height"], j["val"], j["script"],
                                     c.en1, en2, witness_commitment=j["wcm"])
            cb_nowit = cb_info["tx_nowitness"]
            cb_wit = cb_info["tx_witness"]
            cbh = cb_info["txid"]
            mr = merkle_root([cbh] + j["txh"])

            cb_rebuild = j["cb1"] + c.en1 + en2 + j["cb2"]
            cb_match = (cb_rebuild == cb_nowit)

            nt_bytes = struct.pack("<I", int(ntime_hex, 16))
            if NONCE_FORMAT == "bytes":
                no_bytes = bytes.fromhex(nonce_hex)
                if len(no_bytes) != 4:
                    print(f"[Submit] nonce bytes 长度错误: {len(no_bytes)}")
                    return False
            else:
                no_bytes = struct.pack("<I", int(nonce_hex, 16))
            bits_bytes = struct.pack("<I", int(j["bits_hex"], 16))
            hdr = assemble_header(j["vi"], j["prev_bytes"], mr, nt_bytes,
                                  bits_bytes, no_bytes)

            hbytes = self.pow.hash(hdr)
            hval = int.from_bytes(hbytes, "little")
            share_actual = target_to_difficulty(hval) if hval else 0.0

            if DEBUG_PRINT_SHARES:
                print(f"[Share] job={jid} en2={en2_hex} nonce={nonce_hex} "
                      f"hash={hbytes[::-1].hex()} diff={share_actual:.8f} "
                      f"/share={self.share_diff:.6f} /net={net_diff:.6f}")
            if DEBUG_DETAIL:
                print(f"[Debug] cb_match={cb_match} cbh={cbh.hex()} mr={mr.hex()}")
                print(f"[Debug] header={hdr.hex()}")
                if not cb_match:
                    print("[Debug] ★★★ cb1+en1+en2+cb2 与代理重建的 coinbase 不一致！★★★")

            if hval > share_tgt:
                return False

            if hval <= net_tgt:
                print(f"[Submit] ✅ 达到网络难度! nonce={nonce_hex} hash={hbytes[::-1].hex()}")
                block = hdr + varint(1 + len(j["raw"])) + cb_wit + b''.join(j["raw"])
                r = self.rpc.submit(block.hex())
                print("[Submit] 提交成功" if r is None else f"[Submit] 失败: {r}")

            return True
        except Exception as e:
            print(f"[Submit] 异常: {e}")
            traceback.print_exc()
            return False

    def loop(self):
        while True:
            try:
                self.update()
            except Exception as e:
                print(f"[Loop] {e}")
                traceback.print_exc()
            time.sleep(5)

    def run(self):
        print("[run] 首次同步 update() ...")
        self.update()
        with self.jl:
            print(f"[run] 首次 update 后 cur={'None' if self.cur is None else self.cur['id']}")
        threading.Thread(target=self.loop, daemon=True).start()

        # ---- 双栈监听：AF_INET6 + IPV6_V6ONLY=0 ----
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # V6ONLY 必须在 bind 之前设置；0 = 同时接受 IPv4 映射地址
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind((STRATUM_HOST, STRATUM_PORT))
        s.listen(5)
        print(f"[Proxy] Stratum(dual-stack): [{STRATUM_HOST}]:{STRATUM_PORT} | RPC: {RPC_URL}")
        while True:
            c, a = s.accept()
            print(f"[Accept] 新连接 {a[:2] if isinstance(a, tuple) else a}")
            cl = Client(c, a, self)
            self.add(cl)
            cl.start()

if __name__ == "__main__":
    try:
        Proxy().run()
    except KeyboardInterrupt:
        print("\n[Proxy] 退出")
