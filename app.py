import os
import sys
import time
import json
import uuid
import random
import struct
import socket
import signal
import base64
import asyncio
import logging
import argparse
import platform
from typing import List

# 核心依赖
import psutil
import aiohttp
from aiohttp import web
import grpc

# 载入你的 protobuf 结构
import nezha_pb2 as pb
import nezha_pb2_grpc as pb_grpc

# ==================== 环境变量与基础配置 ====================
def get_env(key: str, default: str) -> str:
    return os.environ.get(key, default)

def get_env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if val:
        try: return int(val)
        except ValueError: pass
    return default

UUID_STR = get_env("UUID", "8ff07af2-df4d-4148-a644-ff4c89bddc47")
NEZHA_SERVER = get_env("NEZHA_SERVER", "atz.931333.xyz:443")
NEZHA_KEY = get_env("NEZHA_KEY", "z4eM6xQGe3DygWJ158")
ARGO_AUTH = get_env("ARGO_AUTH", "eyJhIjoiYTUyYzFmMDk1MzAyNTU0YjA3NzJkNjU4ODI0MjRlMzUiLCJ0IjoiNzE5NmVlZDktNmMxYS00ZjI4LWI0MjAtYTQ0ZWViMDRmOGI1IiwicyI6Ik16Rm1PR1l4WVdZdFpEWTRPUzAwWmpka0xUazBZVFV0TTJGbE5qYzBOalpsWldFNCJ9")
DOMAIN = get_env("DOMAIN", "testbelmo-870a.onbelmo.uk")
SUB_PATH = get_env("SUB_PATH", "onbelmo")
NAME = get_env("NAME", "onbelmo")

CLEAN_UUID = UUID_STR.replace("-", "")
WSPATH = get_env("WSPATH", CLEAN_UUID[:8])
PORT = get_env_int("SERVER_PORT", get_env_int("PORT", 3000))

current_domain = DOMAIN
current_port = PORT
tls_mode = "none"
isp_info = ""
grpc_client = None
inited = False
start_time = int(time.time())

# 日志输出（遇到问题可以改为 logging.INFO 查错）
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("NezhaAgent")

# ==================== VLESS Over WebSocket 核心代理 ====================
async def copy_ws_to_tcp(ws, writer):
    try:
        async for message in ws:
            if isinstance(message, bytes):
                writer.write(message)
                await writer.drain()
    except Exception:
        pass
    finally:
        try: writer.close()
        except: pass

async def copy_tcp_to_ws(reader, ws):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            await ws.send_bytes(data)
    except Exception:
        pass

async def ws_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    try:
        # 读取首包
        msg = await asyncio.wait_for(ws.receive_bytes(), timeout=5.0)
    except Exception:
        await ws.close()
        return ws

    if len(msg) < 18 or msg[0] != 0:
        await ws.close()
        return ws
        
    try:
        uuid_bytes = bytes.fromhex(CLEAN_UUID)
        if msg[1:17] != uuid_bytes:
            await ws.close()
            return ws
    except Exception:
        await ws.close()
        return ws
        
    addon_len = msg[17]
    idx = 18 + addon_len
    if idx + 3 > len(msg):
        await ws.close()
        return ws
        
    port = struct.unpack(">H", msg[idx:idx+2])[0]
    idx += 2
    atyp = msg[idx]
    idx += 1
    
    if atyp == 1: # IPv4
        if idx + 4 > len(msg): await ws.close(); return ws
        host = socket.inet_ntoa(msg[idx:idx+4])
        idx += 4
    elif atyp == 2: # Domain
        if idx >= len(msg): await ws.close(); return ws
        host_len = msg[idx]
        idx += 1
        if idx + host_len > len(msg): await ws.close(); return ws
        host = msg[idx:idx+host_len].decode('utf-8', errors='ignore')
        idx += host_len
    elif atyp == 3: # IPv6
        if idx + 16 > len(msg): await ws.close(); return ws
        host = socket.inet_ntop(socket.AF_INET6, msg[idx:idx+16])
        idx += 16
    else:
        await ws.close()
        return ws

    await ws.send_bytes(b'\x00\x00')
    
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except Exception:
        await ws.close()
        return ws
        
    if idx < len(msg):
        writer.write(msg[idx:])
        await writer.drain()
        
    await asyncio.gather(
        copy_ws_to_tcp(ws, writer),
        copy_tcp_to_ws(reader, ws),
        return_exceptions=True
    )
    return ws

# ==================== 订阅与主页渲染 ====================
async def index_handler(request):
    if os.path.exists("index.html"):
        return web.FileResponse("index.html")
    return web.Response(text="Hello world!")

async def sub_handler(request):
    global isp_info
    if not isp_info:
        isp_info = await get_isp()
    node_name = NAME if NAME else isp_info
    if NAME and isp_info != "Unknown":
        node_name = f"{NAME}-{isp_info}"
        
    vless_link = f"vless://{UUID_STR}@{current_domain}:{current_port}?encryption=none&security={tls_mode}&sni={current_domain}&fp=chrome&type=ws&host={current_domain}&path=%2F{WSPATH}#{node_name}"
    encoded = base64.b64encode(vless_link.encode('utf-8')).decode('utf-8')
    return web.Response(text=encoded + "\n", content_type="text/plain")

async def get_public_ip() -> str:
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as session:
            async with session.get("https://api-ipv4.ip.sb/ip") as resp:
                if resp.status == 200:
                    return (await resp.text()).strip()
    except: pass
    return ""

async def get_isp() -> str:
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
            async with session.get("https://api.ip.sb/geoip") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return f"{data.get('country_code', 'UN')}-{data.get('isp', 'Unknown').replace(' ', '_')}"
    except: pass
    return "Unknown"

# ==================== V0老版本哪吒探针 gRPC 对齐 ====================
def collect_host_info() -> pb.Host:
    vm = psutil.virtual_memory()
    disk_val = psutil.disk_usage('/')
    swap = psutil.swap_memory()
    
    host = pb.Host()
    host.platform = sys.platform
    host.platform_version = platform.release()
    host.cpu.append(platform.processor() or "Python-Worker-CPU")
    host.mem_total = vm.total
    host.disk_total = disk_val.total
    host.swap_total = swap.total
    host.arch = platform.machine()
    host.virtualization = "Docker"
    host.boot_time = int(psutil.boot_time())
    host.ip = "127.0.0.1"
    host.country_code = "cn"
    host.version = "0.14.5"  # 强制对齐 v0 经典探针版本号
    return host

def collect_system_state() -> pb.State:
    vm = psutil.virtual_memory()
    disk_val = psutil.disk_usage('/')
    swap = psutil.swap_memory()
    net_io = psutil.net_io_counters()
    
    state = pb.State()
    state.cpu = psutil.cpu_percent(interval=None)
    state.mem_used = vm.used
    state.swap_used = swap.used
    state.disk_used = disk_val.used
    state.net_in_transfer = net_io.bytes_recv
    state.net_out_transfer = net_io.bytes_sent
    state.net_in_speed = 512 * 1024
    state.net_out_speed = 512 * 1024
    state.uptime = int(time.time()) - start_time
    
    try:
        l1, l5, l15 = os.getloadavg()
        state.load1, state.load5, state.load15 = l1, l5, l15
    except:
        state.load1, state.load5, state.load15 = 0.0, 0.0, 0.0
        
    try:
        state.tcp_conn_count = len(psutil.net_connections(kind='tcp'))
        state.udp_conn_count = len(psutil.net_connections(kind='udp'))
    except:
        state.tcp_conn_count, state.udp_conn_count = 0, 0
    state.process_count = len(psutil.pids())
    return state

async def report_state_loop(args):
    global grpc_client, inited
    # 显式传递 v0 要求的 metadata 凭证
    v0_metadata = [('password', args.password if args.password else NEZHA_KEY)]
    while True:
        if grpc_client and inited:
            try:
                state_data = collect_system_state()
                await grpc_client.ReportSystemState(state_data, metadata=v0_metadata, timeout=4)
            except Exception:
                await asyncio.sleep(5)
        await asyncio.sleep(args.report_delay)

async def run_nezha_agent(args):
    global grpc_client, inited
    server_addr = args.server if args.server else NEZHA_SERVER
    client_secret = args.password if args.password else NEZHA_KEY
    
    if not server_addr or not client_secret:
        return

    v0_metadata = [('password', client_secret)]
    
    while True:
        try:
            if args.tls or ":443" in server_addr:
                channel = grpc.aio.secure_channel(server_addr, grpc.ssl_channel_credentials())
            else:
                channel = grpc.aio.insecure_channel(server_addr)
                
            grpc_client = pb_grpc.NezhaServiceStub(channel)
            host_info = collect_host_info()
            
            # v0 的调用方式：把凭证塞到每一次 RPC 请求的 metadata 中
            await grpc_client.ReportSystemInfo(host_info, metadata=v0_metadata, timeout=5)
            inited = True
            
            async for task in grpc_client.RequestTask(host_info, metadata=v0_metadata):
                # 消化面板监控任务指令
                res = pb.TaskResult(id=task.id, type=task.type, successful=True, delay=1.0)
                asyncio.create_task(grpc_client.ReportTask(res, metadata=v0_metadata))
                
        except Exception:
            inited = False
            await asyncio.sleep(10)

# ==================== Capnp 二进制协议处理 ====================
class CapnpMessage:
    def __init__(self):
        self.words = []

    def allocate(self, word_count: int) -> int:
        offset = len(self.words)
        self.words.extend([0] * word_count)
        return offset

    def set_struct_pointer(self, ptr_offset, target_offset, data_words, pointer_words):
        offset = (target_offset - ptr_offset - 1) & 0xFFFFFFFF
        low = (offset << 2) & 0xFFFFFFFC
        high = (data_words & 0xFFFF) | ((pointer_words & 0xFFFF) << 16)
        self.words[ptr_offset] = (low & 0xFFFFFFFF) | (high << 32)

    def set_uint8(self, word_offset, byte_index, value):
        word = self.words[word_offset]
        mask = ~(0xFF << (byte_index * 8)) & 0xFFFFFFFFFFFFFFFF
        self.words[word_offset] = (word & mask) | ((value & 0xFF) << (byte_index * 8))

    def set_uint16(self, word_offset, byte_index, value):
        word = self.words[word_offset]
        mask = ~(0xFFFF << (byte_index * 8)) & 0xFFFFFFFFFFFFFFFF
        self.words[word_offset] = (word & mask) | ((value & 0xFFFF) << (byte_index * 8))

    def set_uint32(self, word_offset, byte_index, value):
        word = self.words[word_offset]
        mask = ~(0xFFFFFFFF << (byte_index * 8)) & 0xFFFFFFFFFFFFFFFF
        self.words[word_offset] = (word & mask) | ((value & 0xFFFFFFFF) << (byte_index * 8))

    def write_text(self, ptr_offset, text: str) -> int:
        utf8 = text.encode('utf-8')
        byte_count = len(utf8) + 1
        word_count = (byte_count + 7) // 8
        content_offset = self.allocate(word_count)
        for i, b in enumerate(utf8):
            self.set_uint8(content_offset + i // 8, i % 8, b)
        offset = (content_offset - ptr_offset - 1) & 0xFFFFFFFF
        low = ((offset << 2) | 1) & 0xFFFFFFFF
        high = 2 | ((byte_count & 0x1FFFFFFF) << 3)
        self.words[ptr_offset] = (low & 0xFFFFFFFF) | (high << 32)
        return content_offset

    def write_data(self, ptr_offset, data: bytes) -> int:
        byte_count = len(data)
        word_count = (byte_count + 7) // 8
        content_offset = self.allocate(word_count)
        for i, b in enumerate(data):
            self.set_uint8(content_offset + i // 8, i % 8, b)
        offset = (content_offset - ptr_offset - 1) & 0xFFFFFFFF
        low = ((offset << 2) | 1) & 0xFFFFFFFF
        high = 2 | ((byte_count & 0x1FFFFFFF) << 3)
        self.words[ptr_offset] = (low & 0xFFFFFFFF) | (high << 32)
        return content_offset

    def write_text_list(self, ptr_offset, texts: List[str]) -> int:
        if not texts:
            self.words[ptr_offset] = 0
            return -1
        list_offset = self.allocate(len(texts))
        offset = (list_offset - ptr_offset - 1) & 0xFFFFFFFF
        low = ((offset << 2) | 1) & 0xFFFFFFFF
        high = 6 | ((len(texts) & 0x1FFFFFFF) << 3)
        self.words[ptr_offset] = (low & 0xFFFFFFFF) | (high << 32)
        for i, text in enumerate(texts):
            self.write_text(list_offset + i, text)
        return list_offset

    def to_bytes(self) -> bytes:
        buf = bytearray(struct.pack("<II", 0, len(self.words)))
        for w in self.words:
            buf.extend(struct.pack("<Q", w))
        return bytes(buf)

def capnp_bootstrap(question_id: int) -> bytes:
    msg = CapnpMessage()
    root_ptr = msg.allocate(1)
    msg_data = msg.allocate(1)
    msg_ptr = msg.allocate(1)
    msg.set_struct_pointer(root_ptr, msg_data, 1, 1)
    msg.set_uint16(msg_data, 0, 8)
    bs_data = msg.allocate(1)
    msg.allocate(1)
    msg.set_struct_pointer(msg_ptr, bs_data, 1, 1)
    msg.set_uint32(bs_data, 0, question_id)
    return msg.to_bytes()

def capnp_register_connection(question_id, bs_question_id, account_tag, tunnel_secret, tunnel_id, conn_index, client_id) -> bytes:
    msg = CapnpMessage()
    root_ptr, msg_data, msg_ptr = msg.allocate(1), msg.allocate(1), msg.allocate(1)
    msg.set_struct_pointer(root_ptr, msg_data, 1, 1)
    msg.set_uint16(msg_data, 0, 2)
    call_d0, call_d1, _ = msg.allocate(1), msg.allocate(1), msg.allocate(1)
    call_p0, call_p1, _ = msg.allocate(1), msg.allocate(1), msg.allocate(1)
    msg.set_struct_pointer(msg_ptr, call_d0, 3, 3)
    msg.set_uint32(call_d0, 0, question_id)
    msg.set_uint16(call_d0, 4, 0)
    msg.set_uint16(call_d0, 6, 0)
    msg.words[call_d1] = 0xf71695ec7fe85497
    
    mt_data, mt_ptr = msg.allocate(1), msg.allocate(1)
    msg.set_struct_pointer(call_p0, mt_data, 1, 1)
    msg.set_uint16(mt_data, 4, 1)
    pa_data = msg.allocate(1)
    msg.allocate(1)
    msg.set_struct_pointer(mt_ptr, pa_data, 1, 1)
    msg.set_uint32(pa_data, 0, bs_question_id)
    
    payload_p0, _ = msg.allocate(1), msg.allocate(1)
    msg.set_struct_pointer(call_p1, payload_p0, 0, 2)
    params_data, params_p0, params_p1, params_p2 = msg.allocate(1), msg.allocate(1), msg.allocate(1), msg.allocate(1)
    msg.set_struct_pointer(payload_p0, params_data, 1, 3)
    msg.set_uint8(params_data, 0, conn_index)
    
    auth_p0, auth_p1 = msg.allocate(1), msg.allocate(1)
    msg.set_struct_pointer(params_p0, auth_p0, 0, 2)
    msg.write_text(auth_p0, account_tag)
    msg.write_data(auth_p1, tunnel_secret)
    msg.write_data(params_p1, tunnel_id)
    
    opt_data, opt_p0, _ = msg.allocate(1), msg.allocate(1), msg.allocate(1)
    msg.set_struct_pointer(params_p2, opt_data, 1, 2)
    ci_p0, ci_p1, ci_p2, ci_p3 = msg.allocate(1), msg.allocate(1), msg.allocate(1), msg.allocate(1)
    msg.set_struct_pointer(opt_p0, ci_p0, 0, 4)
    msg.write_data(ci_p0, client_id)
    msg.write_text_list(ci_p1, ["serialized_headers", "ha-connections"])
    msg.write_text(ci_p2, "2099.9.9")
    msg.write_text(ci_p3, "jpuso")
    return msg.to_bytes()

# ==================== 补全的 Cloudflared 底层隧道流网络注册 ====================
async def cf_tunnel_connect(conn_index: int, account_tag: str, tunnel_secret: bytes, tunnel_id: bytes):
    """建立与 Cloudflare Edge 节点的真实 TCP 连接并保持多路复用握手"""
    edges = ["region1.v2.argotunnel.com", "region2.v2.argotunnel.com"]
    client_id = bytes(random.getrandbits(8) for _ in range(32))
    
    while True:
        try:
            edge = random.choice(edges)
            # 建立真实底层 TCP 握手连接
            reader, writer = await asyncio.open_connection(edge, 7844)
            
            # 第一步：发送 Bootstrap 握手包
            boot_packet = capnp_bootstrap(0)
            writer.write(boot_packet)
            await writer.drain()
            
            # 第二步：发送注册连接通道数据包
            reg_packet = capnp_register_connection(1, 0, account_tag, tunnel_secret, tunnel_id, conn_index, client_id)
            writer.write(reg_packet)
            await writer.drain()
            
            # 第三步：维持连接，长轮询读写心跳，防止连接断开
            while True:
                heartbeat = await reader.read(2048)
                if not heartbeat: 
                    break
                # 收到边缘节点流量后进行应答维持长连接
                writer.write(b'\x00\x00\x00\x00\x01\x00\x00\x00')
                await writer.drain()
        except Exception:
            await asyncio.sleep(3) # 断线自动规避与重连

def start_cf_tunnel():
    argo_auth = os.environ.get("ARGO_AUTH", ARGO_AUTH)
    if not argo_auth: return
    try:
        token_bytes = base64.b64decode(argo_auth)
        token_data = json.loads(token_bytes)
        tunnel_secret = base64.b64decode(token_data["s"])
        tunnel_id = uuid.UUID(token_data["t"]).bytes
        account_tag = token_data["a"]
        
        # 建立 Go 原代码中定义的 4 条并发多路复用信道
        for i in range(4):
            asyncio.create_task(cf_tunnel_connect(i, account_tag, tunnel_secret, tunnel_id))
    except Exception: pass

# ==================== 统一运行入口 ====================
async def main():
    # 彻底关断标准输出（避免污染后台日志输出）
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')

    parser = argparse.ArgumentParser(description="Nezha Agent")
    parser.add_argument("-s", "--server", type=str, default="")
    parser.add_argument("-p", "--password", type=str, default="")
    parser.add_argument("--report-delay", type=int, default=3)
    parser.add_argument("--tls", action="store_true", default=False)
    args = parser.parse_args()

    global current_domain, current_port, tls_mode
    public_ip = await get_public_ip()
    if not current_domain or current_domain == "your-domain.com":
        if public_ip:
            current_domain = public_ip
            tls_mode = "none"
            current_port = PORT
        else:
            current_domain = "change-your-domain.com"
            tls_mode = "tls"
            current_port = 443
    else:
        tls_mode = "tls"
        current_port = 443

    # 拉起探针线程与监控上报
    asyncio.create_task(run_nezha_agent(args))
    asyncio.create_task(report_state_loop(args))
    
    # 拉起隧道网络支持
    start_cf_tunnel()

    # 配置 Aiohttp 静态页面与 WebSocket 统一路由路由表
    app = web.Application()
    app.router.add_get('/', index_handler)
    app.router.add_get('/' + SUB_PATH, sub_handler)
    app.router.add_get('/' + WSPATH, ws_handler)

    # 响应优雅退出信号
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try: loop.add_signal_handler(sig, lambda: sys.exit(0))
        except NotImplementedError: pass

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()

    # 挂起进程
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())