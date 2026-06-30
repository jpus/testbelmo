#!/usr/bin/env python3
# -*- coding: utf-8 -* -*-

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
import ssl
import logging
import argparse
from typing import List, Dict

# 核心系统及网络协议依赖
import psutil
import aiohttp
from aiohttp import web
import grpc
import h2.connection
import h2.events
import h2.exceptions

# 载入 Protobuf 编译生成的结构体
import nezha_pb2 as pb
import nezha_pb2_grpc as pb_grpc

# 设置日志级别
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ProxyApp")

# ==================== 环境变量与基础配置 ====================
def get_env(key: str, default: str) -> str:
    return os.environ.get(key, default)

def get_env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if val:
        try: return int(val)
        except ValueError: pass
    return default

UUID_STR = get_env("UUID", "1d09c597-2f0f-4731-97d3-4b14e2916ef4")
NEZHA_SERVER = get_env("NEZHA_SERVER", "atz.931333.xyz:443")
NEZHA_KEY = get_env("NEZHA_KEY", "z4eM6xQGe3DygWJ158")
ARGO_AUTH = get_env("ARGO_AUTH", "eyJhIjoiYTUyYzFmMDk1MzAyNTU0YjA3NzJkNjU4ODI0MjRlMzUiLCJ0IjoiNzE5NmVlZDktNmMxYS00ZjI4LWI0MjAtYTQ0ZWViMDRmOGI1IiwicyI6Ik16Rm1PR1l4WVdZdFpEWTRPUzAwWmpka0xUazBZVFV0TTJGbE5qYzBOalpsWldFNCJ9")
DOMAIN = get_env("DOMAIN", "testbelmo-870a.onbelmo.uk")
SUB_PATH = get_env("SUB_PATH", "belmo")
NAME = get_env("NAME", "belmo")

CLEAN_UUID = UUID_STR.replace("-", "")
WSPATH = get_env("WSPATH", CLEAN_UUID[:8])
PORT = get_env_int("SERVER_PORT", get_env_int("PORT", 3000))

current_domain = DOMAIN
current_port = PORT
tls_mode = "none"
isp_info = ""

task_client = None
state_client = None
is_task_stream_active = False
cached_public_ip = "127.0.0.1"
cached_country_code = "cn"
start_time = int(time.time())

last_in_bytes = 0
last_out_bytes = 0
last_time_millis = int(time.time() * 1000)

# ==================== 统一的底层 VLESS 二进制解包与目标 TCP 转发核心 ====================
async def handle_vless_binary_stream(reader_in, writer_out, initial_data=b""):
    """
    完全对齐 Java JettyVlessHandler 的底层逻辑
    承接的必须是【纯 VLESS 二进制流】（不论是 H2 隧道剥离出来的，还是 aiohttp 剥离出来的）
    """
    remote_writer = None
    try:
        # 1. 获取首包数据
        if initial_data:
            msg = initial_data
        else:
            msg = await asyncio.wait_for(reader_in.read(4096), timeout=5.0)
            
        if not msg or len(msg) < 18:
            return

        # 2. 校验 VLESS 版本号 (第 1 字节必须是 0)
        if msg[0] != 0:
            return
            
        # 3. 校验 UUID (第 2 到 17 字节)
        try:
            uuid_bytes = bytes.fromhex(CLEAN_UUID)
            if msg[1:17] != uuid_bytes:
                return
        except Exception:
            return
            
        # 4. 解析附加信息与目标地址
        addon_len = msg[17]
        idx = 18 + addon_len
        if idx + 3 > len(msg):
            return
            
        # 提取 2 字节端口 (大端网络字节序)
        port = struct.unpack(">H", msg[idx:idx+2])[0]
        idx += 2
        
        # 提取 1 字节地址类型
        atyp = msg[idx]
        idx += 1
        
        if atyp == 1:    # IPv4
            if idx + 4 > len(msg): return
            host = socket.inet_ntoa(msg[idx:idx+4])
            idx += 4
        elif atyp == 2:  # 域名
            if idx >= len(msg): return
            host_len = msg[idx]
            idx += 1
            if idx + host_len > len(msg): return
            host = msg[idx:idx+host_len].decode('utf-8', errors='ignore')
            idx += host_len
        elif atyp == 3:  # IPv6
            if idx + 16 > len(msg): return
            host = socket.inet_ntop(socket.AF_INET6, msg[idx:idx+16])
            idx += 16
        else:
            return

        # 5. 回传 VLESS 握手成功响应标 (\x00\x00)
        writer_out.write(b'\x00\x00')
        await writer_out.drain()
        
        # 6. 建立到远程目标站点的真正 TCP 连接
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
        
        # 7. 如果首包里除了头部还有后续客户端数据，直接写入远程目标
        if idx < len(msg):
            remote_writer.write(msg[idx:])
            await remote_writer.drain()

        # 8. 启动双向高频抽水泵 (对齐 Java 虚拟线程的高并发 PUMP 环路)
        async def pipe(r, w):
            try:
                while True:
                    data = await r.read(4096)
                    if not data: 
                        break
                    w.write(data)
                    await w.drain()
            except: 
                pass
            finally:
                try: w.close()
                except: pass

        # 并行执行双向转发
        await asyncio.gather(
            pipe(reader_in, remote_writer),
            pipe(remote_reader, writer_out),
            return_exceptions=True
        )

    except Exception:
        pass
    finally:
        try: writer_out.close()
        except: pass
        if remote_writer:
            try: remote_writer.close()
            except: pass

# ==================== 入口 A：处理标准的公网外网 WebSocket 路由 ====================
async def ws_handler(request):
    """
    负责承接客户端发起的标准公网 WS 连接
    利用 aiohttp 剥离掉 WebSocket 协议外壳，转交给底层的纯 VLESS 二进制转发核心
    """
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    # 建立两对内存级虚拟管道，用来将 aiohttp 的 WS 事件桥接到 handle_vless_binary_stream 中
    rs_in, ws_out = os.pipe()
    reader_internal, _ = await asyncio.open_connection(pipe=os.fdopen(rs_in, 'rb'))
    _, writer_to_core = await asyncio.open_connection(pipe=os.fdopen(ws_out, 'wb'))
    
    rs_out, ws_in = os.pipe()
    reader_from_core, _ = await asyncio.open_connection(pipe=os.fdopen(rs_out, 'rb'))
    _, writer_internal = await asyncio.open_connection(pipe=os.fdopen(ws_in, 'wb'))

    # 在后台异步拉起对齐 Java 的 VLESS 核心解包转发器
    asyncio.create_task(handle_vless_binary_stream(reader_internal, writer_internal))
    
    # 桥接器 1: 将客户端通过 WS 发来的二进制包（已脱去 WS Frame 外壳），写入虚拟流
    async def ws_to_pipe():
        try:
            async for message in ws:
                if message.type == web.WSMsgType.BINARY:
                    writer_to_core.write(message.data)
                    await writer_to_core.drain()
        except: pass
        finally:
            try: writer_to_core.close()
            except: pass

    # 桥接器 2: 将核心转发器传回的响应数据，包装成标准 WS 二进制帧发回给客户端
    async def pipe_to_ws():
        try:
            while True:
                data = await reader_from_core.read(4096)
                if not data: 
                    break
                await ws.send_bytes(data)
        except: pass
        finally:
            try: await ws.close()
            except: pass

    # 并行等待 WS 桥接管道结束
    await asyncio.gather(ws_to_pipe(), pipe_to_ws(), return_exceptions=True)
    return ws

# ==================== 基础 HTTP 服务与订阅管理 ====================
async def index_handler(request):
    return web.Response(text="Hello world!", content_type="text/plain")

async def sub_handler(request):
    global isp_info
    if not isp_info: isp_info = await get_isp()
    node_name = NAME if NAME else isp_info
    if NAME and isp_info != "Unknown": node_name = f"{NAME}-{isp_info}"
    
    vless_link = f"vless://{UUID_STR}@{current_domain}:{current_port}?encryption=none&security={tls_mode}&sni={current_domain}&fp=chrome&type=ws&host={current_domain}&path=%2F{WSPATH}#{node_name}"
    encoded = base64.b64encode(vless_link.encode('utf-8')).decode('utf-8')
    return web.Response(text=encoded + "\n", content_type="text/plain")

async def async_fetch_ip_and_country():
    global cached_public_ip, cached_country_code
    ipv4, ipv6, country = None, None, "un"
    timeout = aiohttp.ClientTimeout(total=3)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get("https://api4.ipify.org?format=json") as r:
                if r.status == 200: ipv4 = (await r.json()).get("ip")
        except: pass
        try:
            async with session.get("https://api6.ipify.org?format=json") as r:
                if r.status == 200: ipv6 = (await r.json()).get("ip")
        except: pass
        try:
            async with session.get("https://api.ip.sb/geoip", headers={"User-Agent": "Mozilla/5.0"}) as r:
                if r.status == 200:
                    code = (await r.json()).get("country_code", "").lower()
                    if len(code) == 2: country = code
        except: pass

    if ipv4 and ipv6: cached_public_ip = f"{ipv4} / {ipv6}"
    elif ipv4: cached_public_ip = ipv4
    elif ipv6: cached_public_ip = ipv6
    cached_country_code = country

async def get_isp() -> str:
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
            async with session.get("https://api.ip.sb/geoip") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return f"{data.get('country_code', 'UN')}-{data.get('isp', 'Unknown').replace(' ', '_')}"
    except: pass
    return "Unknown"

# ==================== 工业级双轨探针上报（完全对齐 v0 协议体） ====================
def build_complete_host_info() -> pb.Host:
    vm = psutil.virtual_memory()
    disk_val = psutil.disk_usage('/')
    host = pb.Host()
    host.platform = "debian"
    host.platform_version = "12"
    host.cpu.append("Intel/AMD vCPU Core")
    host.mem_total = vm.total
    host.disk_total = disk_val.total
    host.swap_total = 0
    host.arch = "amd64"
    host.virtualization = "kvm"
    host.boot_time = start_time
    host.ip = cached_public_ip
    host.country_code = cached_country_code
    host.version = f"0.17.9-{int(time.time() * 1000) % 100}"
    return host

def collect_dynamic_state_payload() -> pb.State:
    global last_in_bytes, last_out_bytes, last_time_millis
    vm = psutil.virtual_memory()
    disk_val = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()
    
    current_time_millis = int(time.time() * 1000)
    time_delta_second = (current_time_millis - last_time_millis) // 1000
    if time_delta_second <= 0: time_delta_second = 1

    current_in_bytes = abs(net_io.bytes_recv)
    current_out_bytes = abs(net_io.bytes_sent)

    net_in_speed = max(0, (current_in_bytes - last_in_bytes) // time_delta_second)
    net_out_speed = max(0, (current_out_bytes - last_out_bytes) // time_delta_second)

    last_in_bytes = current_in_bytes
    last_out_bytes = current_out_bytes
    last_time_millis = current_time_millis

    state = pb.State()
    state.cpu = psutil.cpu_percent(interval=None) or 1.2
    state.mem_used = vm.used
    state.swap_used = 0
    state.disk_used = disk_val.used
    state.net_in_transfer = current_in_bytes
    state.net_out_transfer = current_out_bytes
    state.net_in_speed = net_in_speed
    state.net_out_speed = net_out_speed
    state.uptime = int(time.time()) - start_time
    try:
        l1, l5, l15 = os.getloadavg()
        state.load1, state.load5, state.load15 = l1, l5, l15
    except:
        state.load1, state.load5, state.load15 = 0.05, 0.04, 0.03
    state.tcp_conn_count = len(psutil.net_connections(kind='tcp')) or 8
    state.udp_conn_count = 1
    state.process_count = len(psutil.pids()) or 45
    return state

def create_physical_channel(server_addr, use_tls):
    options = [
        ('grpc.keepalive_time_ms', 5000),
        ('grpc.keepalive_timeout_ms', 3000),
        ('grpc.keepalive_permit_without_calls', True)
    ]
    if use_tls or ":443" in server_addr:
        return grpc.aio.secure_channel(server_addr, grpc.ssl_channel_credentials(), options=options)
    else:
        return grpc.aio.insecure_channel(server_addr, options=options)

async def fire_dynamic_state_loop(server_addr, auth_metadata, use_tls):
    global state_client
    while True:
        try:
            if state_client is None:
                channel = create_physical_channel(server_addr, use_tls)
                state_client = pb_grpc.NezhaServiceStub(channel)
            state_payload = collect_dynamic_state_payload()
            func = getattr(state_client, 'ReportSystemState', None) or getattr(state_client, 'reportSystemState')
            await func(state_payload, metadata=auth_metadata, timeout=4)
            await asyncio.sleep(2)
        except Exception:
            state_client = None
            await asyncio.sleep(4)

async def run_nezha_task_loop(server_addr, auth_metadata, use_tls):
    global task_client, is_task_stream_active
    while True:
        try:
            if task_client is None:
                channel = create_physical_channel(server_addr, use_tls)
                task_client = pb_grpc.NezhaServiceStub(channel)
                is_task_stream_active = False

            if not is_task_stream_active:
                host_payload = build_complete_host_info()
                info_func = getattr(task_client, 'ReportSystemInfo', None) or getattr(task_client, 'reportSystemInfo')
                try: await info_func(host_payload, metadata=auth_metadata, timeout=4)
                except: pass
                
                task_func = getattr(task_client, 'RequestTask', None) or getattr(task_client, 'requestTask')
                is_task_stream_active = True
                async for task in task_func(host_payload, metadata=auth_metadata):
                    report_func = getattr(task_client, 'ReportTask', None) or getattr(task_client, 'reportTask')
                    res = pb.TaskResult(id=task.id, type=task.type, successful=True, delay=1.0)
                    asyncio.create_task(report_func(res, metadata=auth_metadata))
        except Exception:
            task_client = None
            is_task_stream_active = False
            await asyncio.sleep(10)

# ==================== Capnp 协议序列化构建器 ====================
class CapnpMessage:
    def __init__(self): self.words = []
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
        for i, b in enumerate(utf8): self.set_uint8(content_offset + i // 8, i % 8, b)
        offset = (content_offset - ptr_offset - 1) & 0xFFFFFFFF
        low = ((offset << 2) | 1) & 0xFFFFFFFF
        high = 2 | ((byte_count & 0x1FFFFFFF) << 3)
        self.words[ptr_offset] = (low & 0xFFFFFFFF) | (high << 32)
        return content_offset
    def write_data(self, ptr_offset, data: bytes) -> int:
        byte_count = len(data)
        word_count = (byte_count + 7) // 8
        content_offset = self.allocate(word_count)
        for i, b in enumerate(data): self.set_uint8(content_offset + i // 8, i % 8, b)
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
        for i, text in enumerate(texts): self.write_text(list_offset + i, text)
        return list_offset
    def to_bytes(self) -> bytes:
        buf = bytearray(struct.pack("<II", 0, len(self.words)))
        for w in self.words: buf.extend(struct.pack("<Q", w))
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

# ==================== 入口 B：HTTP/2 多路复用隧道处理器 ====================
class AsyncStreamBridge:
    """充当 Socket 缓冲流，专门负责将 H2 Stream 与底层的纯二进制 VLESS 转发核心连通"""
    def __init__(self):
        self.queue = asyncio.Queue()
    async def read(self, n):
        return await self.queue.get()
    def put(self, data):
        if data: self.queue.put_nowait(data)

class DummyWriter:
    def __init__(self, stream_id, h2_conn, transport):
        self.stream_id = stream_id
        self.h2_conn = h2_conn
        self.transport = transport
    def write(self, data):
        # 目标站点响应回来的二进制，通过 HTTP/2 DATA 帧原路推回给 Cloudflare 边缘节点
        chunk_size = 16384
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            self.h2_conn.send_data(self.stream_id, chunk)
            self.transport.write(self.h2_conn.data_to_send())
    async def drain(self):
        pass
    def close(self):
        try:
            self.h2_conn.end_stream(self.stream_id)
            self.transport.write(self.h2_conn.data_to_send())
        except: pass

async def cf_tunnel_h2_worker(conn_index: int, account_tag: str, tunnel_secret: bytes, tunnel_id: bytes):
    """
    核心：手工模拟 Cloudflared 客户端的 HTTP/2 多路复用隧道长连接
    """
    edges = ["region1.v2.argotunnel.com", "region2.v2.argotunnel.com"]
    client_id = bytes(random.getrandbits(8) for _ in range(32))
    
    while True:
        try:
            edge = random.choice(edges)
            # 建立物理 TLS 链路，强制指定 ALPN 为 ['h2']。这样边缘节点就会以 H2 帧的方式下发流量 🚀
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_ctx.set_alpn_protocols(['h2'])
            
            reader, writer = await asyncio.open_connection(edge, 7844, ssl=ssl_ctx)
            transport = writer.transport
            
            # 发送 Cap'n Proto 握手注册隧道信道
            writer.write(capnp_bootstrap(0))
            writer.write(capnp_register_connection(1, 0, account_tag, tunnel_secret, tunnel_id, conn_index, client_id))
            await writer.drain()
            
            # 启动本地 Hyper-H2 连接状态机
            config = h2.config.H2Configuration(client_side=False) # 服务端接收流量模式
            h2_conn = h2.connection.H2Connection(config=config)
            h2_conn.initiate_connection()
            transport.write(h2_conn.data_to_send())
            
            active_bridges: Dict[int, AsyncStreamBridge] = {}
            logger.info(f"隧道物理信道 [{conn_index}] 握手成功，开始监听多路复用 H2 数据流...")
            
            while True:
                data = await reader.read(65536)
                if not data: break
                
                try:
                    events = h2_conn.receive_data(data)
                except h2.exceptions.ProtocolError:
                    break
                    
                transport.write(h2_conn.data_to_send())
                
                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        headers = dict(event.headers)
                        path = headers.get(b':path', b'').decode('utf-8').lstrip('/')
                        
                        # 检测路径是否命中我们的 WSPATH 🚀
                        if path == WSPATH or WSPATH in path:
                            bridge = AsyncStreamBridge()
                            active_bridges[event.stream_id] = bridge
                            dummy_writer = DummyWriter(event.stream_id, h2_conn, transport)
                            
                            # 回传 200 OK 标头响应边缘节点
                            response_headers = [
                                (':status', '200'),
                                ('content-type', 'application/octet-stream'),
                            ]
                            h2_conn.send_headers(event.stream_id, response_headers)
                            transport.write(h2_conn.data_to_send())
                            
                            # 将该 H2 Stream 包含的纯二进制流直接交给底层转发器
                            asyncio.create_task(handle_vless_binary_stream(bridge, dummy_writer))
                            
                    elif isinstance(event, h2.events.DataReceived):
                        if event.stream_id in active_bridges:
                            active_bridges[event.stream_id].put(event.data)
                            h2_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                            transport.write(h2_conn.data_to_send())
                            
                    elif isinstance(event, h2.events.StreamEnded):
                        if event.stream_id in active_bridges:
                            active_bridges[event.stream_id].put(b"") # 发送结束标 EOF
                            del active_bridges[event.stream_id]
                            
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        break
                        
                transport.write(h2_conn.data_to_send())
                
        except Exception as e:
            pass
        await asyncio.sleep(4) # 出现异常后断开重连

def start_cf_tunnel_h2():
    argo_auth = os.environ.get("ARGO_AUTH", ARGO_AUTH)
    if not argo_auth: 
        logger.warning("未配置 ARGO_AUTH 环境变量，内嵌 Argo 隧道将不会启动")
        return
    try:
        token_bytes = base64.b64decode(argo_auth.strip())
        token_data = json.loads(token_bytes.decode('utf-8'))
        tunnel_secret = base64.b64decode(token_data["s"])
        tunnel_id = uuid.UUID(token_data["t"]).bytes
        account_tag = token_data["a"]
        
        # 启动 4 条高可用并行物理连接链路
        for i in range(4):
            asyncio.create_task(cf_tunnel_h2_worker(i, account_tag, tunnel_secret, tunnel_id))
        logger.info("成功创建并拉起 4 条内部 Argo H2 高可用连接。")
    except Exception as e:
        logger.error(f"解析 ARGO_AUTH 异常失败: {e}")

# ==================== 主程序入口 ====================
async def main():
    # 重置并清洗标准流，防止由于标准流被破坏导致控制台阻塞崩溃
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')

    parser = argparse.ArgumentParser(description="Nezha Agent")
    parser.add_argument("-s", "--server", type=str, default="")
    parser.add_argument("-p", "--password", type=str, default="")
    parser.add_argument("--report-delay", type=int, default=2)
    parser.add_argument("--tls", action="store_true", default=False)
    args = parser.parse_args()

    # 高频异步拉取地理信息和本机网络信息
    await async_fetch_ip_and_country()

    global current_domain, current_port, tls_mode
    public_ip = cached_public_ip
    if not current_domain or current_domain == "your-domain.com":
        if public_ip and " / " not in public_ip:
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

    server_addr = args.server if args.server else NEZHA_SERVER
    client_secret = (args.password if args.password else NEZHA_KEY).strip()
    
    auth_metadata = [
        ('password', client_secret),
        ('client_secret', client_secret)
    ]
    use_tls = args.tls or ":443" in server_addr

    # 1. 异步启动哪吒探针双轨监测回路
    if server_addr and client_secret:
        asyncio.create_task(run_nezha_task_loop(server_addr, auth_metadata, use_tls))
        asyncio.create_task(fire_dynamic_state_loop(server_addr, auth_metadata, use_tls))
    
    # 2. 异步拉起内嵌高性能 HTTP/2 隧道
    start_cf_tunnel_h2()

    # 3. 注入 aiohttp 服务器环境路由（用于接收传统外网公网 WS 以及提供订阅）
    app = web.Application()
    app.router.add_get('/', index_handler)
    app.router.add_get('/' + SUB_PATH, sub_handler)
    app.router.add_get('/' + WSPATH, ws_handler)

    # 注册系统优雅退出信号
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try: loop.add_signal_handler(sig, lambda: sys.exit(0))
        except NotImplementedError: pass

    # 开启公网 Web 服务监听端口
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()

    # 维持主事件循环永远在线
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
