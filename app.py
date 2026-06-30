#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import time
import json
import uuid
import psutil
import grpc
from aiohttp import web

# 导入 protobuf 编译生成的结构体（需提前生成）
import nezha_pb2 as pb
import nezha_pb2_grpc as pb_grpc

# ==================== 环境变量 ====================
UUID = os.environ.get('UUID', '1d09c597-2f0f-4731-97d3-4b14e2916ef4')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', 'atz.931333.xyz')      # 如 atz.931333.xyz 或 atz.931333.xyz:443
NEZHA_PORT = os.environ.get('NEZHA_PORT', '443')          # v0 专用端口
NEZHA_KEY = os.environ.get('NEZHA_KEY', 'z4eM6xQGe3DygWJ158')
DOMAIN = os.environ.get('DOMAIN', 'testbelmo-870a.onbelmo.uk')
SUB_PATH = os.environ.get('SUB_PATH', 'belmo')
NAME = os.environ.get('NAME', 'belmo')
WSPATH = os.environ.get('WSPATH', UUID[:8])
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true'
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

# ==================== 全局变量（探针用） ====================
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

task_client = None
state_client = None
is_task_stream_active = False
cached_public_ip = "127.0.0.1"
cached_country_code = "cn"
start_time = int(time.time())
last_in_bytes = 0
last_out_bytes = 0
last_time_millis = int(time.time() * 1000)

# ==================== DNS & 域名屏蔽 ====================
DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# ==================== 工具函数 ====================
def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked)
               for blocked in BLOCKED_DOMAINS)

async def get_isp():
    global ISP
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ip.sb/geoip',
                                   headers={'User-Agent': 'Mozilla/5.0'},
                                   timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                    return
    except:
        pass
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://ip-api.com/json',
                                   headers={'User-Agent': 'Mozilla/5.0'},
                                   timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('countryCode', '')}-{data.get('org', '')}".replace(' ', '_')
                    return
    except:
        pass
    ISP = 'Unknown'

async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api-ipv4.ip.sb/ip', timeout=5) as resp:
                    if resp.status == 200:
                        ip = await resp.text()
                        CurrentDomain = ip.strip()
                        Tls = 'none'
                        CurrentPort = PORT
        except Exception as e:
            logger.error(f'Failed to get IP: {e}')
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except:
        pass
    for dns_server in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']:
                                if answer.get('type') == 1:
                                    return answer.get('data')
        except:
            continue
    return host

# ==================== 探针核心模块 ====================
async def async_fetch_ip_and_country():
    """获取公网 IP（v4/v6）和两位国家码，更新缓存"""
    global cached_public_ip, cached_country_code
    ipv4, ipv6, country = None, None, "un"
    timeout = aiohttp.ClientTimeout(total=3)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get("https://api4.ipify.org?format=json") as r:
                if r.status == 200:
                    ipv4 = (await r.json()).get("ip")
        except:
            pass
        try:
            async with session.get("https://api6.ipify.org?format=json") as r:
                if r.status == 200:
                    ipv6 = (await r.json()).get("ip")
        except:
            pass
        try:
            async with session.get("https://api.ip.sb/geoip", headers={"User-Agent": "Mozilla/5.0"}) as r:
                if r.status == 200:
                    code = (await r.json()).get("country_code", "").lower()
                    if len(code) == 2:
                        country = code
        except:
            pass

    if ipv4 and ipv6:
        cached_public_ip = f"{ipv4} / {ipv6}"
    elif ipv4:
        cached_public_ip = ipv4
    elif ipv6:
        cached_public_ip = ipv6
    cached_country_code = country

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
    if time_delta_second <= 0:
        time_delta_second = 1

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
                try:
                    await info_func(host_payload, metadata=auth_metadata, timeout=4)
                except:
                    pass

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

# ==================== 代理协议处理（VLS / Tro / SS） ====================
class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.uuid_bytes = bytes.fromhex(uuid)

    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            if first_msg[1:17] != self.uuid_bytes:
                return False
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            host = ''
            if atyp == 1:  # IPv4
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:  # 域名
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:  # IPv6
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(i, i+16, 2))
                i += 16
            else:
                return False

            if is_blocked_domain(host):
                await websocket.close()
                return False

            await websocket.send_bytes(bytes([0, 0]))
            resolved_host = await resolve_host(host)

            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()

                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass

                await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False

    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 58:
                return False
            received_hash_bytes = first_msg[:56]
            hash_obj1 = hashlib.sha224()
            hash_obj1.update(self.uuid.encode())
            expected_hash_hex1 = hash_obj1.hexdigest()
            standard_uuid = UUID
            hash_obj2 = hashlib.sha224()
            hash_obj2.update(standard_uuid.encode())
            expected_hash_hex2 = hash_obj2.hexdigest()
            received_hash_hex = received_hash_bytes.decode('ascii', errors='ignore')
            if received_hash_hex != expected_hash_hex1 and received_hash_hex != expected_hash_hex2:
                return False
            offset = 56
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            cmd = first_msg[offset]
            if cmd != 1:
                return False
            offset += 1
            atyp = first_msg[offset]
            offset += 1
            host = ''
            if atyp == 1:  # IPv4
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            if is_blocked_domain(host):
                await websocket.close()
                return False
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass
                await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"Tro handler error: {e}")
            return False

    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 7:
                return False
            offset = 0
            atyp = first_msg[offset]
            offset += 1
            host = ''
            if atyp == 1:  # IPv4
                if offset + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                if offset >= len(first_msg):
                    return False
                host_len = first_msg[offset]
                offset += 1
                if offset + host_len > len(first_msg):
                    return False
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                if offset + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            if is_blocked_domain(host):
                await websocket.close()
                return False
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                async def forward_ws_to_tcp():
                    try:
                        async for msg in websocket:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                async def forward_tcp_to_ws():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await websocket.send_bytes(data)
                    except:
                        pass
                await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"Shadowsocks handler error: {e}")
            return False

# ==================== WebSocket 和 HTTP 路由 ====================
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    CUUID = UUID.replace('-', '')
    path = request.path
    if f'/{WSPATH}' not in path:
        await ws.close()
        return ws
    proxy = ProxyHandler(CUUID)
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        msg_data = first_msg.data
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await proxy.handle_vless(ws, msg_data):
                return ws
        if len(msg_data) >= 58:
            if await proxy.handle_trojan(ws, msg_data):
                return ws
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg_data):
                return ws
        await ws.close()
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f"WebSocket handler error: {e}")
        await ws.close()
    return ws

async def http_handler(request):
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except:
            return web.Response(text='Hello world!', content_type='text/html')
    elif request.path == f'/{SUB_PATH}':
        await get_isp()
        await get_ip()
        name_part = f"{NAME}-{ISP}" if NAME else ISP
        tls_param = 'tls' if Tls == 'tls' else 'none'
        ss_tls_param = 'tls;' if Tls == 'tls' else ''
        vless_url = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        trojan_url = f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        ss_method_password = base64.b64encode(f"none:{UUID}".encode()).decode()
        ss_url = f"ss://{ss_method_password}@{CurrentDomain}:{CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain};path%3D%2F{WSPATH};{ss_tls_param}sni%3D{CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#{name_part}"
        subscription = f"{vless_url}\n{trojan_url}\n{ss_url}"
        base64_content = base64.b64encode(subscription.encode()).decode()
        return web.Response(text=base64_content + '\n', content_type='text/plain')
    return web.Response(status=404, text='Not Found\n')

async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return
    full_url = f"https://{DOMAIN}/{SUB_PATH}"
    try:
        async with aiohttp.ClientSession() as session:
            await session.post("https://oooo.serv00.net/add-url",
                               json={"url": full_url},
                               headers={'Content-Type': 'application/json'})
        logger.info('Automatic Access Task added successfully')
    except:
        pass

# ==================== 主函数 ====================
async def main():
    actual_port = PORT
    if not is_port_available(actual_port):
        logger.warning(f"Port {actual_port} is already in use, finding available port...")
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info(f"Using port {actual_port} instead of {PORT}")
        else:
            logger.error("No available ports found")
            sys.exit(1)

    # 获取公网 IP 和国家（用于探针上报）
    await async_fetch_ip_and_country()
    logger.info(f"Public IP: {cached_public_ip}, Country: {cached_country_code}")

    # 启动哪吒探针（如果配置了服务地址和密钥）
    if NEZHA_SERVER and NEZHA_KEY:
        # 构造 server_addr
        if NEZHA_PORT:
            server_addr = f"{NEZHA_SERVER}:{NEZHA_PORT}"
        else:
            server_addr = NEZHA_SERVER  # 可能已经包含端口
        # 判断是否 TLS：端口为常见 TLS 端口或显式指定
        tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
        use_tls = any(server_addr.endswith(f":{p}") for p in tls_ports)
        # 或者如果 NEZHA_PORT 为空且 NEZHA_SERVER 包含端口则自动判断
        if not NEZHA_PORT and ':' in NEZHA_SERVER:
            port_str = NEZHA_SERVER.split(':')[-1]
            use_tls = port_str in tls_ports
        auth_metadata = [('password', NEZHA_KEY), ('client_secret', NEZHA_KEY)]
        asyncio.create_task(run_nezha_task_loop(server_addr, auth_metadata, use_tls))
        asyncio.create_task(fire_dynamic_state_loop(server_addr, auth_metadata, use_tls))
        logger.info("Nezha gRPC client started.")

    # 启动 Web 服务
    app = web.Application()
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    logger.info(f"✅ Server is running on port {actual_port}")

    # 自动访问保活
    await add_access_task()

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")