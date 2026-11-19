#!/usr/bin/env python3
"""Collect Headscale/Tailscale status and serve local control actions for the Komari plugin."""

import concurrent.futures
import datetime
import hmac
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

KOMARI_DATA_DIR = Path(os.environ.get('KOMARI_DATA_DIR', '/opt/komari/data'))
STORAGE_DIR = Path(os.environ.get('KOMARI_PLUGIN_STORAGE_DIR') or (KOMARI_DATA_DIR / 'plugin-data' / 'tailscale-status'))
OUTPUT = STORAGE_DIR / 'status.json'
TOKEN_FILE = STORAGE_DIR / '.control_token'
ENDPOINT_FILE = STORAGE_DIR / '.control_endpoint'
SOCKET = os.environ.get('TAILSCALE_SOCKET', '/var/run/tailscale/tailscaled.sock')
TAILSCALE_BIN = os.environ.get('TAILSCALE_BIN', '/usr/bin/tailscale')
HEADSCALE_BIN = os.environ.get('HEADSCALE_BIN', '/usr/bin/headscale')
HEADSCALE_CONFIG = Path(os.environ.get('HEADSCALE_CONFIG', '/etc/headscale/config.yaml'))
HEADSCALE_DB = Path(os.environ.get('HEADSCALE_DB', '/var/lib/headscale/db.sqlite'))
EXTRA_RECORDS_FILE = Path(os.environ.get('HEADSCALE_EXTRA_RECORDS', '/var/lib/headscale/extra-records.json'))
POLICY_FILE = Path(os.environ.get('HEADSCALE_POLICY_FILE', '/etc/headscale/policy.hujson'))
CONTROL_HOST = os.environ.get('KOMARI_TS_CONTROL_HOST', '127.0.0.1')
CONTROL_PORT = int(os.environ.get('KOMARI_TS_CONTROL_PORT', '25779'))
_NETCHECK_CACHE = {'data': None, 'ts': 0.0}


def _default_observer_name():
    try:
        host = socket.gethostname().split('.')[0].strip()
        if host:
            return host
    except Exception:
        pass
    return 'local-node'

NODE_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,61}$')
USER_NAME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9._-]{0,61}$')
TAG_RE = re.compile(r'^tag:[a-zA-Z0-9._-]{1,48}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$')
EXPIRATION_MAP = {
    '1h': '1h',
    '24h': '24h',
    '7d': '168h',
    '30d': '720h',
    '90d': '2160h',
    '365d': '8760h',
}
ACTION_LOCK = threading.Lock()


class LocalAPIConnection(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('local-tailscaled.sock', timeout=2)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCKET)


def local_api(path, method='GET'):
    connection = LocalAPIConnection()
    try:
        connection.request(method, '/localapi/v0/' + path)
        response = connection.getresponse()
        body = response.read(1 << 20)
        if response.status != 200:
            raise RuntimeError('Tailscale local API returned HTTP ' + str(response.status))
        return json.loads(body)
    finally:
        connection.close()


def parse_timestamp(value):
    """Normalize Headscale protobuf timestamp dicts or ISO strings into UTC ISO-8601."""
    if not value:
        return None
    if isinstance(value, dict):
        seconds = value.get('seconds')
        nanos = value.get('nanos', 0) or 0
        if isinstance(seconds, (int, float)) and seconds > 0:
            dt = datetime.datetime.fromtimestamp(seconds + (nanos / 1e9), tz=datetime.timezone.utc)
            if dt.year <= 1970:
                return None
            return dt.isoformat()
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text or text.startswith('0001-01-01') or text.startswith('1970-01-01T00:00:00'):
            return None
        return text
    return None


def is_timestamp_expired(iso_text, now=None):
    if not iso_text:
        return False
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    try:
        normalized = iso_text.replace('Z', '+00:00')
        parsed = datetime.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed <= now
    except ValueError:
        return False


def preferred_ip(addresses):
    valid = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        network = '100.64.0.0/10' if ip.version == 4 else 'fd7a:115c:a1e0::/48'
        if ip in ipaddress.ip_network(network):
            valid.append(ip)
    valid.sort(key=lambda ip: (ip.version, int(ip)))
    return str(valid[0]) if valid else None


def connection_result(result):
    """Classify only the path actually reported by a successful probe."""
    if result.get('Err'):
        return {'connection': 'unreachable', 'latency_ms': None, 'relay': None}
    seconds = result.get('LatencySeconds')
    latency = round(seconds * 1000, 1) if isinstance(seconds, (int, float)) and seconds >= 0 else None
    if result.get('IsLocalIP'):
        return {'connection': 'self', 'latency_ms': None, 'relay': None}
    if result.get('PeerRelay'):
        return {'connection': 'peer-relay', 'latency_ms': latency, 'relay': str(result['PeerRelay'])}
    if result.get('DERPRegionID') or result.get('DERPRegionCode'):
        return {'connection': 'relay', 'latency_ms': latency, 'relay': str(result.get('DERPRegionCode') or result['DERPRegionID'])}
    if result.get('Endpoint'):
        return {'connection': 'direct', 'latency_ms': latency, 'relay': None}
    return {'connection': 'unknown', 'latency_ms': latency, 'relay': None}


def probe(address):
    query = urllib.parse.urlencode({'ip': address, 'type': 'disco'})
    # A first response can use DERP while NAT traversal finds a direct path.
    result = None
    for _ in range(2):
        try:
            result = connection_result(local_api('ping?' + query, 'POST'))
        except (OSError, ValueError, RuntimeError, http.client.HTTPException):
            if result is None:
                result = {'connection': 'unreachable', 'latency_ms': None, 'relay': None}
            continue
        if result['connection'] not in ('relay', 'peer-relay', 'unreachable'):
            break
    return result


def headscale_cli(*args, timeout=5):
    command = [HEADSCALE_BIN, *args, '--output', 'json']
    process = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    stdout = (process.stdout or '').strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except ValueError:
        return {'raw': stdout}


def parse_netcheck_output(raw_text, checked_at=None):
    if not raw_text:
        return None
    text = str(raw_text)
    brace_idx = text.find('{')
    if brace_idx < 0:
        return None
    try:
        obj = json.loads(text[brace_idx:])
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None

    latencies = {}
    raw_lat = obj.get('RegionLatency') or {}
    if isinstance(raw_lat, dict):
        for k, v in raw_lat.items():
            if isinstance(v, (int, float)) and v > 0:
                latencies[str(k)] = round(v / 1e6, 1)

    mv = obj.get('MappingVariesByDestIP')
    mapping_varies = bool(mv) if isinstance(mv, bool) else None
    pref_derp = obj.get('PreferredDERP')
    return {
        'checked_at': checked_at or datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'udp': bool(obj.get('UDP', False)),
        'ipv4': bool(obj.get('IPv4', False)),
        'ipv6': bool(obj.get('IPv6', False)),
        'ipv4_can_send': bool(obj.get('IPv4CanSend', False)),
        'ipv6_can_send': bool(obj.get('IPv6CanSend', False)),
        'icmpv4': bool(obj.get('ICMPv4', False)),
        'mapping_varies': mapping_varies,
        'upnp': str(obj.get('UPnP') or ''),
        'pmp': str(obj.get('PMP') or ''),
        'pcp': str(obj.get('PCP') or ''),
        'preferred_derp': int(pref_derp) if isinstance(pref_derp, int) else 0,
        'global_v4': str(obj.get('GlobalV4') or ''),
        'global_v6': str(obj.get('GlobalV6') or ''),
        'region_latency_ms': latencies,
    }


def get_netcheck(force=False, timeout=5):
    now = time.time()
    if not force and _NETCHECK_CACHE['data'] is not None and (now - _NETCHECK_CACHE['ts']) < 60:
        return _NETCHECK_CACHE['data']
    try:
        proc = subprocess.run(
            [TAILSCALE_BIN, 'netcheck', '--format=json'],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        parsed = parse_netcheck_output(proc.stdout or proc.stderr or '')
        if parsed:
            _NETCHECK_CACHE['data'] = parsed
            _NETCHECK_CACHE['ts'] = now
            return parsed
    except Exception:
        pass
    return _NETCHECK_CACHE['data']


def build_diagnostics(derpmap=None, netcheck=None, derp_server_cfg=None, nodes_rows=None):
    srv = dict(derp_server_cfg or {})
    default_srv = {
        'enabled': bool(srv.get('enabled', True)),
        'region_id': int(srv.get('region_id') or 999),
        'region_code': str(srv.get('region_code') or 'local'),
        'region_name': str(srv.get('region_name') or 'Embedded DERP'),
        'verify_clients': bool(srv.get('verify_clients', True)),
        'private_only': bool(srv.get('private_only', True)),
        'stun_listen_addr': str(srv.get('stun_listen_addr') or '0.0.0.0:3478'),
        'ipv4': str(srv.get('ipv4') or ''),
    }

    regions_raw = (derpmap or {}).get('Regions') if isinstance(derpmap, dict) else None
    regions_list = []
    lat_map = (netcheck or {}).get('region_latency_ms') or {}
    pref_id = (netcheck or {}).get('preferred_derp') or 0

    if isinstance(regions_raw, dict) and regions_raw:
        for _, reg in sorted(regions_raw.items(), key=lambda item: int(item[1].get('RegionID') or 0) if isinstance(item[1], dict) else 0):
            if not isinstance(reg, dict):
                continue
            rid = int(reg.get('RegionID') or 0)
            rcode = str(reg.get('RegionCode') or '')
            rname = str(reg.get('RegionName') or rcode or f'Region {rid}')
            rnodes = reg.get('Nodes') or []
            first_node = rnodes[0] if (isinstance(rnodes, list) and rnodes and isinstance(rnodes[0], dict)) else {}
            host = str(first_node.get('HostName') or first_node.get('IPv4') or default_srv['ipv4'])
            ipv4 = str(first_node.get('IPv4') or '')
            stun_port = int(first_node.get('STUNPort') or 3478)
            derp_port = int(first_node.get('DERPPort') or 443)
            is_embedded = bool(default_srv['enabled'] and rid == default_srv['region_id'])

            relay_names = []
            for nrow in nodes_rows or []:
                if nrow.get('connection') == 'relay':
                    r_tag = str(nrow.get('relay') or '')
                    if r_tag in (str(rid), rcode):
                        relay_names.append(str(nrow.get('name') or ''))

            regions_list.append({
                'region_id': rid,
                'region_code': rcode,
                'region_name': rname,
                'hostname': host,
                'ipv4': ipv4,
                'stun_port': stun_port,
                'derp_port': derp_port,
                'latency_ms': lat_map.get(str(rid)),
                'is_preferred': bool(pref_id == rid),
                'is_embedded': is_embedded,
                'verify_clients': default_srv['verify_clients'] if is_embedded else None,
                'relay_nodes_count': len(relay_names),
                'relay_node_names': relay_names,
            })
    elif default_srv['enabled']:
        rid = default_srv['region_id']
        rcode = default_srv['region_code']
        relay_names = [
            str(nrow.get('name') or '')
            for nrow in (nodes_rows or [])
            if nrow.get('connection') == 'relay' and str(nrow.get('relay') or '') in (str(rid), rcode)
        ]
        regions_list.append({
            'region_id': rid,
            'region_code': rcode,
            'region_name': default_srv['region_name'],
            'hostname': default_srv['ipv4'],
            'ipv4': default_srv['ipv4'],
            'stun_port': 3478,
            'derp_port': 443,
            'latency_ms': lat_map.get(str(rid)),
            'is_preferred': bool(pref_id == rid),
            'is_embedded': True,
            'verify_clients': default_srv['verify_clients'],
            'relay_nodes_count': len(relay_names),
            'relay_node_names': relay_names,
        })

    return {
        'derp_server': default_srv,
        'derp_regions': regions_list,
        'netcheck': netcheck or {
            'checked_at': None,
            'udp': False,
            'ipv4': False,
            'ipv6': False,
            'ipv4_can_send': False,
            'ipv6_can_send': False,
            'icmpv4': False,
            'mapping_varies': None,
            'upnp': '',
            'pmp': '',
            'pcp': '',
            'preferred_derp': 0,
            'global_v4': '',
            'global_v6': '',
            'region_latency_ms': {},
        },
    }


def normalize_dns_record(name, value, base_domain='nodes.internal'):
    raw_name = str(name or '').strip().rstrip('.').lower()
    if not raw_name:
        raise ValueError('请输入解析域名')
    if '.' not in raw_name:
        if not NODE_NAME_RE.match(raw_name):
            raise ValueError('短主机名仅允许字母、数字、连字符或下划线')
        raw_name = f'{raw_name}.{base_domain.strip(".")}'
    if not DOMAIN_RE.match(raw_name):
        raise ValueError(f'域名格式无效：{raw_name}（示例：nas.nodes.internal 或 git.lan）')

    raw_val = str(value or '').strip()
    if not raw_val:
        raise ValueError('请输入指向的 IP 地址')
    try:
        ip_obj = ipaddress.ip_address(raw_val)
    except ValueError:
        raise ValueError(f'无效的 IPv4/IPv6 地址：{raw_val}')

    return {
        'name': raw_name,
        'type': 'A' if ip_obj.version == 4 else 'AAAA',
        'value': str(ip_obj),
    }


def _normalize_extra_records_list(raw_records, base_domain='nodes.internal'):
    items = []
    seen = set()
    if not isinstance(raw_records, list):
        return items
    for r in raw_records:
        if not isinstance(r, dict):
            continue
        try:
            norm = normalize_dns_record(r.get('name'), r.get('value'), base_domain=base_domain)
        except ValueError:
            continue
        key = (norm['name'], norm['type'], norm['value'])
        if key not in seen:
            seen.add(key)
            items.append(norm)
    items.sort(key=lambda x: (x['name'], x['type'], x['value']))
    return items


def strip_hujson_to_json(text):
    """Strip // line comments, /* */ block comments, and trailing commas from HuJSON text."""
    out = []
    i = 0
    n = len(text)
    in_str = False
    esc = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < n and text[i + 1] == '/':
            i += 2
            while i < n and text[i] not in '\r\n':
                i += 1
            continue
        if ch == '/' and i + 1 < n and text[i + 1] == '*':
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    no_comments = ''.join(out)
    return re.sub(r',\s*([}\]])', r'\1', no_comments)


def summarize_acl_policy(raw_text, mode='file', path='/etc/headscale/policy.hujson'):
    default_raw = '{\n  "acls": [\n    {\n      "action": "accept",\n      "src": ["*"],\n      "dst": ["*:*"]\n    }\n  ]\n}'
    text = (raw_text or '').strip() or default_raw
    rules = []
    groups = {}
    tag_owners = {}
    hosts = {}
    ssh_rules = 0
    try:
        parsed = json.loads(strip_hujson_to_json(text))
        if isinstance(parsed, dict):
            # If the raw file is a single-line compact JSON without comments, pretty-format it for the editor
            if '\n' not in text and '//' not in text and '/*' not in text:
                text = json.dumps(parsed, ensure_ascii=False, indent=2)
            for item in parsed.get('acls') or []:
                if not isinstance(item, dict):
                    continue
                src_list = [str(s) for s in (item.get('src') or []) if s]
                dst_list = [str(d) for d in (item.get('dst') or []) if d]
                rules.append({
                    'action': str(item.get('action') or 'accept'),
                    'src': src_list,
                    'dst': dst_list,
                    'proto': str(item.get('proto') or ''),
                })
            if isinstance(parsed.get('groups'), dict):
                for k, v in parsed['groups'].items():
                    if isinstance(v, list):
                        groups[str(k)] = [str(x) for x in v]
            if isinstance(parsed.get('tagOwners'), dict):
                for k, v in parsed['tagOwners'].items():
                    if isinstance(v, list):
                        tag_owners[str(k)] = [str(x) for x in v]
            if isinstance(parsed.get('hosts'), dict):
                for k, v in parsed['hosts'].items():
                    hosts[str(k)] = str(v)
            if isinstance(parsed.get('ssh'), list):
                ssh_rules = len(parsed['ssh'])
    except ValueError:
        pass

    return {
        'mode': mode,
        'path': str(path),
        'raw': text,
        'rules': rules,
        'rules_count': len(rules),
        'groups': groups,
        'tag_owners': tag_owners,
        'hosts': hosts,
        'ssh_rules_count': ssh_rules,
    }


def read_headscale_config():
    config = {
        'server_url': '',
        'base_domain': 'nodes.internal',
        'magic_dns': True,
        'override_local_dns': False,
        'nameservers_global': [],
        'nameservers_split': {},
        'search_domains': [],
        'extra_records': [],
        'policy_mode': 'file',
        'policy_path': str(POLICY_FILE),
        'derp_server': {
            'enabled': True,
            'region_id': 999,
            'region_code': 'local',
            'region_name': 'Embedded DERP',
            'verify_clients': True,
            'stun_listen_addr': '0.0.0.0:3478',
            'ipv4': '',
        },
    }
    raw_extra = []
    extra_path = None
    try:
        if HEADSCALE_CONFIG.exists():
            text = HEADSCALE_CONFIG.read_text(encoding='utf-8', errors='ignore')
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                if parsed.get('server_url'):
                    config['server_url'] = str(parsed['server_url']).strip()
                pol_sec = parsed.get('policy')
                if isinstance(pol_sec, dict):
                    if pol_sec.get('mode'):
                        config['policy_mode'] = str(pol_sec['mode']).strip()
                    if pol_sec.get('path'):
                        config['policy_path'] = str(pol_sec['path']).strip()
                derp_sec = parsed.get('derp')
                if isinstance(derp_sec, dict):
                    dsrv = derp_sec.get('server')
                    urls_list = derp_sec.get('urls')
                    private_only = not bool(urls_list)
                    if isinstance(dsrv, dict):
                        config['derp_server'] = {
                            'enabled': bool(dsrv.get('enabled', True)),
                            'region_id': int(dsrv.get('region_id') or 999),
                            'region_code': str(dsrv.get('region_code') or 'local'),
                            'region_name': str(dsrv.get('region_name') or 'Embedded DERP'),
                            'verify_clients': bool(dsrv.get('verify_clients', True)),
                            'private_only': private_only,
                            'stun_listen_addr': str(dsrv.get('stun_listen_addr') or '0.0.0.0:3478'),
                            'ipv4': str(dsrv.get('ipv4') or ''),
                        }
                dns_sec = parsed.get('dns')
                if isinstance(dns_sec, dict):
                    if dns_sec.get('base_domain'):
                        config['base_domain'] = str(dns_sec['base_domain']).strip()
                    if isinstance(dns_sec.get('magic_dns'), bool):
                        config['magic_dns'] = dns_sec['magic_dns']
                    if isinstance(dns_sec.get('override_local_dns'), bool):
                        config['override_local_dns'] = dns_sec['override_local_dns']
                    ns = dns_sec.get('nameservers')
                    if isinstance(ns, dict):
                        if isinstance(ns.get('global'), list):
                            config['nameservers_global'] = [str(x).strip() for x in ns['global'] if str(x).strip()]
                        if isinstance(ns.get('split'), dict):
                            split_clean = {}
                            for dom, servers in ns['split'].items():
                                if isinstance(servers, list):
                                    s_list = [str(s).strip() for s in servers if str(s).strip()]
                                    if dom and s_list:
                                        split_clean[str(dom).strip()] = s_list
                            config['nameservers_split'] = split_clean
                    if isinstance(dns_sec.get('search_domains'), list):
                        config['search_domains'] = [str(x).strip() for x in dns_sec['search_domains'] if str(x).strip()]
                    if isinstance(dns_sec.get('extra_records'), list):
                        raw_extra = dns_sec['extra_records']
                    if dns_sec.get('extra_records_path'):
                        extra_path = Path(str(dns_sec['extra_records_path']).strip())
            else:
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith('server_url:'):
                        val = stripped.split(':', 1)[1].strip().strip('"\'')
                        if val:
                            config['server_url'] = val
                    elif stripped.startswith('base_domain:'):
                        val = stripped.split(':', 1)[1].strip().strip('"\'')
                        if val:
                            config['base_domain'] = val
    except OSError:
        pass

    target_extra_file = extra_path or EXTRA_RECORDS_FILE
    try:
        if target_extra_file.exists():
            loaded = json.loads(target_extra_file.read_text(encoding='utf-8', errors='ignore'))
            if isinstance(loaded, list):
                raw_extra = loaded
    except (OSError, ValueError):
        pass

    config['extra_records'] = _normalize_extra_records_list(raw_extra, base_domain=config['base_domain'])

    policy_file = Path(config['policy_path'])
    raw_policy_text = ''
    try:
        if policy_file.exists():
            raw_policy_text = policy_file.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        pass
    config['acl'] = summarize_acl_policy(raw_policy_text, mode=config['policy_mode'], path=policy_file)
    return config


def _index_peers(status):
    by_id = {}
    by_key = {}
    by_ip = {}
    self_peer = status.get('Self') or {}
    all_peers = [self_peer, *((status.get('Peer') or {}).values())]
    for peer in all_peers:
        if not isinstance(peer, dict):
            continue
        node_id = peer.get('NodeID') or peer.get('ID')
        if node_id is not None:
            try:
                by_id[int(node_id)] = peer
            except (ValueError, TypeError):
                pass
        pub_key = peer.get('PublicKey')
        if pub_key:
            by_key[str(pub_key)] = peer
        for ip in peer.get('TailscaleIPs') or []:
            by_ip[str(ip)] = peer
    return by_id, by_key, by_ip


def _normalize_routes(raw_routes, nodes_rows):
    normalized = []
    seen = set()
    if isinstance(raw_routes, list):
        for item in raw_routes:
            if not isinstance(item, dict):
                continue
            prefix = str(item.get('prefix') or item.get('route') or '').strip()
            node_info = item.get('node') or {}
            node_id = item.get('node_id') or node_info.get('id')
            node_name = str(node_info.get('given_name') or node_info.get('name') or item.get('node_name') or '')
            if not prefix:
                continue
            key = (node_id, prefix)
            if key in seen:
                continue
            seen.add(key)
            entry = {
                'id': item.get('id'),
                'node_id': int(node_id) if isinstance(node_id, int) else None,
                'node_name': node_name,
                'prefix': prefix,
                'advertised': bool(item.get('advertised', True)),
                'enabled': bool(item.get('enabled', False)),
                'is_primary': bool(item.get('is_primary', False)),
                'is_exit': prefix in ('0.0.0.0/0', '::/0'),
            }
            normalized.append(entry)

    routes_by_node = {}
    for route in normalized:
        nid = route.get('node_id')
        if nid is not None:
            routes_by_node.setdefault(nid, []).append(route)

    for row in nodes_rows:
        nid = row.get('id')
        node_routes = list(routes_by_node.get(nid, []))
        existing_prefixes = {r['prefix'] for r in node_routes}
        approved_set = set(row.pop('_approved_subnets', []) or [])
        for prefix in row.pop('_extra_subnets', []):
            if prefix not in existing_prefixes:
                is_enabled = (prefix in approved_set) if approved_set is not None else True
                r_obj = {
                    'id': None,
                    'node_id': nid,
                    'node_name': row['name'],
                    'prefix': prefix,
                    'advertised': True,
                    'enabled': is_enabled,
                    'is_primary': is_enabled,
                    'is_exit': prefix in ('0.0.0.0/0', '::/0'),
                }
                node_routes.append(r_obj)
                normalized.append(r_obj)
        row['routes'] = node_routes
        if any(r.get('is_exit') and r.get('enabled') for r in node_routes):
            row['exit_node'] = True
    return normalized


def _normalize_users(raw_users, nodes_rows, keys_rows=None):
    users = []
    seen = set()
    if isinstance(raw_users, list):
        for u in raw_users:
            if not isinstance(u, dict):
                continue
            uid = u.get('id')
            name = str(u.get('name') or '').strip()
            if not name or name in seen:
                continue
            seen.add(name)
            users.append({
                'id': int(uid) if isinstance(uid, int) else uid,
                'name': name,
                'display_name': str(u.get('display_name') or '').strip(),
                'email': str(u.get('email') or '').strip(),
                'created_at': parse_timestamp(u.get('created_at')),
            })
    if not users:
        for row in nodes_rows:
            uname = row.get('user')
            uid = row.get('user_id')
            if uname and uname not in seen:
                seen.add(uname)
                users.append({
                    'id': uid if uid is not None else len(users) + 1,
                    'name': uname,
                    'display_name': '',
                    'email': '',
                    'created_at': None,
                })

    node_counts = {}
    online_counts = {}
    for row in nodes_rows or []:
        uname = str(row.get('user') or '')
        if uname:
            node_counts[uname] = node_counts.get(uname, 0) + 1
            if row.get('online') is True:
                online_counts[uname] = online_counts.get(uname, 0) + 1

    key_counts = {}
    for k in keys_rows or []:
        if k.get('state') == 'active':
            uname = str(k.get('user') or '')
            if uname:
                key_counts[uname] = key_counts.get(uname, 0) + 1

    for u in users:
        uname = u['name']
        u['node_count'] = node_counts.get(uname, 0)
        u['online_count'] = online_counts.get(uname, 0)
        u['active_key_count'] = key_counts.get(uname, 0)

    return users


def _mask_key(key_text):
    if not key_text:
        return ''
    text = str(key_text)
    if '***' in text:
        return text
    if len(text) > 16:
        return text[:16] + '-***'
    return text[:4] + '***'


def _normalize_preauthkeys(raw_keys):
    if not isinstance(raw_keys, list):
        return []
    now = datetime.datetime.now(datetime.timezone.utc)
    items = []
    for k in raw_keys:
        if not isinstance(k, dict):
            continue
        kid = k.get('id')
        user_obj = k.get('user') or {}
        created_at = parse_timestamp(k.get('created_at'))
        expiration = parse_timestamp(k.get('expiration'))
        expired = is_timestamp_expired(expiration, now=now)
        used = bool(k.get('used', False))
        reusable = bool(k.get('reusable', False))
        ephemeral = bool(k.get('ephemeral', False))
        if expired:
            state = 'expired'
        elif used and not reusable:
            state = 'used'
        else:
            state = 'active'
        items.append({
            'id': int(kid) if isinstance(kid, int) else kid,
            'key_preview': _mask_key(k.get('key') or k.get('prefix') or ''),
            'user': str(user_obj.get('name') or 'default'),
            'user_id': user_obj.get('id'),
            'reusable': reusable,
            'ephemeral': ephemeral,
            'used': used,
            'state': state,
            'created_at': created_at,
            'expiration': expiration,
            'acl_tags': sorted(set(k.get('acl_tags') or [])),
        })
    items.sort(key=lambda item: (item['state'] != 'active', -(item['id'] if isinstance(item['id'], int) else 0)))
    return items


def build_snapshot(nodes, status, probe_function=probe, users=None, preauthkeys=None, routes=None, config=None, derpmap=None, netcheck=None, local_prefs=None):
    self_peer = status.get('Self') or {}
    self_addresses = set(self_peer.get('TailscaleIPs') or status.get('TailscaleIPs') or [])
    peers_by_id, peers_by_key, peers_by_ip = _index_peers(status)
    hs_config = config or {'server_url': '', 'base_domain': 'nodes.internal'}
    prefs = local_prefs if isinstance(local_prefs, dict) else {}
    pref_adv_routes = [str(r) for r in (prefs.get('AdvertiseRoutes') or []) if r]
    local_exit_adv = ('0.0.0.0/0' in pref_adv_routes) or ('::/0' in pref_adv_routes)
    local_subnet_adv = [r for r in pref_adv_routes if r not in ('0.0.0.0/0', '::/0')]
    magic_suffix = str(
        status.get('MagicDNSSuffix')
        or (status.get('CurrentTailnet') or {}).get('MagicDNSSuffix')
        or hs_config.get('base_domain')
        or 'nodes.internal'
    ).strip('.')

    rows = []
    pending = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for node in nodes:
            addresses = list(node.get('ip_addresses') or [])
            online = node.get('online')
            raw_id = node.get('id')
            node_id = int(raw_id) if isinstance(raw_id, int) else None

            peer = None
            if node_id is not None and node_id in peers_by_id:
                peer = peers_by_id[node_id]
            elif node.get('node_key') and str(node.get('node_key')) in peers_by_key:
                peer = peers_by_key[str(node.get('node_key'))]
            else:
                for addr in addresses:
                    if addr in peers_by_ip:
                        peer = peers_by_ip[addr]
                        break

            hostname = str(node.get('name') or (peer or {}).get('HostName') or '')
            display_name = str(node.get('given_name') or hostname or '未命名节点')
            user_obj = node.get('user') or {}
            user_name = str(user_obj.get('name') or 'default')
            user_id = user_obj.get('id')

            dns_name = str((peer or {}).get('DNSName') or '').rstrip('.')
            if not dns_name and display_name and magic_suffix:
                dns_name = f'{display_name}.{magic_suffix}'

            cur_addr = str((peer or {}).get('CurAddr') or '').strip()
            peer_addrs = [str(a) for a in ((peer or {}).get('Addrs') or node.get('endpoints') or []) if a]
            if cur_addr and cur_addr not in peer_addrs:
                peer_addrs.insert(0, cur_addr)
            active_endpoint = cur_addr or (peer_addrs[0] if peer_addrs else None)

            extra_subnets = []
            approved_subnets = []
            for allowed in (peer or {}).get('AllowedIPs') or []:
                try:
                    net = ipaddress.ip_network(str(allowed), strict=False)
                    if (net.version == 4 and net.prefixlen < 32) or (net.version == 6 and net.prefixlen < 128):
                        s_net = str(net)
                        extra_subnets.append(s_net)
                        approved_subnets.append(s_net)
                except ValueError:
                    continue
            for sub in (node.get('approved_routes') or []) + (node.get('subnet_routes') or []):
                if sub and str(sub) not in approved_subnets:
                    approved_subnets.append(str(sub))
            for sub in (node.get('approved_routes') or []) + (node.get('available_routes') or []) + (node.get('subnet_routes') or []):
                if sub and str(sub) not in extra_subnets:
                    extra_subnets.append(str(sub))
            is_obs = bool(self_addresses.intersection(addresses))
            if is_obs:
                for sub in pref_adv_routes:
                    if sub not in extra_subnets:
                        extra_subnets.append(sub)

            tags = sorted(set((node.get('forced_tags') or []) + (node.get('valid_tags') or [])))
            reg_val = node.get('register_method')
            reg_label = {
                1: 'AuthKey',
                2: 'CLI',
                3: 'OIDC',
                'REGISTER_METHOD_AUTH_KEY': 'AuthKey',
                'REGISTER_METHOD_CLI': 'CLI',
                'REGISTER_METHOD_OIDC': 'OIDC',
            }.get(reg_val, 'AuthKey' if node.get('pre_auth_key') else '默认')

            expiry_iso = parse_timestamp(node.get('expiry'))
            row = {
                'id': node_id,
                'name': display_name,
                'hostname': hostname or display_name,
                'dns_name': dns_name,
                'user': user_name,
                'user_id': int(user_id) if isinstance(user_id, int) else None,
                'os': str((peer or {}).get('OS') or ''),
                'ips': addresses,
                'online': online if isinstance(online, bool) else None,
                'is_observer': is_obs,
                'connection': 'offline' if online is False else 'unknown',
                'latency_ms': None,
                'relay': None,
                'active_endpoint': active_endpoint,
                'endpoints': peer_addrs,
                'rx_bytes': int((peer or {}).get('RxBytes') or 0),
                'tx_bytes': int((peer or {}).get('TxBytes') or 0),
                'created_at': parse_timestamp(node.get('created_at')) or parse_timestamp((peer or {}).get('Created')),
                'last_seen': parse_timestamp(node.get('last_seen')) or parse_timestamp((peer or {}).get('LastSeen')) or parse_timestamp((peer or {}).get('LastWrite')),
                'last_handshake': parse_timestamp((peer or {}).get('LastHandshake')),
                'expiry': expiry_iso,
                'expiry_disabled': expiry_iso is None,
                'tags': tags,
                'exit_node': bool((peer or {}).get('ExitNode') or (peer or {}).get('ExitNodeOption') or ('0.0.0.0/0' in approved_subnets) or ('::/0' in approved_subnets)),
                'register_method': reg_label,
                '_extra_subnets': extra_subnets,
                '_approved_subnets': approved_subnets,
            }
            rows.append(row)
            if row['is_observer']:
                row['connection'] = 'self'
            elif online is not False and status.get('BackendState') == 'Running':
                address = preferred_ip(addresses)
                if address:
                    pending[executor.submit(probe_function, address)] = row
        for future in concurrent.futures.as_completed(pending):
            row = pending[future]
            try:
                row.update(future.result())
            except Exception:
                row['connection'] = 'unreachable'

    normalized_routes = _normalize_routes(routes, rows)
    normalized_keys = _normalize_preauthkeys(preauthkeys)
    normalized_users = _normalize_users(users, rows, keys_rows=normalized_keys)

    rows.sort(key=lambda row: (not row['is_observer'], preferred_ip(row['ips']) or row['name']))
    diagnostics = build_diagnostics(
        derpmap=derpmap,
        netcheck=netcheck,
        derp_server_cfg=hs_config.get('derp_server'),
        nodes_rows=rows,
    )
    observer_row = next((r for r in rows if r.get('is_observer')), None)
    control_url = hs_config.get('server_url') or str(status.get('ControlURL') or '')
    return {
        'schema': 1,
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'observer': self_peer.get('HostName') or _default_observer_name(),
        'control_state': status.get('BackendState', 'Unknown'),
        'interval_seconds': 15,
        'local_node': {
            'headscale_installed': Path(HEADSCALE_BIN).exists(),
            'headscale_config_exists': HEADSCALE_CONFIG.exists(),
            'tailscale_installed': Path(TAILSCALE_BIN).exists(),
            'tailscale_running': status.get('BackendState') == 'Running',
            'tailscale_state': str(status.get('BackendState') or 'Unknown'),
            'tailscale_version': str(status.get('Version') or ''),
            'observer_connected': bool(observer_row),
            'observer_name': str((observer_row or {}).get('name') or self_peer.get('HostName') or _default_observer_name()),
            'observer_ip': str(((observer_row or {}).get('ips') or [None])[0] or preferred_ip(list(self_addresses)) or ''),
            'server_url': control_url,
            'derp_enabled': bool(diagnostics['derp_server'].get('enabled', True)),
            'derp_region_code': str(diagnostics['derp_server'].get('region_code') or ''),
            'allow_incoming': not bool(prefs.get('ShieldsUp', False)),
            'accept_dns': bool(prefs.get('CorpDNS', True)),
            'accept_routes': bool(prefs.get('RouteAll', True)),
            'advertise_exit_node': bool(local_exit_adv or (observer_row and observer_row.get('exit_node'))),
            'advertise_routes': local_subnet_adv,
        },
        'tailnet': {
            'control_url': control_url,
            'magic_dns_suffix': magic_suffix,
            'magic_dns_enabled': bool(hs_config.get('magic_dns', (status.get('CurrentTailnet') or {}).get('MagicDNSEnabled', True))),
            'client_version': str(status.get('Version') or ''),
        },
        'dns': {
            'magic_dns': bool(hs_config.get('magic_dns', True)),
            'base_domain': magic_suffix,
            'override_local_dns': bool(hs_config.get('override_local_dns', False)),
            'nameservers_global': list(hs_config.get('nameservers_global') or []),
            'nameservers_split': dict(hs_config.get('nameservers_split') or {}),
            'search_domains': list(hs_config.get('search_domains') or []),
            'extra_records': list(hs_config.get('extra_records') or []),
        },
        'acl': hs_config.get('acl') or summarize_acl_policy(''),
        'diagnostics': diagnostics,
        'nodes': rows,
        'users': normalized_users,
        'preauthkeys': normalized_keys,
        'routes': normalized_routes,
        'errors': [],
    }


def collect():
    nodes = headscale_cli('nodes', 'list', timeout=4)
    if not isinstance(nodes, list):
        raise ValueError('Invalid Headscale node list')

    users = []
    try:
        raw_users = headscale_cli('users', 'list', timeout=4)
        if isinstance(raw_users, list):
            users = raw_users
    except Exception:
        pass

    preauthkeys = []
    try:
        raw_keys = headscale_cli('preauthkeys', 'list', timeout=4)
        if isinstance(raw_keys, list):
            preauthkeys = raw_keys
    except Exception:
        pass

    routes = []
    try:
        raw_routes = headscale_cli('nodes', 'list-routes', timeout=4)
        if isinstance(raw_routes, list):
            routes = raw_routes
    except Exception:
        pass

    derpmap = None
    try:
        derpmap = local_api('derpmap')
    except Exception:
        pass

    local_prefs = None
    try:
        local_prefs = local_api('prefs')
    except Exception:
        pass

    return build_snapshot(
        nodes,
        local_api('status'),
        users=users,
        preauthkeys=preauthkeys,
        routes=routes,
        config=read_headscale_config(),
        derpmap=derpmap,
        netcheck=get_netcheck(force=False),
        local_prefs=local_prefs,
    )


def _komari_ids():
    if os.geteuid() != 0:
        return None
    try:
        account = pwd.getpwnam('komari')
        return account.pw_uid, account.pw_gid
    except KeyError:
        return None


def _ensure_storage_dir():
    STORAGE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    ids = _komari_ids()
    if ids:
        os.chown(STORAGE_DIR, ids[0], ids[1])
        os.chmod(STORAGE_DIR, 0o700)


def write_snapshot(snapshot):
    _ensure_storage_dir()
    ids = _komari_ids()
    descriptor, name = tempfile.mkstemp(prefix='.status-', dir=OUTPUT.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            json.dump(snapshot, handle, ensure_ascii=False)
        if ids:
            os.chown(name, ids[0], ids[1])
        os.chmod(name, 0o600)
        os.replace(name, OUTPUT)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def ensure_control_token(preferred_token=None):
    _ensure_storage_dir()
    ids = _komari_ids()
    try:
        if not ENDPOINT_FILE.exists():
            ENDPOINT_FILE.write_text(f'http://{CONTROL_HOST}:{CONTROL_PORT}', encoding='utf-8')
            if ids:
                os.chown(ENDPOINT_FILE, ids[0], ids[1])
            os.chmod(ENDPOINT_FILE, 0o600)
    except OSError:
        pass
    if TOKEN_FILE.exists():
        try:
            existing = TOKEN_FILE.read_text(encoding='utf-8').strip()
            if len(existing) >= 32 and (not preferred_token or existing == preferred_token):
                if ids:
                    os.chown(TOKEN_FILE, ids[0], ids[1])
                os.chmod(TOKEN_FILE, 0o600)
                return existing
        except OSError:
            pass
    token = preferred_token if (preferred_token and len(preferred_token) >= 32) else secrets.token_hex(32)
    descriptor, name = tempfile.mkstemp(prefix='.token-', dir=STORAGE_DIR)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(token)
        if ids:
            os.chown(name, ids[0], ids[1])
        os.chmod(name, 0o600)
        os.replace(name, TOKEN_FILE)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return token


def _parse_positive_int(val, field_name):
    try:
        num = int(val)
    except (ValueError, TypeError):
        raise ValueError(f'{field_name} 参数无效')
    if num <= 0:
        raise ValueError(f'{field_name} 必须为正整数')
    return num


def _headscale_ids():
    if os.geteuid() != 0:
        return None
    try:
        account = pwd.getpwnam('headscale')
        return account.pw_uid, account.pw_gid
    except KeyError:
        return None


def upsert_dns_record(records, new_record, old_name=None, old_type=None, old_value=None):
    cleaned = []
    old_n = str(old_name or '').strip().lower()
    old_t = str(old_type or '').strip().upper()
    old_v = str(old_value or '').strip()
    for r in records:
        rn = str(r.get('name') or '').lower()
        rt = str(r.get('type') or '').upper()
        rv = str(r.get('value') or '')
        if old_n and rn == old_n and (not old_t or rt == old_t) and (not old_v or rv == old_v):
            continue
        if rn == new_record['name'] and rt == new_record['type']:
            continue
        cleaned.append({'name': rn, 'type': rt, 'value': rv})
    cleaned.append(new_record)
    cleaned.sort(key=lambda x: (x['name'], x['type'], x['value']))
    return cleaned


def remove_dns_record(records, name, record_type=None, value=None):
    target_n = str(name or '').strip().rstrip('.').lower()
    if not target_n:
        raise ValueError('请指定要删除的域名')
    target_t = str(record_type or '').strip().upper()
    target_v = str(value or '').strip()
    kept = []
    removed = 0
    for r in records:
        rn = str(r.get('name') or '').lower()
        rt = str(r.get('type') or '').upper()
        rv = str(r.get('value') or '')
        if rn == target_n and (not target_t or rt == target_t) and (not target_v or rv == target_v):
            removed += 1
            continue
        kept.append({'name': rn, 'type': rt, 'value': rv})
    if removed == 0:
        raise ValueError(f'未找到域名记录：{target_n}')
    return kept


def _validate_nameserver(server_str):
    s = str(server_str or '').strip()
    if not s:
        return None
    if s.startswith('https://'):
        parsed = urllib.parse.urlparse(s)
        if not parsed.netloc:
            raise ValueError(f'无效的 DoH 地址：{s}')
        return s
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        raise ValueError(f'DNS 服务器地址无效：{s}（请输入 IPv4/IPv6 或 https:// DoH 地址）')


def prepare_dns_config_update(raw_cfg_dict, payload):
    if not isinstance(raw_cfg_dict, dict):
        raise ValueError('Headscale 配置文件格式不支持在线修改')
    cfg = json.loads(json.dumps(raw_cfg_dict))
    dns_sec = cfg.setdefault('dns', {})
    base_domain = str(dns_sec.get('base_domain') or 'nodes.internal').strip()

    magic_dns = bool(payload.get('magic_dns', dns_sec.get('magic_dns', True)))
    override_local = bool(payload.get('override_local_dns', dns_sec.get('override_local_dns', False)))

    raw_global = payload.get('nameservers_global', [])
    if isinstance(raw_global, str):
        raw_global = [x.strip() for x in re.split(r'[,\s]+', raw_global) if x.strip()]
    global_ns = []
    for item in raw_global or []:
        validated = _validate_nameserver(item)
        if validated and validated not in global_ns:
            global_ns.append(validated)

    if override_local and not global_ns:
        raise ValueError('开启“覆盖本地 DNS”时，需至少填写一个全局 DNS 服务器（如 223.5.5.5）')

    raw_search = payload.get('search_domains', [])
    if isinstance(raw_search, str):
        raw_search = [x.strip() for x in re.split(r'[,\s]+', raw_search) if x.strip()]
    search_domains = []
    for dom in raw_search or []:
        d = str(dom).strip().rstrip('.').lower()
        if not d:
            continue
        if not DOMAIN_RE.match(d):
            raise ValueError(f'搜索域格式无效：{d}')
        if d not in search_domains:
            search_domains.append(d)

    raw_split = payload.get('nameservers_split', {})
    split_ns = {}
    if isinstance(raw_split, str):
        for line in raw_split.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if '=' in stripped:
                dom_part, servers_part = stripped.split('=', 1)
            elif ':' in stripped:
                dom_part, servers_part = stripped.split(':', 1)
            else:
                raise ValueError(f'分流 DNS 格式错误：{stripped}（格式：域名=DNS，如 corp.local=10.0.0.53）')
            d = dom_part.strip().rstrip('.').lower()
            if not DOMAIN_RE.match(d):
                raise ValueError(f'分流域名格式无效：{d}')
            servers = []
            for s_item in re.split(r'[,\s]+', servers_part.strip()):
                if not s_item:
                    continue
                v_ns = _validate_nameserver(s_item)
                if v_ns and v_ns not in servers:
                    servers.append(v_ns)
            if not servers:
                raise ValueError(f'分流域名 {d} 未指定有效 DNS 服务器')
            split_ns[d] = servers
    elif isinstance(raw_split, dict):
        for dom_part, s_list in raw_split.items():
            d = str(dom_part).strip().rstrip('.').lower()
            if not d:
                continue
            if not DOMAIN_RE.match(d):
                raise ValueError(f'分流域名格式无效：{d}')
            if isinstance(s_list, str):
                s_list = [x.strip() for x in re.split(r'[,\s]+', s_list) if x.strip()]
            servers = []
            for s_item in s_list or []:
                v_ns = _validate_nameserver(s_item)
                if v_ns and v_ns not in servers:
                    servers.append(v_ns)
            if servers:
                split_ns[d] = servers

    dns_sec['magic_dns'] = magic_dns
    dns_sec['base_domain'] = base_domain
    dns_sec['override_local_dns'] = override_local
    dns_sec['nameservers'] = {
        'global': global_ns,
        'split': split_ns,
    }
    dns_sec['search_domains'] = search_domains
    dns_sec.pop('extra_records', None)
    dns_sec['extra_records_path'] = str(EXTRA_RECORDS_FILE)
    return cfg


def _write_extra_records_file(records):
    EXTRA_RECORDS_FILE.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    hs_ids = _headscale_ids()
    content = json.dumps(records, ensure_ascii=False, indent=2) + '\n'
    # Write in-place so Headscale's fsnotify watcher on EXTRA_RECORDS_FILE receives IN_MODIFY/IN_CLOSE_WRITE
    with open(EXTRA_RECORDS_FILE, 'w', encoding='utf-8') as handle:
        handle.write(content)
    if hs_ids:
        os.chown(EXTRA_RECORDS_FILE, hs_ids[0], hs_ids[1])
    os.chmod(EXTRA_RECORDS_FILE, 0o640)


def _apply_headscale_config_dict(cfg_dict):
    fd, tmp_path = tempfile.mkstemp(prefix='.headscale-cfg-', suffix='.json', dir=HEADSCALE_CONFIG.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(cfg_dict, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
        os.chmod(tmp_path, 0o644)
        test_proc = subprocess.run(
            [HEADSCALE_BIN, 'configtest', '-c', tmp_path],
            capture_output=True,
            text=True,
            timeout=6,
        )
        if test_proc.returncode != 0:
            err_msg = (test_proc.stderr or test_proc.stdout or '配置校验未通过').strip()
            raise ValueError(f'Headscale 配置校验失败：{err_msg.splitlines()[-1]}')
        os.replace(tmp_path, HEADSCALE_CONFIG)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
    subprocess.run(['/usr/bin/systemctl', 'restart', 'headscale.service'], check=True, timeout=12)


def prepare_derp_config_update(existing_cfg, payload):
    if not isinstance(existing_cfg, dict):
        raise ValueError('无效的 Headscale 配置结构')
    cfg = json.loads(json.dumps(existing_cfg))

    raw_server_url = str(payload.get('server_url') or '').strip().rstrip('/')
    if raw_server_url:
        parsed_url = urllib.parse.urlparse(raw_server_url)
        if parsed_url.scheme not in ('http', 'https') or not parsed_url.netloc:
            raise ValueError('服务端地址格式无效（示例：https://hs.example.com）')
        cfg['server_url'] = raw_server_url

    derp_sec = cfg.setdefault('derp', {})
    if not isinstance(derp_sec, dict):
        derp_sec = {}
        cfg['derp'] = derp_sec
    srv = derp_sec.setdefault('server', {})
    if not isinstance(srv, dict):
        srv = {}
        derp_sec['server'] = srv

    enabled = bool(payload.get('enabled', True))
    verify_clients = bool(payload.get('verify_clients', True))
    private_only = bool(payload.get('private_only', True))
    region_code = str(payload.get('region_code') or srv.get('region_code') or 'local').strip()
    if not NODE_NAME_RE.match(region_code):
        raise ValueError('区域代码仅允许字母、数字、连字符或下划线（如 local）')
    region_name = str(payload.get('region_name') or srv.get('region_name') or f'{region_code} relay').strip()
    if len(region_name) > 64:
        raise ValueError('区域名称过长（最多 64 个字符）')

    raw_ipv4 = str(payload.get('ipv4') or srv.get('ipv4') or '').strip()
    if raw_ipv4:
        try:
            ip_obj = ipaddress.ip_address(raw_ipv4)
            if ip_obj.version != 4:
                raise ValueError('DERP 公网 IPv4 必须为 IPv4 地址')
            raw_ipv4 = str(ip_obj)
        except ValueError:
            raise ValueError(f'无效的 IPv4 地址：{raw_ipv4}')

    stun_port = int(payload.get('stun_port') or 3478)
    if stun_port < 1 or stun_port > 65535:
        raise ValueError('STUN 端口必须在 1-65535 之间')

    srv['enabled'] = enabled
    srv['region_id'] = int(srv.get('region_id') or 999)
    srv['region_code'] = region_code
    srv['region_name'] = region_name
    srv['verify_clients'] = verify_clients
    srv['stun_listen_addr'] = f'0.0.0.0:{stun_port}'
    srv['private_key_path'] = str(srv.get('private_key_path') or '/var/lib/headscale/derp_server_private.key')
    srv['automatically_add_embedded_derp_region'] = True
    if raw_ipv4:
        srv['ipv4'] = raw_ipv4

    derp_sec['urls'] = [] if private_only else ['https://controlplane.tailscale.com/derpmap/default']
    derp_sec['auto_update_enabled'] = not private_only
    return cfg


def validate_acl_policy_structure(raw_text):
    text = str(raw_text or '').strip()
    if not text:
        raise ValueError('ACL 策略内容不能为空')
    if len(text) > 131072:
        raise ValueError('ACL 策略文件过大')
    try:
        parsed = json.loads(strip_hujson_to_json(text))
    except ValueError as exc:
        raise ValueError(f'JSON / HuJSON 语法错误：{exc}')
    if not isinstance(parsed, dict):
        raise ValueError('ACL 策略根节点必须为 JSON 对象 ({...})')
    acls = parsed.get('acls')
    if acls is not None and not isinstance(acls, list):
        raise ValueError('acls 字段必须为数组 ([...])')
    if isinstance(acls, list):
        for idx, rule in enumerate(acls, 1):
            if not isinstance(rule, dict):
                raise ValueError(f'第 {idx} 条 ACL 规则必须为对象')
            if rule.get('action') not in (None, 'accept'):
                raise ValueError(f'第 {idx} 条规则 action 仅支持 "accept"')
            if not isinstance(rule.get('src'), list) or not rule.get('src'):
                raise ValueError(f'第 {idx} 条规则缺少有效的 src 数组')
            if not isinstance(rule.get('dst'), list) or not rule.get('dst'):
                raise ValueError(f'第 {idx} 条规则缺少有效的 dst 数组')
    return parsed


def _check_and_apply_acl_policy(raw_text, apply_changes=False):
    validate_acl_policy_structure(raw_text)
    hs_cfg = read_headscale_config()
    target_path = Path(hs_cfg.get('policy_path') or POLICY_FILE)
    target_dir = target_path.parent if target_path.parent.exists() else Path('/tmp')
    fd, tmp_path = tempfile.mkstemp(prefix='.policy-check-', suffix='.hujson', dir=target_dir)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(str(raw_text).strip() + '\n')
        os.chmod(tmp_path, 0o644)
        check_proc = subprocess.run(
            [HEADSCALE_BIN, 'policy', 'check', '-f', tmp_path],
            capture_output=True,
            text=True,
            timeout=6,
        )
        if check_proc.returncode != 0:
            err_text = (check_proc.stderr or check_proc.stdout or 'ACL 策略校验未通过').strip()
            last_line = err_text.splitlines()[-1] if err_text else '校验未通过'
            raise ValueError(f'策略校验未通过：{last_line}')
        if apply_changes:
            os.replace(tmp_path, target_path)
            subprocess.run(['/usr/bin/systemctl', 'reload', 'headscale.service'], check=True, timeout=8)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _ensure_tags_in_policy(tags):
    if not tags:
        return
    hs_cfg = read_headscale_config()
    acl_info = hs_cfg.get('acl') or {}
    raw_text = acl_info.get('raw') or ''
    try:
        parsed = json.loads(strip_hujson_to_json(raw_text)) if raw_text else {}
    except ValueError:
        return
    if not isinstance(parsed, dict):
        return
    tag_owners = parsed.setdefault('tagOwners', {})
    if not isinstance(tag_owners, dict):
        return
    groups = parsed.get('groups') or {}
    if 'group:admin' not in groups:
        users_raw = []
        try:
            users_raw = headscale_cli('users', 'list', timeout=4) or []
        except Exception:
            pass
        first_user = (users_raw[0].get('name') if (isinstance(users_raw, list) and users_raw and isinstance(users_raw[0], dict)) else 'default') or 'default'
        groups['group:admin'] = [f'{first_user}@']
        parsed['groups'] = groups
    default_owner = 'group:admin'
    changed = False
    for t in tags:
        if t not in tag_owners:
            tag_owners[t] = [default_owner]
            changed = True
    if changed:
        try:
            _check_and_apply_acl_policy(json.dumps(parsed, ensure_ascii=False, indent=2), apply_changes=True)
        except Exception:
            pass


def _ensure_extra_records_path_enabled(records):
    _write_extra_records_file(records)
    if not HEADSCALE_CONFIG.exists():
        return
    try:
        cfg_dict = json.loads(HEADSCALE_CONFIG.read_text(encoding='utf-8'))
    except ValueError:
        return
    if not isinstance(cfg_dict, dict):
        return
    dns_sec = cfg_dict.setdefault('dns', {})
    if dns_sec.get('extra_records_path') != str(EXTRA_RECORDS_FILE) or 'extra_records' in dns_sec:
        dns_sec.pop('extra_records', None)
        dns_sec['extra_records_path'] = str(EXTRA_RECORDS_FILE)
        _apply_headscale_config_dict(cfg_dict)


def parse_register_token(raw_input):
    text = str(raw_input or '').strip()
    if not text:
        raise ValueError('请输入节点注册链接、Auth ID 或 NodeKey')

    m_auth = re.search(r'--auth-id[=\s]+([A-Za-z0-9_-]{8,128})', text)
    if m_auth:
        return 'auth_id', m_auth.group(1)

    m_key = re.search(r'(?:--key|-k)[=\s]+([A-Za-z0-9:_-]{8,160})', text)
    if m_key:
        val = m_key.group(1)
        return ('node_key' if ':' in val else 'auth_id'), val

    m_url = re.search(r'/(?:register|a)/([A-Za-z0-9:_-]{8,160})', text)
    if m_url:
        val = m_url.group(1)
        return ('node_key' if ':' in val else 'auth_id'), val

    if text.startswith(('nodekey:', 'mkey:')):
        if not re.match(r'^(?:nodekey|mkey):[A-Za-z0-9]{16,128}$', text):
            raise ValueError('节点密钥格式无效')
        return 'node_key', text

    if re.match(r'^[A-Za-z0-9_-]{8,128}$', text):
        return 'auth_id', text

    raise ValueError('无法识别的注册标识，请粘贴注册链接、Auth ID 或 nodekey/mkey')


def _move_node_to_user(node_id, user_id):
    if not HEADSCALE_DB.exists():
        raise ValueError('未找到 Headscale 数据库文件')
    conn = sqlite3.connect(str(HEADSCALE_DB), timeout=5)
    try:
        user_row = conn.execute('SELECT id, name FROM users WHERE id = ? AND deleted_at IS NULL', (user_id,)).fetchone()
        if not user_row:
            raise ValueError(f'目标用户 #{user_id} 不存在')
        node_row = conn.execute('SELECT id, given_name, user_id FROM nodes WHERE id = ? AND deleted_at IS NULL', (node_id,)).fetchone()
        if not node_row:
            raise ValueError(f'节点 #{node_id} 不存在')
        if node_row[2] == user_id:
            return str(user_row[1])
        conn.execute('UPDATE nodes SET user_id = ? WHERE id = ?', (user_id, node_id))
        conn.commit()
    finally:
        conn.close()

    subprocess.run(
        ['/usr/bin/systemctl', 'restart', 'headscale.service'],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    for _ in range(12):
        try:
            headscale_cli('nodes', 'list', timeout=3)
            break
        except Exception:
            time.sleep(0.2)
    return str(user_row[1])


def _set_node_ipv4(node_id, new_ipv4):
    raw_ip = str(new_ipv4 or '').strip()
    if not raw_ip:
        raise ValueError('请输入有效的 IPv4 地址')
    try:
        ip_obj = ipaddress.IPv4Address(raw_ip)
    except ValueError:
        raise ValueError(f'无效的 IPv4 地址格式：{raw_ip}')
    cgnat_net = ipaddress.IPv4Network('100.64.0.0/10')
    if not (ip_obj in cgnat_net or ip_obj.is_private):
        raise ValueError('节点内网 IP 必须位于 Tailscale 内网网段 (100.64.0.0/10) 或私有网段内')

    normalized_ip = str(ip_obj)
    if not HEADSCALE_DB.exists():
        raise ValueError('未找到 Headscale 数据库文件')
    conn = sqlite3.connect(str(HEADSCALE_DB), timeout=5)
    try:
        node_row = conn.execute(
            'SELECT id, given_name, hostname, ipv4 FROM nodes WHERE id = ? AND deleted_at IS NULL',
            (node_id,),
        ).fetchone()
        if not node_row:
            raise ValueError(f'节点 #{node_id} 不存在')
        conflict_row = conn.execute(
            'SELECT id, given_name, hostname FROM nodes WHERE ipv4 = ? AND id != ? AND deleted_at IS NULL',
            (normalized_ip, node_id),
        ).fetchone()
        if conflict_row:
            conflict_name = conflict_row[1] or conflict_row[2] or f'#{conflict_row[0]}'
            raise ValueError(f'该内网 IP ({normalized_ip}) 已被节点「{conflict_name}」占用')
        if str(node_row[3] or '').strip() == normalized_ip:
            return normalized_ip
        conn.execute('UPDATE nodes SET ipv4 = ? WHERE id = ?', (normalized_ip, node_id))
        conn.commit()
    finally:
        conn.close()

    subprocess.run(
        ['/usr/bin/systemctl', 'restart', 'headscale.service'],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    for _ in range(12):
        try:
            headscale_cli('nodes', 'list', timeout=3)
            break
        except Exception:
            time.sleep(0.2)
    return normalized_ip


def build_export_bundle(snapshot):
    cfg_raw = ''
    try:
        if HEADSCALE_CONFIG.exists():
            cfg_raw = HEADSCALE_CONFIG.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        pass
    acl_raw = ((snapshot or {}).get('acl') or {}).get('raw') or ''
    diag = (snapshot or {}).get('diagnostics') or {}
    return {
        'backup_schema': 1,
        'exported_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'observer': (snapshot or {}).get('observer') or _default_observer_name(),
        'tailnet': (snapshot or {}).get('tailnet') or {},
        'dns': (snapshot or {}).get('dns') or {},
        'derp_config': diag.get('derp_server') or diag.get('derp_config') or {},
        'acl_policy_raw': acl_raw,
        'headscale_config_raw': cfg_raw,
        'users': (snapshot or {}).get('users') or [],
        'nodes': [
            {
                'id': n.get('id'),
                'name': n.get('name'),
                'hostname': n.get('hostname'),
                'user': n.get('user'),
                'ips': n.get('ips'),
                'tags': n.get('tags'),
                'routes': [r.get('prefix') for r in (n.get('routes') or []) if r.get('enabled')],
            }
            for n in ((snapshot or {}).get('nodes') or [])
        ],
        'routes': (snapshot or {}).get('routes') or [],
    }


def _restore_backup_bundle(raw_bundle, restore_dns=True, restore_acl=True, restore_derp=True):
    if isinstance(raw_bundle, str):
        text = raw_bundle.strip()
        if not text:
            raise ValueError('请提供备份 JSON 内容')
        try:
            bundle = json.loads(text)
        except ValueError as exc:
            raise ValueError(f'备份文件不是合法的 JSON 格式：{exc}')
    elif isinstance(raw_bundle, dict):
        bundle = raw_bundle
    else:
        raise ValueError('备份数据格式无效')

    if not isinstance(bundle, dict):
        raise ValueError('备份数据根节点必须为 JSON 对象')

    restored_parts = []
    raw_cfg = None
    cfg_modified = False
    if HEADSCALE_CONFIG.exists():
        try:
            loaded_cfg = json.loads(HEADSCALE_CONFIG.read_text(encoding='utf-8'))
            if isinstance(loaded_cfg, dict):
                raw_cfg = loaded_cfg
        except ValueError:
            raw_cfg = None

    if restore_dns and isinstance(bundle.get('dns'), dict):
        dns_data = bundle['dns']
        base_domain = str(dns_data.get('base_domain') or 'nodes.internal').strip() or 'nodes.internal'
        raw_records = dns_data.get('extra_records') or []
        cleaned_records = []
        if isinstance(raw_records, list):
            for item in raw_records:
                if isinstance(item, dict) and item.get('name') and item.get('value'):
                    cleaned_records.append(
                        normalize_dns_record(item.get('name'), item.get('value'), base_domain=base_domain)
                    )
        _write_extra_records_file(cleaned_records)
        if raw_cfg is not None:
            raw_cfg = prepare_dns_config_update(raw_cfg, {
                'magic_dns': dns_data.get('magic_dns', True),
                'override_local_dns': dns_data.get('override_local_dns', False),
                'nameservers_global': dns_data.get('nameservers_global') or [],
                'search_domains': dns_data.get('search_domains') or [],
                'nameservers_split': dns_data.get('nameservers_split') or {},
            })
            cfg_modified = True
        restored_parts.append('DNS 配置与解析记录')

    if restore_derp and raw_cfg is not None:
        derp_payload = {}
        if isinstance(bundle.get('derp_config'), dict) and bundle['derp_config']:
            dc = bundle['derp_config']
            stun_addr = str(dc.get('stun_listen_addr') or ':3478')
            try:
                stun_port = int(stun_addr.rsplit(':', 1)[-1])
            except ValueError:
                stun_port = int(dc.get('stun_port') or 3478)
            tailnet_info = bundle.get('tailnet') if isinstance(bundle.get('tailnet'), dict) else {}
            derp_payload = {
                'server_url': str(dc.get('server_url') or tailnet_info.get('control_url') or raw_cfg.get('server_url') or '').strip(),
                'enabled': dc.get('enabled', True),
                'verify_clients': dc.get('verify_clients', True),
                'private_only': dc.get('private_only', True),
                'region_code': dc.get('region_code') or 'local',
                'region_name': dc.get('region_name') or 'local relay',
                'ipv4': dc.get('ipv4') or '',
                'stun_port': stun_port,
            }
        elif isinstance(bundle.get('headscale_config_raw'), str) and bundle['headscale_config_raw'].strip():
            try:
                backup_cfg = json.loads(bundle['headscale_config_raw'])
                if isinstance(backup_cfg, dict) and isinstance(backup_cfg.get('derp'), dict):
                    raw_cfg['derp'] = backup_cfg['derp']
                    if backup_cfg.get('server_url'):
                        raw_cfg['server_url'] = backup_cfg['server_url']
                    cfg_modified = True
                    restored_parts.append('中继配置')
            except ValueError:
                pass
        if derp_payload:
            raw_cfg = prepare_derp_config_update(raw_cfg, derp_payload)
            cfg_modified = True
            restored_parts.append('中继配置')

    if cfg_modified and raw_cfg is not None:
        _apply_headscale_config_dict(raw_cfg)

    if restore_acl:
        acl_raw = ''
        if isinstance(bundle.get('acl_policy_raw'), str) and bundle['acl_policy_raw'].strip():
            acl_raw = bundle['acl_policy_raw']
        elif isinstance(bundle.get('acl'), dict) and isinstance(bundle['acl'].get('raw'), str) and bundle['acl']['raw'].strip():
            acl_raw = bundle['acl']['raw']
        if acl_raw:
            _check_and_apply_acl_policy(acl_raw, apply_changes=True)
            restored_parts.append('访问控制策略')

    if not restored_parts:
        raise ValueError('未选择要恢复的配置项，或备份文件中不包含有效配置数据')

    for _ in range(10):
        try:
            headscale_cli('nodes', 'list', timeout=3)
            break
        except Exception:
            time.sleep(0.2)
    return restored_parts


def _enable_linux_ip_forwarding():
    try:
        sysctl_conf = Path('/etc/sysctl.d/99-tailscale-forward.conf')
        sysctl_conf.write_text(
            'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n',
            encoding='utf-8',
        )
    except OSError:
        pass
    for key in ('net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1'):
        for sysctl_bin in ('/usr/sbin/sysctl', '/sbin/sysctl'):
            if Path(sysctl_bin).exists():
                try:
                    subprocess.run([sysctl_bin, '-w', key], capture_output=True, text=True, timeout=4)
                except Exception:
                    pass
                break


def _apply_local_tailscale_prefs(payload):
    if not Path(TAILSCALE_BIN).exists():
        return False
    has_pref_keys = any(
        k in payload
        for k in ('allow_incoming', 'accept_dns', 'accept_routes', 'advertise_exit_node', 'advertise_routes')
    )
    if not has_pref_keys:
        return False

    cmd = [TAILSCALE_BIN, 'set']
    if 'allow_incoming' in payload:
        shields_up = not bool(payload.get('allow_incoming'))
        cmd.append(f'--shields-up={"true" if shields_up else "false"}')
    if 'accept_dns' in payload:
        acc_dns = bool(payload.get('accept_dns'))
        cmd.append(f'--accept-dns={"true" if acc_dns else "false"}')
    if 'accept_routes' in payload:
        acc_routes = bool(payload.get('accept_routes'))
        cmd.append(f'--accept-routes={"true" if acc_routes else "false"}')

    exit_enabled = payload.get('advertise_exit_node')
    if exit_enabled is not None:
        exit_bool = bool(exit_enabled)
        if exit_bool:
            _enable_linux_ip_forwarding()
        cmd.append(f'--advertise-exit-node={"true" if exit_bool else "false"}')

    if 'advertise_routes' in payload:
        raw_adv = payload.get('advertise_routes') or []
        if isinstance(raw_adv, str):
            raw_adv = [r.strip() for r in raw_adv.split(',') if r.strip()]
        cleaned_adv = []
        for r in raw_adv:
            try:
                net = ipaddress.ip_network(str(r).strip(), strict=False)
                cleaned_adv.append(str(net))
            except ValueError:
                raise ValueError(f'无效的本机子网网段：{r}')
        if cleaned_adv:
            _enable_linux_ip_forwarding()
        cmd.append(f'--advertise-routes={",".join(cleaned_adv)}')

    if len(cmd) > 2:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)

    if exit_enabled is not None:
        try:
            status = local_api('status')
            self_ips = set((status.get('Self') or {}).get('TailscaleIPs') or status.get('TailscaleIPs') or [])
            nodes = headscale_cli('nodes', 'list', timeout=4) or []
            for n in nodes:
                n_ips = set(n.get('ip_addresses') or [])
                if self_ips.intersection(n_ips) and n.get('id'):
                    obs_id = int(n['id'])
                    existing_approved = [
                        str(r) for r in (n.get('approved_routes') or [])
                        if r and str(r) not in ('0.0.0.0/0', '::/0')
                    ]
                    if bool(exit_enabled):
                        next_routes = existing_approved + ['0.0.0.0/0', '::/0']
                    else:
                        next_routes = existing_approved
                    headscale_cli(
                        'nodes', 'approve-routes', '-i', str(obs_id), '-r', ','.join(next_routes), '--force', timeout=6
                    )
                    break
        except Exception:
            pass
    return True


_EN_EXACT_MESSAGES = {
    '请输入解析域名': 'Please enter a domain name',
    '短主机名仅允许字母、数字、连字符或下划线': 'Short hostnames may only contain letters, digits, hyphens, or underscores',
    '请输入指向的 IP 地址': 'Please enter a target IP address',
    '请指定要删除的域名': 'Please specify a domain to delete',
    'Headscale 配置文件格式不支持在线修改': 'Headscale config format does not support online editing',
    '开启“覆盖本地 DNS”时，需至少填写一个全局 DNS 服务器（如 223.5.5.5）': 'At least one global DNS server (e.g. 1.1.1.1) is required when "Override local DNS" is enabled',
    '无效的 Headscale 配置结构': 'Invalid Headscale config structure',
    '服务端地址格式无效（示例：https://hs.example.com）': 'Invalid server URL format (e.g. https://hs.example.com)',
    '区域代码仅允许字母、数字、连字符或下划线（如 local）': 'Region code may only contain letters, digits, hyphens, or underscores (e.g. local)',
    '区域名称过长（最多 64 个字符）': 'Region name is too long (max 64 characters)',
    'DERP 公网 IPv4 必须为 IPv4 地址': 'DERP public IPv4 must be a valid IPv4 address',
    'STUN 端口必须在 1-65535 之间': 'STUN port must be between 1 and 65535',
    'ACL 策略内容不能为空': 'ACL policy cannot be empty',
    'ACL 策略文件过大': 'ACL policy file is too large',
    'ACL 策略根节点必须为 JSON 对象 ({...})': 'ACL policy root must be a JSON object ({...})',
    'acls 字段必须为数组 ([...])': 'The "acls" field must be an array ([...])',
    '请输入节点注册链接、Auth ID 或 NodeKey': 'Please paste a registration URL, Auth ID, or NodeKey',
    '节点密钥格式无效': 'Invalid node key format',
    '无法识别的注册标识，请粘贴注册链接、Auth ID 或 nodekey/mkey': 'Unrecognized registration token. Please paste a registration URL, Auth ID, or nodekey/mkey',
    '未找到 Headscale 数据库文件': 'Headscale database file not found',
    '请输入有效的 IPv4 地址': 'Please enter a valid IPv4 address',
    '节点内网 IP 必须位于 Tailscale 内网网段 (100.64.0.0/10) 或私有网段内': 'Node IP must be within the Tailscale CGNAT range (100.64.0.0/10) or a private IPv4 range',
    '请提供备份 JSON 内容': 'Please provide backup JSON content',
    '备份数据格式无效': 'Invalid backup data format',
    '备份数据根节点必须为 JSON 对象': 'Backup data root must be a JSON object',
    '未选择要恢复的配置项，或备份文件中不包含有效配置数据': 'No restore items selected, or backup contains no valid configuration data',
    '请求参数格式错误': 'Invalid request parameters',
    '缺少操作类型 (action)': 'Missing action parameter',
    '已刷新组网状态': 'Mesh status refreshed',
    '未找到可用于测速的内网 IP': 'No tailnet IP available for ping',
    '测速完成：直连': 'Ping completed: Direct',
    '当前节点为本机': 'This is the local node',
    '未收到探测响应，节点可能离线或被防火墙拦截': 'No ping response received; node may be offline or blocked by a firewall',
    '节点名称仅允许字母、数字、点、下划线或连字符，且以字母或数字开头（1-62 位）': 'Node name must start with a letter or digit and contain only letters, digits, dots, underscores, or hyphens (1-62 chars)',
    '已将该节点设为密钥永不过期': 'Node key expiry disabled (never expires)',
    '节点会话已设为过期，客户端需重新认证': 'Node session expired; client must re-authenticate',
    '安全保护：不能直接移除当前控制面所在的本机节点': 'Safety guard: cannot remove the local control-plane node directly',
    '请至少提供一个有效标签（如 tag:server）': 'Please provide at least one valid tag (e.g. tag:server)',
    '节点标签已更新': 'Node tags updated',
    '节点子网路由审批已更新': 'Node route approvals updated',
    '不支持的有效期选项，请选择 1h、24h、7d、30d、90d 或 365d': 'Unsupported expiry option; choose 1h, 24h, 7d, 30d, 90d, or 365d',
    '密钥已生成，请复制保存': 'Pre-auth key created; please copy and save it',
    '解析记录已删除': 'DNS record deleted',
    '未找到 Headscale 配置文件': 'Headscale config file not found',
    'DNS 配置已生效': 'DNS settings applied',
    '策略语法校验通过': 'Policy syntax check passed',
    '访问控制策略已保存并生效': 'ACL policy saved and applied',
    '用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）': 'Username must start with a letter and contain only letters, digits, dots, underscores, or hyphens (1-62 chars)',
    '备注名称过长（最多 64 个字符）': 'Display name is too long (max 64 characters)',
    '邮箱格式无效': 'Invalid email address',
    '新用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）': 'New username must start with a letter and contain only letters, digits, dots, underscores, or hyphens (1-62 chars)',
    '用户已删除': 'User deleted',
    '网络诊断已完成': 'Network diagnostics completed',
    '请选择有效的所属用户': 'Please select a valid user',
    '已生成最新配置快照': 'Latest configuration snapshot generated',
    '本机与中继配置已保存并生效': 'Local & relay configuration saved and applied',
    '已开启本机作为出口节点并自动批准路由': 'Local exit node enabled and routes approved',
    '已关闭本机出口节点功能': 'Local exit node disabled',
    '本机 Tailscale 客户端已安装并启动服务': 'Local Tailscale client installed and started',
    '未检测到服务端地址 (server_url)': 'Server URL (server_url) not detected',
    '自动签发本机接入密钥失败': 'Failed to issue a pre-auth key for local node',
    '无法读取组网状态，请检查 Headscale、Tailscale 和采集服务。': 'Unable to read mesh status. Please check Headscale, Tailscale, and the collector service.',
    '未授权的本地控制请求': 'Unauthorized local control request',
    '未知路径': 'Unknown path',
    '请求体大小异常': 'Invalid request body size',
    '命令执行失败': 'Command execution failed',
    '配置校验未通过': 'Config validation failed',
    'ACL 策略校验未通过': 'ACL policy check failed',
    '校验未通过': 'Validation failed',
}

_EN_FIELD_NAMES = {
    '节点 ID': 'Node ID',
    '用户 ID': 'User ID',
    '目标用户 ID': 'Target User ID',
    '密钥 ID': 'Key ID',
}

_EN_RESTORE_PARTS = {
    'DNS 配置与解析记录': 'DNS settings & records',
    '中继配置': 'DERP relay config',
    '访问控制策略': 'ACL policy',
}

_EN_PATTERN_RULES = [
    (re.compile(r'^域名格式无效：(.+)（示例：nas\.nodes\.internal 或 git\.lan）$'), lambda m: f'Invalid domain format: {m.group(1)} (e.g. nas.nodes.internal or git.lan)'),
    (re.compile(r'^无效的 IPv4/IPv6 地址：(.+)$'), lambda m: f'Invalid IPv4/IPv6 address: {m.group(1)}'),
    (re.compile(r'^(.+) 参数无效$'), lambda m: f'Invalid {_EN_FIELD_NAMES.get(m.group(1), m.group(1))}'),
    (re.compile(r'^(.+) 必须为正整数$'), lambda m: f'{_EN_FIELD_NAMES.get(m.group(1), m.group(1))} must be a positive integer'),
    (re.compile(r'^未找到域名记录：(.+)$'), lambda m: f'DNS record not found: {m.group(1)}'),
    (re.compile(r'^无效的 DoH 地址：(.+)$'), lambda m: f'Invalid DoH URL: {m.group(1)}'),
    (re.compile(r'^DNS 服务器地址无效：(.+)（请输入 IPv4/IPv6 或 https:// DoH 地址）$'), lambda m: f'Invalid DNS server: {m.group(1)} (enter IPv4/IPv6 or https:// DoH URL)'),
    (re.compile(r'^搜索域格式无效：(.+)$'), lambda m: f'Invalid search domain: {m.group(1)}'),
    (re.compile(r'^分流 DNS 格式错误：(.+)（格式：域名=DNS，如 corp\.local=10\.0\.0\.53）$'), lambda m: f'Invalid Split DNS format: {m.group(1)} (use domain=DNS, e.g. corp.local=10.0.0.53)'),
    (re.compile(r'^分流域名格式无效：(.+)$'), lambda m: f'Invalid split domain: {m.group(1)}'),
    (re.compile(r'^分流域名 (.+) 未指定有效 DNS 服务器$'), lambda m: f'No valid DNS server specified for split domain {m.group(1)}'),
    (re.compile(r'^Headscale 配置校验失败：(.+)$'), lambda m: f'Headscale config check failed: {m.group(1)}'),
    (re.compile(r'^无效的 IPv4 地址：(.+)$'), lambda m: f'Invalid IPv4 address: {m.group(1)}'),
    (re.compile(r'^JSON / HuJSON 语法错误：(.+)$'), lambda m: f'JSON / HuJSON syntax error: {m.group(1)}'),
    (re.compile(r'^第 (\d+) 条 ACL 规则必须为对象$'), lambda m: f'ACL rule #{m.group(1)} must be an object'),
    (re.compile(r'^第 (\d+) 条规则 action 仅支持 "accept"$'), lambda m: f'ACL rule #{m.group(1)} action only supports "accept"'),
    (re.compile(r'^第 (\d+) 条规则缺少有效的 src 数组$'), lambda m: f'ACL rule #{m.group(1)} is missing a valid "src" array'),
    (re.compile(r'^第 (\d+) 条规则缺少有效的 dst 数组$'), lambda m: f'ACL rule #{m.group(1)} is missing a valid "dst" array'),
    (re.compile(r'^策略校验未通过：(.+)$'), lambda m: f'Policy validation failed: {m.group(1)}'),
    (re.compile(r'^目标用户 #(\d+) 不存在$'), lambda m: f'Target user #{m.group(1)} does not exist'),
    (re.compile(r'^节点 #(\d+) 不存在$'), lambda m: f'Node #{m.group(1)} does not exist'),
    (re.compile(r'^无效的 IPv4 地址格式：(.+)$'), lambda m: f'Invalid IPv4 address format: {m.group(1)}'),
    (re.compile(r'^该内网 IP \(([^)]+)\) 已被节点「(.+)」占用$'), lambda m: f'IP address ({m.group(1)}) is already used by node "{m.group(2)}"'),
    (re.compile(r'^备份文件不是合法的 JSON 格式：(.+)$'), lambda m: f'Backup file is not valid JSON: {m.group(1)}'),
    (re.compile(r'^无效的本机子网网段：(.+)$'), lambda m: f'Invalid local subnet CIDR: {m.group(1)}'),
    (re.compile(r'^测速完成：直连 \(([^)]+) ms\)$'), lambda m: f'Ping completed: Direct ({m.group(1)} ms)'),
    (re.compile(r'^测速完成：中继 (.+) \(([^)]+) ms\)$'), lambda m: f'Ping completed: Relay {m.group(1)} ({m.group(2)} ms)'),
    (re.compile(r'^测速完成：中继 (.+)$'), lambda m: f'Ping completed: Relay {m.group(1)}'),
    (re.compile(r'^节点已重命名为「(.+)」$'), lambda m: f'Node renamed to "{m.group(1)}"'),
    (re.compile(r'^节点 #(\d+) 已从组网中移除$'), lambda m: f'Node #{m.group(1)} removed from tailnet'),
    (re.compile(r'^标签格式不合法：(.+)（示例：tag:server）$'), lambda m: f'Invalid tag format: {m.group(1)} (e.g. tag:server)'),
    (re.compile(r'^标签格式不合法：(.+)$'), lambda m: f'Invalid tag format: {m.group(1)}'),
    (re.compile(r'^无效的 CIDR 子网网段：(.+)$'), lambda m: f'Invalid CIDR subnet: {m.group(1)}'),
    (re.compile(r'^预授权密钥 #(\d+) 已废止$'), lambda m: f'Pre-auth key #{m.group(1)} expired'),
    (re.compile(r'^预授权密钥 #(\d+) 已删除$'), lambda m: f'Pre-auth key #{m.group(1)} deleted'),
    (re.compile(r'^解析记录已保存：(.+) -> (.+)$'), lambda m: f'DNS record saved: {m.group(1)} -> {m.group(2)}'),
    (re.compile(r'^已创建用户「(.+)」$'), lambda m: f'User "{m.group(1)}" created'),
    (re.compile(r'^用户已重命名为「(.+)」$'), lambda m: f'User renamed to "{m.group(1)}"'),
    (re.compile(r'^用户「(.+)」下仍有 (\d+) 台设备，请先移除设备后再删除用户$'), lambda m: f'User "{m.group(1)}" still owns {m.group(2)} node(s); remove or move them first'),
    (re.compile(r'^全网测速完成：(\d+) 台直连，(\d+) 台中继$'), lambda m: f'Mesh ping completed: {m.group(1)} direct, {m.group(2)} relayed'),
    (re.compile(r'^已将节点迁移至用户「(.+)」$'), lambda m: f'Node moved to user "{m.group(1)}"'),
    (re.compile(r'^节点内网 IP 已修改为 (.+)$'), lambda m: f'Node tailnet IP updated to {m.group(1)}'),
    (re.compile(r'^节点已批准接入至用户「(.+)」$'), lambda m: f'Node approved and assigned to user "{m.group(1)}"'),
    (re.compile(r'^已成功恢复：(.+)$'), lambda m: 'Restored successfully: ' + ', '.join(_EN_RESTORE_PARTS.get(p, p) for p in m.group(1).split('、'))),
    (re.compile(r'^本机节点 \((.+)\) 已成功接入组网并设为永不过期$'), lambda m: f'Local node ({m.group(1)}) connected with key expiry disabled'),
    (re.compile(r'^未知的操作类型：(.+)$'), lambda m: f'Unknown action: {m.group(1)}'),
    (re.compile(r'^Headscale 执行失败：(.+)$'), lambda m: f'Headscale command failed: {m.group(1)}'),
    (re.compile(r'^操作失败：(.+)$'), lambda m: f'Action failed: {m.group(1)}'),
]

_ZHTW_EXACT_MESSAGES = {
    '请输入解析域名': '請輸入解析網域',
    '短主机名仅允许字母、数字、连字符或下划线': '短主機名稱僅允許英文字母、數字、連字號或底線',
    '请输入指向的 IP 地址': '請輸入指向的 IP 位址',
    '请指定要删除的域名': '請指定要刪除的網域',
    'Headscale 配置文件格式不支持在线修改': 'Headscale 設定檔格式不支援線上修改',
    '开启“覆盖本地 DNS”时，需至少填写一个全局 DNS 服务器（如 223.5.5.5）': '開啟「覆蓋本機 DNS」時，需至少填寫一個全域 DNS 伺服器（如 1.1.1.1）',
    '无效的 Headscale 配置结构': '無效的 Headscale 設定結構',
    '服务端地址格式无效（示例：https://hs.example.com）': '伺服器網址格式無效（範例：https://hs.example.com）',
    '区域代码仅允许字母、数字、连字符或下划线（如 local）': '區域代碼僅允許英文字母、數字、連字號或底線（如 local）',
    '区域名称过长（最多 64 个字符）': '區域名稱過長（最多 64 個字元）',
    'DERP 公网 IPv4 必须为 IPv4 地址': 'DERP 公開 IPv4 必須為有效的 IPv4 位址',
    'STUN 端口必须在 1-65535 之间': 'STUN 連接埠必須在 1-65535 之間',
    'ACL 策略内容不能为空': 'ACL 原則內容不能為空',
    'ACL 策略文件过大': 'ACL 原則檔案過大',
    'ACL 策略根节点必须为 JSON 对象 ({...})': 'ACL 原則根節點必須為 JSON 物件 ({...})',
    'acls 字段必须为数组 ([...])': 'acls 欄位必須為陣列 ([...])',
    '请输入节点注册链接、Auth ID 或 NodeKey': '請輸入節點註冊連結、Auth ID 或 NodeKey',
    '节点密钥格式无效': '節點金鑰格式無效',
    '无法识别的注册标识，请粘贴注册链接、Auth ID 或 nodekey/mkey': '無法辨識的註冊識別碼，請貼上註冊連結、Auth ID 或 nodekey/mkey',
    '未找到 Headscale 数据库文件': '找不到 Headscale 資料庫檔案',
    '请输入有效的 IPv4 地址': '請輸入有效的 IPv4 位址',
    '节点内网 IP 必须位于 Tailscale 内网网段 (100.64.0.0/10) 或私有网段内': '節點內網 IP 必須位於 Tailscale 內網網段 (100.64.0.0/10) 或私有網段內',
    '请提供备份 JSON 内容': '請提供備份 JSON 內容',
    '备份数据格式无效': '備份資料格式無效',
    '备份数据根节点必须为 JSON 对象': '備份資料根節點必須為 JSON 物件',
    '未选择要恢复的配置项，或备份文件中不包含有效配置数据': '未選擇要還原的設定項目，或備份檔中不包含有效設定資料',
    '请求参数格式错误': '請求參數格式錯誤',
    '缺少操作类型 (action)': '缺少操作類型 (action)',
    '已刷新组网状态': '已重新整理組網狀態',
    '未找到可用于测速的内网 IP': '找不到可用於測速的內網 IP',
    '测速完成：直连': '測速完成：直連',
    '当前节点为本机': '目前節點為本機',
    '未收到探测响应，节点可能离线或被防火墙拦截': '未收到探測回應，節點可能離線或被防火牆攔截',
    '节点名称仅允许字母、数字、点、下划线或连字符，且以字母或数字开头（1-62 位）': '節點名稱僅允許英文字母、數字、點號、底線或連字號，且須以字母或數字開頭（1-62 個字元）',
    '已将该节点设为密钥永不过期': '已將此節點設為金鑰永不過期',
    '节点会话已设为过期，客户端需重新认证': '節點工作階段已設為過期，用戶端須重新認證',
    '安全保护：不能直接移除当前控制面所在的本机节点': '安全防護：不能直接移除目前控制面所在的本機節點',
    '请至少提供一个有效标签（如 tag:server）': '請至少提供一個有效標籤（如 tag:server）',
    '节点标签已更新': '節點標籤已更新',
    '节点子网路由审批已更新': '節點子網路路由核准狀態已更新',
    '不支持的有效期选项，请选择 1h、24h、7d、30d、90d 或 365d': '不支援的效期選項，請選擇 1h、24h、7d、30d、90d 或 365d',
    '密钥已生成，请复制保存': '金鑰已產生，請複製並妥善儲存',
    '解析记录已删除': '解析記錄已刪除',
    '未找到 Headscale 配置文件': '找不到 Headscale 設定檔',
    'DNS 配置已生效': 'DNS 設定已生效',
    '策略语法校验通过': '原則語法驗證通過',
    '访问控制策略已保存并生效': '存取控制原則已儲存並生效',
    '用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）': '使用者名稱須以英文字母開頭，僅允許字母、數字、點號、底線或連字號（1-62 個字元）',
    '备注名称过长（最多 64 个字符）': '顯示名稱過長（最多 64 個字元）',
    '邮箱格式无效': '電子郵件格式無效',
    '新用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）': '新使用者名稱須以英文字母開頭，僅允許字母、數字、點號、底線或連字號（1-62 個字元）',
    '用户已删除': '使用者已刪除',
    '网络诊断已完成': '網路診斷已完成',
    '请选择有效的所属用户': '請選擇有效的所屬使用者',
    '已生成最新配置快照': '已產生最新設定快照',
    '本机与中继配置已保存并生效': '本機與中繼設定已儲存並生效',
    '已开启本机作为出口节点并自动批准路由': '已開啟本機作為出口節點並自動核准路由',
    '已关闭本机出口节点功能': '已關閉本機出口節點功能',
    '本机 Tailscale 客户端已安装并启动服务': '本機 Tailscale 用戶端已安裝並啟動服務',
    '未检测到服务端地址 (server_url)': '未偵測到伺服器網址 (server_url)',
    '自动签发本机接入密钥失败': '自動核發本機加入金鑰失敗',
    '无法读取组网状态，请检查 Headscale、Tailscale 和采集服务。': '無法讀取組網狀態，請檢查 Headscale、Tailscale 與採集服務。',
    '未授权的本地控制请求': '未授權的本機控制請求',
    '未知路径': '未知路徑',
    '请求体大小异常': '請求主體大小異常',
    '命令执行失败': '指令執行失敗',
    '配置校验未通过': '設定驗證未通過',
    'ACL 策略校验未通过': 'ACL 原則驗證未通過',
    '校验未通过': '驗證未通過',
}

_ZHTW_FIELD_NAMES = {
    '节点 ID': '節點 ID',
    '用户 ID': '使用者 ID',
    '目标用户 ID': '目標使用者 ID',
    '密钥 ID': '金鑰 ID',
}

_ZHTW_RESTORE_PARTS = {
    'DNS 配置与解析记录': 'DNS 設定與解析記錄',
    '中继配置': '中繼設定',
    '访问控制策略': '存取控制原則',
}

_ZHTW_PATTERN_RULES = [
    (re.compile(r'^域名格式无效：(.+)（示例：nas\.nodes\.internal 或 git\.lan）$'), lambda m: f'網域格式無效：{m.group(1)}（範例：nas.nodes.internal 或 git.lan）'),
    (re.compile(r'^无效的 IPv4/IPv6 地址：(.+)$'), lambda m: f'無效的 IPv4/IPv6 位址：{m.group(1)}'),
    (re.compile(r'^(.+) 参数无效$'), lambda m: f"{_ZHTW_FIELD_NAMES.get(m.group(1), m.group(1))} 參數無效"),
    (re.compile(r'^(.+) 必须为正整数$'), lambda m: f"{_ZHTW_FIELD_NAMES.get(m.group(1), m.group(1))} 必須為正整數"),
    (re.compile(r'^未找到域名记录：(.+)$'), lambda m: f'找不到網域記錄：{m.group(1)}'),
    (re.compile(r'^无效的 DoH 地址：(.+)$'), lambda m: f'無效的 DoH 位址：{m.group(1)}'),
    (re.compile(r'^DNS 服务器地址无效：(.+)（请输入 IPv4/IPv6 或 https:// DoH 地址）$'), lambda m: f'DNS 伺服器位址無效：{m.group(1)}（請輸入 IPv4/IPv6 或 https:// DoH 位址）'),
    (re.compile(r'^搜索域格式无效：(.+)$'), lambda m: f'搜尋網域格式無效：{m.group(1)}'),
    (re.compile(r'^分流 DNS 格式错误：(.+)（格式：域名=DNS，如 corp\.local=10\.0\.0\.53）$'), lambda m: f'分流 DNS 格式錯誤：{m.group(1)}（格式：網域=DNS，如 corp.local=10.0.0.53）'),
    (re.compile(r'^分流域名格式无效：(.+)$'), lambda m: f'分流網域格式無效：{m.group(1)}'),
    (re.compile(r'^分流域名 (.+) 未指定有效 DNS 服务器$'), lambda m: f'分流網域 {m.group(1)} 未指定有效 DNS 伺服器'),
    (re.compile(r'^Headscale 配置校验失败：(.+)$'), lambda m: f'Headscale 設定驗證失敗：{m.group(1)}'),
    (re.compile(r'^无效的 IPv4 地址：(.+)$'), lambda m: f'無效的 IPv4 位址：{m.group(1)}'),
    (re.compile(r'^JSON / HuJSON 语法错误：(.+)$'), lambda m: f'JSON / HuJSON 語法錯誤：{m.group(1)}'),
    (re.compile(r'^第 (\d+) 条 ACL 规则必须为对象$'), lambda m: f'第 {m.group(1)} 條 ACL 規則必須為物件'),
    (re.compile(r'^第 (\d+) 条规则 action 仅支持 "accept"$'), lambda m: f'第 {m.group(1)} 條規則 action 僅支援 "accept"'),
    (re.compile(r'^第 (\d+) 条规则缺少有效的 src 数组$'), lambda m: f'第 {m.group(1)} 條規則缺少有效的 src 陣列'),
    (re.compile(r'^第 (\d+) 条规则缺少有效的 dst 数组$'), lambda m: f'第 {m.group(1)} 條規則缺少有效的 dst 陣列'),
    (re.compile(r'^策略校验未通过：(.+)$'), lambda m: f'原則驗證未通過：{m.group(1)}'),
    (re.compile(r'^目标用户 #(\d+) 不存在$'), lambda m: f'目標使用者 #{m.group(1)} 不存在'),
    (re.compile(r'^节点 #(\d+) 不存在$'), lambda m: f'節點 #{m.group(1)} 不存在'),
    (re.compile(r'^无效的 IPv4 地址格式：(.+)$'), lambda m: f'無效的 IPv4 位址格式：{m.group(1)}'),
    (re.compile(r'^该内网 IP \(([^)]+)\) 已被节点「(.+)」占用$'), lambda m: f'該內網 IP ({m.group(1)}) 已被節點「{m.group(2)}」佔用'),
    (re.compile(r'^备份文件不是合法的 JSON 格式：(.+)$'), lambda m: f'備份檔不是合法的 JSON 格式：{m.group(1)}'),
    (re.compile(r'^无效的本机子网网段：(.+)$'), lambda m: f'無效的本機子網路網段：{m.group(1)}'),
    (re.compile(r'^测速完成：直连 \(([^)]+) ms\)$'), lambda m: f'測速完成：直連 ({m.group(1)} ms)'),
    (re.compile(r'^测速完成：中继 (.+) \(([^)]+) ms\)$'), lambda m: f'測速完成：中繼 {m.group(1)} ({m.group(2)} ms)'),
    (re.compile(r'^测速完成：中继 (.+)$'), lambda m: f'測速完成：中繼 {m.group(1)}'),
    (re.compile(r'^节点已重命名为「(.+)」$'), lambda m: f'節點已重新命名為「{m.group(1)}」'),
    (re.compile(r'^节点 #(\d+) 已从组网中移除$'), lambda m: f'節點 #{m.group(1)} 已從組網中移除'),
    (re.compile(r'^标签格式不合法：(.+)（示例：tag:server）$'), lambda m: f'標籤格式不合法：{m.group(1)}（範例：tag:server）'),
    (re.compile(r'^标签格式不合法：(.+)$'), lambda m: f'標籤格式不合法：{m.group(1)}'),
    (re.compile(r'^无效的 CIDR 子网网段：(.+)$'), lambda m: f'無效的 CIDR 子網路網段：{m.group(1)}'),
    (re.compile(r'^预授权密钥 #(\d+) 已废止$'), lambda m: f'預先授權金鑰 #{m.group(1)} 已撤銷'),
    (re.compile(r'^预授权密钥 #(\d+) 已删除$'), lambda m: f'預先授權金鑰 #{m.group(1)} 已刪除'),
    (re.compile(r'^解析记录已保存：(.+) -> (.+)$'), lambda m: f'解析記錄已儲存：{m.group(1)} -> {m.group(2)}'),
    (re.compile(r'^已创建用户「(.+)」$'), lambda m: f'已建立使用者「{m.group(1)}」'),
    (re.compile(r'^用户已重命名为「(.+)」$'), lambda m: f'使用者已重新命名為「{m.group(1)}」'),
    (re.compile(r'^用户「(.+)」下仍有 (\d+) 台设备，请先移除设备后再删除用户$'), lambda m: f'使用者「{m.group(1)}」下仍有 {m.group(2)} 台裝置，請先移除裝置後再刪除使用者'),
    (re.compile(r'^全网测速完成：(\d+) 台直连，(\d+) 台中继$'), lambda m: f'全網測速完成：{m.group(1)} 台直連，{m.group(2)} 台中繼'),
    (re.compile(r'^已将节点迁移至用户「(.+)」$'), lambda m: f'已將節點轉移至使用者「{m.group(1)}」'),
    (re.compile(r'^节点内网 IP 已修改为 (.+)$'), lambda m: f'節點內網 IP 已修改為 {m.group(1)}'),
    (re.compile(r'^节点已批准接入至用户「(.+)」$'), lambda m: f'節點已核准加入至使用者「{m.group(1)}」'),
    (re.compile(r'^已成功恢复：(.+)$'), lambda m: '已成功還原：' + '、'.join(_ZHTW_RESTORE_PARTS.get(p, p) for p in m.group(1).split('、'))),
    (re.compile(r'^本机节点 \((.+)\) 已成功接入组网并设为永不过期$'), lambda m: f'本機節點 ({m.group(1)}) 已成功加入組網並設為永不過期'),
    (re.compile(r'^未知的操作类型：(.+)$'), lambda m: f'未知的操作類型：{m.group(1)}'),
    (re.compile(r'^Headscale 执行失败：(.+)$'), lambda m: f'Headscale 執行失敗：{m.group(1)}'),
    (re.compile(r'^操作失败：(.+)$'), lambda m: f'操作失敗：{m.group(1)}'),
]

_JA_EXACT_MESSAGES = {
    '请输入解析域名': 'ドメイン名を入力してください',
    '短主机名仅允许字母、数字、连字符或下划线': '短縮ホスト名には英数字、ハイフン、アンダースコアのみ使用できます',
    '请输入指向的 IP 地址': '宛先の IP アドレスを入力してください',
    '请指定要删除的域名': '削除するドメイン名を指定してください',
    'Headscale 配置文件格式不支持在线修改': 'Headscale 設定ファイル形式はオンライン編集に対応していません',
    '开启“覆盖本地 DNS”时，需至少填写一个全局 DNS 服务器（如 223.5.5.5）': '「ローカル DNS を上書き」を有効にする場合、グローバル DNS サーバーを少なくとも1つ指定してください（例: 1.1.1.1）',
    '无效的 Headscale 配置结构': 'Headscale 設定構造が無効です',
    '服务端地址格式无效（示例：https://hs.example.com）': 'サーバー URL の形式が無効です（例: https://hs.example.com）',
    '区域代码仅允许字母、数字、连字符或下划线（如 local）': 'リージョンコードには英数字、ハイフン、アンダースコアのみ使用できます（例: local）',
    '区域名称过长（最多 64 个字符）': 'リージョン名が長すぎます（最大 64 文字）',
    'DERP 公网 IPv4 必须为 IPv4 地址': 'DERP パブリック IPv4 は有効な IPv4 アドレスである必要があります',
    'STUN 端口必须在 1-65535 之间': 'STUN ポートは 1-65535 の範囲で指定してください',
    'ACL 策略内容不能为空': 'ACL ポリシーの内容を空にすることはできません',
    'ACL 策略文件过大': 'ACL ポリシーファイルが大きすぎます',
    'ACL 策略根节点必须为 JSON 对象 ({...})': 'ACL ポリシーのルートは JSON オブジェクト ({...}) である必要があります',
    'acls 字段必须为数组 ([...])': 'acls フィールドは配列 ([...]) である必要があります',
    '请输入节点注册链接、Auth ID 或 NodeKey': 'ノード登録 URL、Auth ID、または NodeKey を入力してください',
    '节点密钥格式无效': 'ノードキーの形式が無効です',
    '无法识别的注册标识，请粘贴注册链接、Auth ID 或 nodekey/mkey': '登録トークンを識別できません。登録 URL、Auth ID、または nodekey/mkey を貼り付けてください',
    '未找到 Headscale 数据库文件': 'Headscale データベースファイルが見つかりません',
    '请输入有效的 IPv4 地址': '有効な IPv4 アドレスを入力してください',
    '节点内网 IP 必须位于 Tailscale 内网网段 (100.64.0.0/10) 或私有网段内': 'ノード IP は Tailscale CGNAT 帯域 (100.64.0.0/10) またはプライベート IPv4 帯域内である必要があります',
    '请提供备份 JSON 内容': 'バックアップ JSON の内容を入力してください',
    '备份数据格式无效': 'バックアップデータの形式が無効です',
    '备份数据根节点必须为 JSON 对象': 'バックアップデータのルートは JSON オブジェクトである必要があります',
    '未选择要恢复的配置项，或备份文件中不包含有效配置数据': '復元する項目が選択されていないか、バックアップに有効な設定データが含まれていません',
    '请求参数格式错误': 'リクエストパラメーターの形式が不正です',
    '缺少操作类型 (action)': '操作タイプ (action) が不足しています',
    '已刷新组网状态': 'メッシュ状態を更新しました',
    '未找到可用于测速的内网 IP': 'Ping に使用できる Tailnet IP が見つかりません',
    '测速完成：直连': 'Ping 完了：直接接続',
    '当前节点为本机': '現在のノードはローカルノードです',
    '未收到探测响应，节点可能离线或被防火墙拦截': '応答がありませんでした。ノードがオフラインかファイアウォールでブロックされている可能性があります',
    '节点名称仅允许字母、数字、点、下划线或连字符，且以字母或数字开头（1-62 位）': 'ノード名は英数字で始まり、英数字・ドット・アンダースコア・ハイフンのみ使用できます（1-62 文字）',
    '已将该节点设为密钥永不过期': 'このノードのキー有効期限を無期限に設定しました',
    '节点会话已设为过期，客户端需重新认证': 'ノードのセッションを期限切れにしました。クライアントで再認証が必要です',
    '安全保护：不能直接移除当前控制面所在的本机节点': '安全保護：現在のコントロールプレーンがあるローカルノードは直接削除できません',
    '请至少提供一个有效标签（如 tag:server）': '有効なタグを少なくとも1つ指定してください（例: tag:server）',
    '节点标签已更新': 'ノードタグを更新しました',
    '节点子网路由审批已更新': 'ノードのサブネットルート承認を更新しました',
    '不支持的有效期选项，请选择 1h、24h、7d、30d、90d 或 365d': '未対応の有効期限オプションです。1h、24h、7d、30d、90d、または 365d を選択してください',
    '密钥已生成，请复制保存': '事前認証キーを作成しました。コピーして保存してください',
    '解析记录已删除': 'DNS レコードを削除しました',
    '未找到 Headscale 配置文件': 'Headscale 設定ファイルが見つかりません',
    'DNS 配置已生效': 'DNS 設定を適用しました',
    '策略语法校验通过': 'ポリシーの構文検証に合格しました',
    '访问控制策略已保存并生效': 'ACL ポリシーを保存して適用しました',
    '用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）': 'ユーザー名は英字で始まり、英数字・ドット・アンダースコア・ハイフンのみ使用できます（1-62 文字）',
    '备注名称过长（最多 64 个字符）': '表示名が長すぎます（最大 64 文字）',
    '邮箱格式无效': 'メールアドレスの形式が無効です',
    '新用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）': '新しいユーザー名は英字で始まり、英数字・ドット・アンダースコア・ハイフンのみ使用できます（1-62 文字）',
    '用户已删除': 'ユーザーを削除しました',
    '网络诊断已完成': 'ネットワーク診断が完了しました',
    '请选择有效的所属用户': '有効な所有ユーザーを選択してください',
    '已生成最新配置快照': '最新の設定スナップショットを生成しました',
    '本机与中继配置已保存并生效': 'ローカルおよびリレー設定を保存して適用しました',
    '已开启本机作为出口节点并自动批准路由': 'ローカル出口ノードを有効化しルートを承認しました',
    '已关闭本机出口节点功能': 'ローカル出口ノードを無効化しました',
    '本机 Tailscale 客户端已安装并启动服务': 'ローカル Tailscale クライアントをインストールして起動しました',
    '未检测到服务端地址 (server_url)': 'サーバー URL (server_url) が検出されませんでした',
    '自动签发本机接入密钥失败': 'ローカルノード用の事前認証キーの自動発行に失敗しました',
    '无法读取组网状态，请检查 Headscale、Tailscale 和采集服务。': 'メッシュ状態を読み取れません。Headscale、Tailscale、およびコレクターサービスを確認してください。',
    '未授权的本地控制请求': '未承認のローカル制御リクエストです',
    '未知路径': '不明なパスです',
    '请求体大小异常': 'リクエストボディのサイズが不正です',
    '命令执行失败': 'コマンドの実行に失敗しました',
    '配置校验未通过': '設定の検証に失敗しました',
    'ACL 策略校验未通过': 'ACL ポリシーの検証に失敗しました',
    '校验未通过': '検証に失敗しました',
}

_JA_FIELD_NAMES = {
    '节点 ID': 'ノード ID',
    '用户 ID': 'ユーザー ID',
    '目标用户 ID': '移行先ユーザー ID',
    '密钥 ID': 'キー ID',
}

_JA_RESTORE_PARTS = {
    'DNS 配置与解析记录': 'DNS 設定とカスタムレコード',
    '中继配置': 'DERP リレー設定',
    '访问控制策略': 'ACL ポリシー',
}

_JA_PATTERN_RULES = [
    (re.compile(r'^域名格式无效：(.+)（示例：nas\.nodes\.internal 或 git\.lan）$'), lambda m: f'ドメイン形式が無効です：{m.group(1)}（例: nas.nodes.internal または git.lan）'),
    (re.compile(r'^无效的 IPv4/IPv6 地址：(.+)$'), lambda m: f'無効な IPv4/IPv6 アドレスです：{m.group(1)}'),
    (re.compile(r'^(.+) 参数无效$'), lambda m: f'{_JA_FIELD_NAMES.get(m.group(1), m.group(1))} が無効です'),
    (re.compile(r'^(.+) 必须为正整数$'), lambda m: f'{_JA_FIELD_NAMES.get(m.group(1), m.group(1))} は正の整数である必要があります'),
    (re.compile(r'^未找到域名记录：(.+)$'), lambda m: f'DNS レコードが見つかりません：{m.group(1)}'),
    (re.compile(r'^无效的 DoH 地址：(.+)$'), lambda m: f'無効な DoH URL です：{m.group(1)}'),
    (re.compile(r'^DNS 服务器地址无效：(.+)（请输入 IPv4/IPv6 或 https:// DoH 地址）$'), lambda m: f'DNS サーバーアドレスが無効です：{m.group(1)}（IPv4/IPv6 または https:// DoH URL を入力してください）'),
    (re.compile(r'^搜索域格式无效：(.+)$'), lambda m: f'検索ドメインの形式が無効です：{m.group(1)}'),
    (re.compile(r'^分流 DNS 格式错误：(.+)（格式：域名=DNS，如 corp\.local=10\.0\.0\.53）$'), lambda m: f'スプリット DNS の形式が無効です：{m.group(1)}（形式：ドメイン=DNS、例: corp.local=10.0.0.53）'),
    (re.compile(r'^分流域名格式无效：(.+)$'), lambda m: f'スプリットドメインの形式が無効です：{m.group(1)}'),
    (re.compile(r'^分流域名 (.+) 未指定有效 DNS 服务器$'), lambda m: f'スプリットドメイン {m.group(1)} に有効な DNS サーバーが指定されていません'),
    (re.compile(r'^Headscale 配置校验失败：(.+)$'), lambda m: f'Headscale 設定の検証に失敗しました：{m.group(1)}'),
    (re.compile(r'^无效的 IPv4 地址：(.+)$'), lambda m: f'無効な IPv4 アドレスです：{m.group(1)}'),
    (re.compile(r'^JSON / HuJSON 语法错误：(.+)$'), lambda m: f'JSON / HuJSON 構文エラー：{m.group(1)}'),
    (re.compile(r'^第 (\d+) 条 ACL 规则必须为对象$'), lambda m: f'ACL ルール #{m.group(1)} はオブジェクトである必要があります'),
    (re.compile(r'^第 (\d+) 条规则 action 仅支持 "accept"$'), lambda m: f'ACL ルール #{m.group(1)} の action は "accept" のみ対応しています'),
    (re.compile(r'^第 (\d+) 条规则缺少有效的 src 数组$'), lambda m: f'ACL ルール #{m.group(1)} に有効な "src" 配列がありません'),
    (re.compile(r'^第 (\d+) 条规则缺少有效的 dst 数组$'), lambda m: f'ACL ルール #{m.group(1)} に有効な "dst" 配列がありません'),
    (re.compile(r'^策略校验未通过：(.+)$'), lambda m: f'ポリシーの検証に失敗しました：{m.group(1)}'),
    (re.compile(r'^目标用户 #(\d+) 不存在$'), lambda m: f'対象ユーザー #{m.group(1)} が存在しません'),
    (re.compile(r'^节点 #(\d+) 不存在$'), lambda m: f'ノード #{m.group(1)} が存在しません'),
    (re.compile(r'^无效的 IPv4 地址格式：(.+)$'), lambda m: f'IPv4 アドレスの形式が無効です：{m.group(1)}'),
    (re.compile(r'^该内网 IP \(([^)]+)\) 已被节点「(.+)」占用$'), lambda m: f'IP アドレス ({m.group(1)}) は既にノード「{m.group(2)}」で使用されています'),
    (re.compile(r'^备份文件不是合法的 JSON 格式：(.+)$'), lambda m: f'バックアップファイルが有効な JSON ではありません：{m.group(1)}'),
    (re.compile(r'^无效的本机子网网段：(.+)$'), lambda m: f'ローカルサブネット CIDR が無効です：{m.group(1)}'),
    (re.compile(r'^测速完成：直连 \(([^)]+) ms\)$'), lambda m: f'Ping 完了：直接接続 ({m.group(1)} ms)'),
    (re.compile(r'^测速完成：中继 (.+) \(([^)]+) ms\)$'), lambda m: f'Ping 完了：リレー {m.group(1)} ({m.group(2)} ms)'),
    (re.compile(r'^测速完成：中继 (.+)$'), lambda m: f'Ping 完了：リレー {m.group(1)}'),
    (re.compile(r'^节点已重命名为「(.+)」$'), lambda m: f'ノード名を「{m.group(1)}」に変更しました'),
    (re.compile(r'^节点 #(\d+) 已从组网中移除$'), lambda m: f'ノード #{m.group(1)} を Tailnet から削除しました'),
    (re.compile(r'^标签格式不合法：(.+)（示例：tag:server）$'), lambda m: f'タグの形式が無効です：{m.group(1)}（例: tag:server）'),
    (re.compile(r'^标签格式不合法：(.+)$'), lambda m: f'タグの形式が無効です：{m.group(1)}'),
    (re.compile(r'^无效的 CIDR 子网网段：(.+)$'), lambda m: f'CIDR サブネットが無効です：{m.group(1)}'),
    (re.compile(r'^预授权密钥 #(\d+) 已废止$'), lambda m: f'事前認証キー #{m.group(1)} を失効させました'),
    (re.compile(r'^预授权密钥 #(\d+) 已删除$'), lambda m: f'事前認証キー #{m.group(1)} を削除しました'),
    (re.compile(r'^解析记录已保存：(.+) -> (.+)$'), lambda m: f'DNS レコードを保存しました：{m.group(1)} -> {m.group(2)}'),
    (re.compile(r'^已创建用户「(.+)」$'), lambda m: f'ユーザー「{m.group(1)}」を作成しました'),
    (re.compile(r'^用户已重命名为「(.+)」$'), lambda m: f'ユーザー名を「{m.group(1)}」に変更しました'),
    (re.compile(r'^用户「(.+)」下仍有 (\d+) 台设备，请先移除设备后再删除用户$'), lambda m: f'ユーザー「{m.group(1)}」にはまだ {m.group(2)} 台のデバイスが所属しているため、先にデバイスを削除または移行してください'),
    (re.compile(r'^全网测速完成：(\d+) 台直连，(\d+) 台中继$'), lambda m: f'一括 Ping 完了：{m.group(1)} 台 直接接続、{m.group(2)} 台 リレー'),
    (re.compile(r'^已将节点迁移至用户「(.+)」$'), lambda m: f'ノードをユーザー「{m.group(1)}」へ移行しました'),
    (re.compile(r'^节点内网 IP 已修改为 (.+)$'), lambda m: f'ノードの Tailnet IP を {m.group(1)} に変更しました'),
    (re.compile(r'^节点已批准接入至用户「(.+)」$'), lambda m: f'ノードを承認しユーザー「{m.group(1)}」へ割り当てました'),
    (re.compile(r'^已成功恢复：(.+)$'), lambda m: '復元しました：' + '、'.join(_JA_RESTORE_PARTS.get(p, p) for p in m.group(1).split('、'))),
    (re.compile(r'^本机节点 \((.+)\) 已成功接入组网并设为永不过期$'), lambda m: f'ローカルノード ({m.group(1)}) を Tailnet に接続し無期限に設定しました'),
    (re.compile(r'^未知的操作类型：(.+)$'), lambda m: f'不明な操作タイプです：{m.group(1)}'),
    (re.compile(r'^Headscale 执行失败：(.+)$'), lambda m: f'Headscale コマンドの実行に失敗しました：{m.group(1)}'),
    (re.compile(r'^操作失败：(.+)$'), lambda m: f'操作に失敗しました：{m.group(1)}'),
]

_ID_EXACT_MESSAGES = {
    '请输入解析域名': 'Silakan masukkan nama domain',
    '短主机名仅允许字母、数字、连字符或下划线': 'Nama host pendek hanya boleh berisi huruf, angka, tanda hubung, atau garis bawah',
    '请输入指向的 IP 地址': 'Silakan masukkan alamat IP tujuan',
    '请指定要删除的域名': 'Silakan tentukan domain yang ingin dihapus',
    'Headscale 配置文件格式不支持在线修改': 'Format konfigurasi Headscale tidak mendukung pengeditan online',
    '开启“覆盖本地 DNS”时，需至少填写一个全局 DNS 服务器（如 223.5.5.5）': 'Minimal satu server DNS global (mis. 1.1.1.1) diperlukan saat "Timpa DNS Lokal" diaktifkan',
    '无效的 Headscale 配置结构': 'Struktur konfigurasi Headscale tidak valid',
    '服务端地址格式无效（示例：https://hs.example.com）': 'Format URL server tidak valid (mis. https://hs.example.com)',
    '区域代码仅允许字母、数字、连字符或下划线（如 local）': 'Kode wilayah hanya boleh berisi huruf, angka, tanda hubung, atau garis bawah (mis. local)',
    '区域名称过长（最多 64 个字符）': 'Nama wilayah terlalu panjang (maks. 64 karakter)',
    'DERP 公网 IPv4 必须为 IPv4 地址': 'IPv4 publik DERP harus berupa alamat IPv4 yang valid',
    'STUN 端口必须在 1-65535 之间': 'Port STUN harus berada di antara 1 dan 65535',
    'ACL 策略内容不能为空': 'Kebijakan ACL tidak boleh kosong',
    'ACL 策略文件过大': 'File kebijakan ACL terlalu besar',
    'ACL 策略根节点必须为 JSON 对象 ({...})': 'Root kebijakan ACL harus berupa objek JSON ({...})',
    'acls 字段必须为数组 ([...])': 'Field "acls" harus berupa array ([...])',
    '请输入节点注册链接、Auth ID 或 NodeKey': 'Silakan tempel URL pendaftaran, Auth ID, atau NodeKey',
    '节点密钥格式无效': 'Format kunci node tidak valid',
    '无法识别的注册标识，请粘贴注册链接、Auth ID 或 nodekey/mkey': 'Token pendaftaran tidak dikenali. Harap tempel URL pendaftaran, Auth ID, atau nodekey/mkey',
    '未找到 Headscale 数据库文件': 'File database Headscale tidak ditemukan',
    '请输入有效的 IPv4 地址': 'Silakan masukkan alamat IPv4 yang valid',
    '节点内网 IP 必须位于 Tailscale 内网网段 (100.64.0.0/10) 或私有网段内': 'IP node harus berada dalam rentang CGNAT Tailscale (100.64.0.0/10) atau rentang IPv4 privat',
    '请提供备份 JSON 内容': 'Harap berikan konten JSON cadangan',
    '备份数据格式无效': 'Format data cadangan tidak valid',
    '备份数据根节点必须为 JSON 对象': 'Root data cadangan harus berupa objek JSON',
    '未选择要恢复的配置项，或备份文件中不包含有效配置数据': 'Tidak ada item pemulihan yang dipilih, atau cadangan tidak berisi data konfigurasi yang valid',
    '请求参数格式错误': 'Parameter permintaan tidak valid',
    '缺少操作类型 (action)': 'Parameter aksi (action) tidak ditemukan',
    '已刷新组网状态': 'Status mesh disegarkan',
    '未找到可用于测速的内网 IP': 'Tidak ada IP tailnet yang tersedia untuk ping',
    '测速完成：直连': 'Ping selesai: Langsung',
    '当前节点为本机': 'Ini adalah node lokal',
    '未收到探测响应，节点可能离线或被防火墙拦截': 'Tidak ada respons ping yang diterima; node mungkin offline atau diblokir firewall',
    '节点名称仅允许字母、数字、点、下划线或连字符，且以字母或数字开头（1-62 位）': 'Nama node harus diawali huruf atau angka dan hanya boleh berisi huruf, angka, titik, garis bawah, atau tanda hubung (1-62 karakter)',
    '已将该节点设为密钥永不过期': 'Masa berlaku kunci node dinonaktifkan (tidak pernah kedaluwarsa)',
    '节点会话已设为过期，客户端需重新认证': 'Sesi node diakhiri; klien harus melakukan autentikasi ulang',
    '安全保护：不能直接移除当前控制面所在的本机节点': 'Perlindungan keamanan: tidak dapat menghapus node control-plane lokal secara langsung',
    '请至少提供一个有效标签（如 tag:server）': 'Harap berikan minimal satu tag yang valid (mis. tag:server)',
    '节点标签已更新': 'Tag node diperbarui',
    '节点子网路由审批已更新': 'Persetujuan rute node diperbarui',
    '不支持的有效期选项，请选择 1h、24h、7d、30d、90d 或 365d': 'Opsi masa berlaku tidak didukung; pilih 1h, 24h, 7d, 30d, 90d, atau 365d',
    '密钥已生成，请复制保存': 'Kunci pra-auth dibuat; silakan salin dan simpan',
    '解析记录已删除': 'Catatan DNS dihapus',
    '未找到 Headscale 配置文件': 'File konfigurasi Headscale tidak ditemukan',
    'DNS 配置已生效': 'Pengaturan DNS diterapkan',
    '策略语法校验通过': 'Pemeriksaan sintaks kebijakan lolos',
    '访问控制策略已保存并生效': 'Kebijakan ACL disimpan dan diterapkan',
    '用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）': 'Nama pengguna harus diawali huruf dan hanya boleh berisi huruf, angka, titik, garis bawah, atau tanda hubung (1-62 karakter)',
    '备注名称过长（最多 64 个字符）': 'Nama tampilan terlalu panjang (maks. 64 karakter)',
    '邮箱格式无效': 'Alamat email tidak valid',
    '新用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）': 'Nama pengguna baru harus diawali huruf dan hanya boleh berisi huruf, angka, titik, garis bawah, atau tanda hubung (1-62 karakter)',
    '用户已删除': 'Pengguna dihapus',
    '网络诊断已完成': 'Diagnostik jaringan selesai',
    '请选择有效的所属用户': 'Silakan pilih pengguna yang valid',
    '已生成最新配置快照': 'Snapshot konfigurasi terbaru dibuat',
    '本机与中继配置已保存并生效': 'Konfigurasi lokal & relay disimpan dan diterapkan',
    '已开启本机作为出口节点并自动批准路由': 'Exit node lokal diaktifkan dan rute disetujui',
    '已关闭本机出口节点功能': 'Exit node lokal dinonaktifkan',
    '本机 Tailscale 客户端已安装并启动服务': 'Klien Tailscale lokal terpasang dan layanan dijalankan',
    '未检测到服务端地址 (server_url)': 'URL server (server_url) tidak terdeteksi',
    '自动签发本机接入密钥失败': 'Gagal menerbitkan kunci pra-auth untuk node lokal',
    '无法读取组网状态，请检查 Headscale、Tailscale 和采集服务。': 'Tidak dapat membaca status mesh. Harap periksa Headscale, Tailscale, dan layanan kolektor.',
    '未授权的本地控制请求': 'Permintaan kontrol lokal tidak sah',
    '未知路径': 'Jalur tidak dikenal',
    '请求体大小异常': 'Ukuran body permintaan tidak valid',
    '命令执行失败': 'Eksekusi perintah gagal',
    '配置校验未通过': 'Validasi konfigurasi gagal',
    'ACL 策略校验未通过': 'Pemeriksaan kebijakan ACL gagal',
    '校验未通过': 'Validasi gagal',
}

_ID_FIELD_NAMES = {
    '节点 ID': 'ID Node',
    '用户 ID': 'ID Pengguna',
    '目标用户 ID': 'ID Pengguna Target',
    '密钥 ID': 'ID Kunci',
}

_ID_RESTORE_PARTS = {
    'DNS 配置与解析记录': 'pengaturan & catatan DNS',
    '中继配置': 'konfigurasi relay DERP',
    '访问控制策略': 'kebijakan ACL',
}

_ID_PATTERN_RULES = [
    (re.compile(r'^域名格式无效：(.+)（示例：nas\.nodes\.internal 或 git\.lan）$'), lambda m: f'Format domain tidak valid: {m.group(1)} (mis. nas.nodes.internal atau git.lan)'),
    (re.compile(r'^无效的 IPv4/IPv6 地址：(.+)$'), lambda m: f'Alamat IPv4/IPv6 tidak valid: {m.group(1)}'),
    (re.compile(r'^(.+) 参数无效$'), lambda m: f'{_ID_FIELD_NAMES.get(m.group(1), m.group(1))} tidak valid'),
    (re.compile(r'^(.+) 必须为正整数$'), lambda m: f'{_ID_FIELD_NAMES.get(m.group(1), m.group(1))} harus berupa bilangan bulat positif'),
    (re.compile(r'^未找到域名记录：(.+)$'), lambda m: f'Catatan DNS tidak ditemukan: {m.group(1)}'),
    (re.compile(r'^无效的 DoH 地址：(.+)$'), lambda m: f'URL DoH tidak valid: {m.group(1)}'),
    (re.compile(r'^DNS 服务器地址无效：(.+)（请输入 IPv4/IPv6 或 https:// DoH 地址）$'), lambda m: f'Server DNS tidak valid: {m.group(1)} (masukkan IPv4/IPv6 atau URL https:// DoH)'),
    (re.compile(r'^搜索域格式无效：(.+)$'), lambda m: f'Domain pencarian tidak valid: {m.group(1)}'),
    (re.compile(r'^分流 DNS 格式错误：(.+)（格式：域名=DNS，如 corp\.local=10\.0\.0\.53）$'), lambda m: f'Format Split DNS tidak valid: {m.group(1)} (gunakan domain=DNS, mis. corp.local=10.0.0.53)'),
    (re.compile(r'^分流域名格式无效：(.+)$'), lambda m: f'Domain split tidak valid: {m.group(1)}'),
    (re.compile(r'^分流域名 (.+) 未指定有效 DNS 服务器$'), lambda m: f'Tidak ada server DNS valid yang ditentukan untuk domain split {m.group(1)}'),
    (re.compile(r'^Headscale 配置校验失败：(.+)$'), lambda m: f'Pemeriksaan konfigurasi Headscale gagal: {m.group(1)}'),
    (re.compile(r'^无效的 IPv4 地址：(.+)$'), lambda m: f'Alamat IPv4 tidak valid: {m.group(1)}'),
    (re.compile(r'^JSON / HuJSON 语法错误：(.+)$'), lambda m: f'Kesalahan sintaks JSON / HuJSON: {m.group(1)}'),
    (re.compile(r'^第 (\d+) 条 ACL 规则必须为对象$'), lambda m: f'Aturan ACL #{m.group(1)} harus berupa objek'),
    (re.compile(r'^第 (\d+) 条规则 action 仅支持 "accept"$'), lambda m: f'Aksi aturan ACL #{m.group(1)} hanya mendukung "accept"'),
    (re.compile(r'^第 (\d+) 条规则缺少有效的 src 数组$'), lambda m: f'Aturan ACL #{m.group(1)} tidak memiliki array "src" yang valid'),
    (re.compile(r'^第 (\d+) 条规则缺少有效的 dst 数组$'), lambda m: f'Aturan ACL #{m.group(1)} tidak memiliki array "dst" yang valid'),
    (re.compile(r'^策略校验未通过：(.+)$'), lambda m: f'Validasi kebijakan gagal: {m.group(1)}'),
    (re.compile(r'^目标用户 #(\d+) 不存在$'), lambda m: f'Pengguna target #{m.group(1)} tidak ada'),
    (re.compile(r'^节点 #(\d+) 不存在$'), lambda m: f'Node #{m.group(1)} tidak ada'),
    (re.compile(r'^无效的 IPv4 地址格式：(.+)$'), lambda m: f'Format alamat IPv4 tidak valid: {m.group(1)}'),
    (re.compile(r'^该内网 IP \(([^)]+)\) 已被节点「(.+)」占用$'), lambda m: f'Alamat IP ({m.group(1)}) sudah digunakan oleh node "{m.group(2)}"'),
    (re.compile(r'^备份文件不是合法的 JSON 格式：(.+)$'), lambda m: f'File cadangan bukan JSON yang valid: {m.group(1)}'),
    (re.compile(r'^无效的本机子网网段：(.+)$'), lambda m: f'CIDR subnet lokal tidak valid: {m.group(1)}'),
    (re.compile(r'^测速完成：直连 \(([^)]+) ms\)$'), lambda m: f'Ping selesai: Langsung ({m.group(1)} ms)'),
    (re.compile(r'^测速完成：中继 (.+) \(([^)]+) ms\)$'), lambda m: f'Ping selesai: Relay {m.group(1)} ({m.group(2)} ms)'),
    (re.compile(r'^测速完成：中继 (.+)$'), lambda m: f'Ping selesai: Relay {m.group(1)}'),
    (re.compile(r'^节点已重命名为「(.+)」$'), lambda m: f'Nama node diubah menjadi "{m.group(1)}"'),
    (re.compile(r'^节点 #(\d+) 已从组网中移除$'), lambda m: f'Node #{m.group(1)} dihapus dari tailnet'),
    (re.compile(r'^标签格式不合法：(.+)（示例：tag:server）$'), lambda m: f'Format tag tidak valid: {m.group(1)} (mis. tag:server)'),
    (re.compile(r'^标签格式不合法：(.+)$'), lambda m: f'Format tag tidak valid: {m.group(1)}'),
    (re.compile(r'^无效的 CIDR 子网网段：(.+)$'), lambda m: f'Subnet CIDR tidak valid: {m.group(1)}'),
    (re.compile(r'^预授权密钥 #(\d+) 已废止$'), lambda m: f'Kunci pra-auth #{m.group(1)} dicabut'),
    (re.compile(r'^预授权密钥 #(\d+) 已删除$'), lambda m: f'Kunci pra-auth #{m.group(1)} dihapus'),
    (re.compile(r'^解析记录已保存：(.+) -> (.+)$'), lambda m: f'Catatan DNS disimpan: {m.group(1)} -> {m.group(2)}'),
    (re.compile(r'^已创建用户「(.+)」$'), lambda m: f'Pengguna "{m.group(1)}" dibuat'),
    (re.compile(r'^用户已重命名为「(.+)」$'), lambda m: f'Nama pengguna diubah menjadi "{m.group(1)}"'),
    (re.compile(r'^用户「(.+)」下仍有 (\d+) 台设备，请先移除设备后再删除用户$'), lambda m: f'Pengguna "{m.group(1)}" masih memiliki {m.group(2)} perangkat; hapus atau pindahkan terlebih dahulu'),
    (re.compile(r'^全网测速完成：(\d+) 台直连，(\d+) 台中继$'), lambda m: f'Ping mesh selesai: {m.group(1)} langsung, {m.group(2)} via relay'),
    (re.compile(r'^已将节点迁移至用户「(.+)」$'), lambda m: f'Node dipindahkan ke pengguna "{m.group(1)}"'),
    (re.compile(r'^节点内网 IP 已修改为 (.+)$'), lambda m: f'IP tailnet node diperbarui menjadi {m.group(1)}'),
    (re.compile(r'^节点已批准接入至用户「(.+)」$'), lambda m: f'Node disetujui dan ditetapkan ke pengguna "{m.group(1)}"'),
    (re.compile(r'^已成功恢复：(.+)$'), lambda m: 'Berhasil memulihkan: ' + ', '.join(_ID_RESTORE_PARTS.get(p, p) for p in m.group(1).split('、'))),
    (re.compile(r'^本机节点 \((.+)\) 已成功接入组网并设为永不过期$'), lambda m: f'Node lokal ({m.group(1)}) terhubung dengan masa berlaku kunci dinonaktifkan'),
    (re.compile(r'^未知的操作类型：(.+)$'), lambda m: f'Tindakan tidak dikenal: {m.group(1)}'),
    (re.compile(r'^Headscale 执行失败：(.+)$'), lambda m: f'Perintah Headscale gagal: {m.group(1)}'),
    (re.compile(r'^操作失败：(.+)$'), lambda m: f'Tindakan gagal: {m.group(1)}'),
]


_LANG_CATALOGS = {
    'zh-TW': (_ZHTW_EXACT_MESSAGES, _ZHTW_PATTERN_RULES),
    'en': (_EN_EXACT_MESSAGES, _EN_PATTERN_RULES),
    'ja': (_JA_EXACT_MESSAGES, _JA_PATTERN_RULES),
    'id': (_ID_EXACT_MESSAGES, _ID_PATTERN_RULES),
}


def normalize_lang(lang):
    raw = str(lang or '').strip().lower().replace('_', '-')
    if not raw:
        return 'zh'
    if (
        raw in ('zh-tw', 'zh-hk', 'zh-mo', 'zh-hant')
        or raw.startswith(('zh-tw-', 'zh-hk-', 'zh-mo-', 'zh-hant-'))
    ):
        return 'zh-TW'
    if raw == 'zh' or raw.startswith('zh-'):
        return 'zh'
    if raw == 'ja' or raw.startswith('ja-'):
        return 'ja'
    if raw in ('id', 'in') or raw.startswith(('id-', 'in-')):
        return 'id'
    return 'en'


def localize_message(text, lang='zh'):
    norm = normalize_lang(lang)
    if norm == 'zh' or not isinstance(text, str) or not text:
        return text
    catalog = _LANG_CATALOGS.get(norm)
    if not catalog:
        return text
    exact_map, pattern_rules = catalog
    if text in exact_map:
        return exact_map[text]
    for pattern, repl in pattern_rules:
        m = pattern.match(text)
        if m:
            return repl(m)
    return text


def execute_action(payload):
    lang = normalize_lang(payload.get('lang')) if isinstance(payload, dict) else 'zh'
    try:
        result = _execute_action_core(payload)
    except ValueError as exc:
        raise ValueError(localize_message(str(exc), lang)) from exc
    if isinstance(result, dict) and isinstance(result.get('message'), str):
        result['message'] = localize_message(result['message'], lang)
    return result


def _execute_action_core(payload):
    if not isinstance(payload, dict):
        raise ValueError('请求参数格式错误')
    action = str(payload.get('action') or '').strip()
    if not action:
        raise ValueError('缺少操作类型 (action)')

    with ACTION_LOCK:
        if action == 'refresh':
            snapshot = collect()
            write_snapshot(snapshot)
            return {'ok': True, 'message': '已刷新组网状态', 'snapshot': snapshot}

        if action == 'ping':
            node_id = payload.get('node_id')
            target_ip = str(payload.get('ip') or '').strip()
            nodes = headscale_cli('nodes', 'list', timeout=4) or []
            target_node = None
            if node_id is not None:
                nid = _parse_positive_int(node_id, '节点 ID')
                for n in nodes:
                    if n.get('id') == nid:
                        target_node = n
                        break
            if target_node and not target_ip:
                target_ip = preferred_ip(target_node.get('ip_addresses') or []) or ''
            valid_ip = preferred_ip([target_ip]) if target_ip else None
            if not valid_ip:
                raise ValueError('未找到可用于测速的内网 IP')
            probe_res = probe(valid_ip)
            snapshot = collect()
            write_snapshot(snapshot)
            conn = probe_res.get('connection')
            lat = probe_res.get('latency_ms')
            if conn == 'direct':
                msg = f'测速完成：直连 ({lat} ms)' if lat is not None else '测速完成：直连'
            elif conn in ('relay', 'peer-relay'):
                relay_code = probe_res.get('relay') or 'DERP'
                msg = f'测速完成：中继 {relay_code} ({lat} ms)' if lat is not None else f'测速完成：中继 {relay_code}'
            elif conn == 'self':
                msg = '当前节点为本机'
            else:
                msg = '未收到探测响应，节点可能离线或被防火墙拦截'
            return {'ok': True, 'message': msg, 'probe': probe_res, 'snapshot': snapshot}

        if action == 'rename_node':
            nid = _parse_positive_int(payload.get('node_id'), '节点 ID')
            new_name = str(payload.get('name') or '').strip()
            if not NODE_NAME_RE.match(new_name):
                raise ValueError('节点名称仅允许字母、数字、点、下划线或连字符，且以字母或数字开头（1-62 位）')
            headscale_cli('nodes', 'rename', new_name, '-i', str(nid), '--force', timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {'ok': True, 'message': f'节点已重命名为「{new_name}」', 'snapshot': snapshot}

        if action == 'expire_node':
            nid = _parse_positive_int(payload.get('node_id'), '节点 ID')
            disable = bool(payload.get('disable', False))
            if disable:
                headscale_cli('nodes', 'expire', '-i', str(nid), '--disable', '--force', timeout=6)
                msg = '已将该节点设为密钥永不过期'
            else:
                headscale_cli('nodes', 'expire', '-i', str(nid), '--force', timeout=6)
                msg = '节点会话已设为过期，客户端需重新认证'
            snapshot = collect()
            write_snapshot(snapshot)
            return {'ok': True, 'message': msg, 'snapshot': snapshot}

        if action == 'delete_node':
            nid = _parse_positive_int(payload.get('node_id'), '节点 ID')
            current = collect()
            for row in current.get('nodes') or []:
                if row.get('id') == nid and row.get('is_observer'):
                    raise ValueError('安全保护：不能直接移除当前控制面所在的本机节点')
            headscale_cli('nodes', 'delete', '-i', str(nid), '--force', timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {'ok': True, 'message': f'节点 #{nid} 已从组网中移除', 'snapshot': snapshot}

        if action == 'set_tags':
            nid = _parse_positive_int(payload.get('node_id'), '节点 ID')
            raw_tags = payload.get('tags') or []
            if isinstance(raw_tags, str):
                raw_tags = [t.strip() for t in raw_tags.split(',') if t.strip()]
            cleaned = []
            for t in raw_tags:
                tag_str = str(t).strip()
                if not tag_str:
                    continue
                if not tag_str.startswith('tag:'):
                    tag_str = 'tag:' + tag_str
                if not TAG_RE.match(tag_str):
                    raise ValueError(f'标签格式不合法：{tag_str}（示例：tag:server）')
                if tag_str not in cleaned:
                    cleaned.append(tag_str)
            if not cleaned:
                raise ValueError('请至少提供一个有效标签（如 tag:server）')
            _ensure_tags_in_policy(cleaned)
            headscale_cli('nodes', 'tag', '-i', str(nid), '-t', ','.join(cleaned), '--force', timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {'ok': True, 'message': '节点标签已更新', 'snapshot': snapshot}

        if action == 'approve_routes':
            nid = _parse_positive_int(payload.get('node_id'), '节点 ID')
            raw_routes = payload.get('routes') or []
            if isinstance(raw_routes, str):
                raw_routes = [r.strip() for r in raw_routes.split(',') if r.strip()]
            cleaned_routes = []
            for r in raw_routes:
                try:
                    net = ipaddress.ip_network(str(r).strip(), strict=False)
                    cleaned_routes.append(str(net))
                except ValueError:
                    raise ValueError(f'无效的 CIDR 子网网段：{r}')
            route_arg = ','.join(cleaned_routes)
            headscale_cli('nodes', 'approve-routes', '-i', str(nid), '-r', route_arg, '--force', timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {'ok': True, 'message': '节点子网路由审批已更新', 'snapshot': snapshot}

        if action == 'create_preauthkey':
            uid = _parse_positive_int(payload.get('user_id', 1), '用户 ID')
            exp_key = str(payload.get('expiration') or '24h').strip()
            exp_duration = EXPIRATION_MAP.get(exp_key)
            if not exp_duration:
                raise ValueError('不支持的有效期选项，请选择 1h、24h、7d、30d、90d 或 365d')
            args = ['preauthkeys', 'create', '-u', str(uid), '-e', exp_duration]
            if payload.get('reusable'):
                args.append('--reusable')
            if payload.get('ephemeral'):
                args.append('--ephemeral')
            raw_tags = payload.get('tags') or []
            if isinstance(raw_tags, str):
                raw_tags = [t.strip() for t in raw_tags.split(',') if t.strip()]
            cleaned_tags = []
            for t in raw_tags:
                tag_str = str(t).strip()
                if not tag_str:
                    continue
                if not tag_str.startswith('tag:'):
                    tag_str = 'tag:' + tag_str
                if not TAG_RE.match(tag_str):
                    raise ValueError(f'标签格式不合法：{tag_str}')
                cleaned_tags.append(tag_str)
            if cleaned_tags:
                args.extend(['--tags', ','.join(cleaned_tags)])

            created = headscale_cli(*args, timeout=6)
            plaintext_key = ''
            if isinstance(created, dict):
                plaintext_key = str(created.get('key') or created.get('raw') or '').strip()
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': '密钥已生成，请复制保存',
                'created_key': plaintext_key,
                'snapshot': snapshot,
            }

        if action == 'expire_preauthkey':
            kid = _parse_positive_int(payload.get('key_id'), '密钥 ID')
            headscale_cli('preauthkeys', 'expire', '-i', str(kid), '--force', timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {'ok': True, 'message': f'预授权密钥 #{kid} 已废止', 'snapshot': snapshot}

        if action == 'delete_preauthkey':
            kid = _parse_positive_int(payload.get('key_id'), '密钥 ID')
            headscale_cli('preauthkeys', 'delete', '-i', str(kid), '--force', timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {'ok': True, 'message': f'预授权密钥 #{kid} 已删除', 'snapshot': snapshot}

        if action == 'save_dns_record':
            hs_cfg = read_headscale_config()
            base_domain = hs_cfg.get('base_domain') or 'nodes.internal'
            record = normalize_dns_record(payload.get('name'), payload.get('value'), base_domain=base_domain)
            updated_records = upsert_dns_record(
                hs_cfg.get('extra_records') or [],
                record,
                old_name=payload.get('old_name'),
                old_type=payload.get('old_type'),
                old_value=payload.get('old_value'),
            )
            _ensure_extra_records_path_enabled(updated_records)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': f'解析记录已保存：{record["name"]} -> {record["value"]}',
                'snapshot': snapshot,
            }

        if action == 'delete_dns_record':
            hs_cfg = read_headscale_config()
            updated_records = remove_dns_record(
                hs_cfg.get('extra_records') or [],
                payload.get('name'),
                record_type=payload.get('type'),
                value=payload.get('value'),
            )
            _ensure_extra_records_path_enabled(updated_records)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': '解析记录已删除',
                'snapshot': snapshot,
            }

        if action == 'save_dns_config':
            if not HEADSCALE_CONFIG.exists():
                raise ValueError('未找到 Headscale 配置文件')
            try:
                raw_cfg = json.loads(HEADSCALE_CONFIG.read_text(encoding='utf-8'))
            except ValueError:
                raise ValueError('Headscale 配置文件格式不支持在线修改')
            hs_cfg = read_headscale_config()
            _write_extra_records_file(hs_cfg.get('extra_records') or [])
            updated_cfg = prepare_dns_config_update(raw_cfg, payload)
            _apply_headscale_config_dict(updated_cfg)
            time.sleep(0.5)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': 'DNS 配置已生效',
                'snapshot': snapshot,
            }

        if action == 'check_acl_policy':
            _check_and_apply_acl_policy(payload.get('policy'), apply_changes=False)
            return {
                'ok': True,
                'valid': True,
                'message': '策略语法校验通过',
            }

        if action == 'save_acl_policy':
            _check_and_apply_acl_policy(payload.get('policy'), apply_changes=True)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': '访问控制策略已保存并生效',
                'snapshot': snapshot,
            }

        if action == 'create_user':
            name = str(payload.get('name') or '').strip()
            if not USER_NAME_RE.match(name):
                raise ValueError('用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）')
            args = ['users', 'create', name]
            display_name = str(payload.get('display_name') or '').strip()
            if display_name:
                if len(display_name) > 64:
                    raise ValueError('备注名称过长（最多 64 个字符）')
                args.extend(['-d', display_name])
            email = str(payload.get('email') or '').strip()
            if email:
                if len(email) > 120 or '@' not in email:
                    raise ValueError('邮箱格式无效')
                args.extend(['-e', email])
            headscale_cli(*args, timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': f'已创建用户「{name}」',
                'snapshot': snapshot,
            }

        if action == 'rename_user':
            uid = _parse_positive_int(payload.get('user_id'), '用户 ID')
            new_name = str(payload.get('new_name') or '').strip()
            if not USER_NAME_RE.match(new_name):
                raise ValueError('新用户名需以字母开头，仅允许字母、数字、点、下划线或连字符（1-62 位）')
            headscale_cli('users', 'rename', '-i', str(uid), '-r', new_name, '--force', timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': f'用户已重命名为「{new_name}」',
                'snapshot': snapshot,
            }

        if action == 'delete_user':
            uid = _parse_positive_int(payload.get('user_id'), '用户 ID')
            current = collect()
            for u in current.get('users') or []:
                if u.get('id') == uid and (u.get('node_count') or 0) > 0:
                    raise ValueError(f'用户「{u.get("name")}」下仍有 {u.get("node_count")} 台设备，请先移除设备后再删除用户')
            headscale_cli('users', 'destroy', '-i', str(uid), '--force', timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': '用户已删除',
                'snapshot': snapshot,
            }

        if action == 'run_netcheck':
            get_netcheck(force=True, timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': '网络诊断已完成',
                'snapshot': snapshot,
            }

        if action == 'ping_all':
            get_netcheck(force=True, timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            nodes_list = snapshot.get('nodes') or []
            direct_cnt = sum(1 for n in nodes_list if n.get('connection') == 'direct')
            relay_cnt = sum(1 for n in nodes_list if n.get('connection') == 'relay')
            return {
                'ok': True,
                'message': f'全网测速完成：{direct_cnt} 台直连，{relay_cnt} 台中继',
                'snapshot': snapshot,
            }

        if action == 'move_node_user':
            nid = _parse_positive_int(payload.get('node_id'), '节点 ID')
            uid = _parse_positive_int(payload.get('user_id'), '目标用户 ID')
            user_name = _move_node_to_user(nid, uid)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': f'已将节点迁移至用户「{user_name}」',
                'snapshot': snapshot,
            }

        if action == 'set_node_ip':
            nid = _parse_positive_int(payload.get('node_id'), '节点 ID')
            updated_ip = _set_node_ipv4(nid, payload.get('ipv4'))
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': f'节点内网 IP 已修改为 {updated_ip}',
                'snapshot': snapshot,
            }

        if action == 'register_node':
            user = str(payload.get('user') or '').strip()
            if not USER_NAME_RE.match(user):
                raise ValueError('请选择有效的所属用户')
            kind, token = parse_register_token(payload.get('token'))
            if kind == 'node_key':
                headscale_cli('nodes', 'register', '-u', user, '-k', token, timeout=8)
            else:
                headscale_cli('auth', 'register', '-u', user, '--auth-id', token, timeout=8)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': f'节点已批准接入至用户「{user}」',
                'snapshot': snapshot,
            }

        if action == 'export_config':
            snapshot = collect()
            write_snapshot(snapshot)
            bundle = build_export_bundle(snapshot)
            date_str = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            return {
                'ok': True,
                'message': '已生成最新配置快照',
                'filename': f'headscale-backup-{date_str}.json',
                'bundle': bundle,
                'snapshot': snapshot,
            }

        if action == 'restore_config':
            restored_parts = _restore_backup_bundle(
                payload.get('bundle'),
                restore_dns=bool(payload.get('restore_dns', True)),
                restore_acl=bool(payload.get('restore_acl', True)),
                restore_derp=bool(payload.get('restore_derp', True)),
            )
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': f'已成功恢复：{"、".join(restored_parts)}',
                'snapshot': snapshot,
            }

        if action == 'save_derp_config':
            if not HEADSCALE_CONFIG.exists():
                raise ValueError('未找到 Headscale 配置文件')
            try:
                raw_cfg = json.loads(HEADSCALE_CONFIG.read_text(encoding='utf-8'))
            except ValueError:
                raise ValueError('Headscale 配置文件格式不支持在线修改')
            updated_cfg = prepare_derp_config_update(raw_cfg, payload)
            _apply_headscale_config_dict(updated_cfg)
            for _ in range(10):
                try:
                    headscale_cli('nodes', 'list', timeout=3)
                    break
                except Exception:
                    time.sleep(0.2)
            _apply_local_tailscale_prefs(payload)
            get_netcheck(force=True, timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': '本机与中继配置已保存并生效',
                'snapshot': snapshot,
            }

        if action == 'set_local_exit_node':
            enable_exit = bool(payload.get('enabled', True))
            _apply_local_tailscale_prefs({'advertise_exit_node': enable_exit})
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': '已开启本机作为出口节点并自动批准路由' if enable_exit else '已关闭本机出口节点功能',
                'snapshot': snapshot,
            }

        if action == 'install_local_tailscale':
            if not Path(TAILSCALE_BIN).exists():
                subprocess.run(
                    ['/bin/sh', '-c', 'curl -fsSL https://tailscale.com/install.sh | sh'],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
            subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'tailscaled.service'], check=True, timeout=15)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': '本机 Tailscale 客户端已安装并启动服务',
                'snapshot': snapshot,
            }

        if action == 'connect_local_node':
            hs_cfg = read_headscale_config()
            server_url = str(payload.get('server_url') or hs_cfg.get('server_url') or '').strip()
            if not server_url:
                raise ValueError('未检测到服务端地址 (server_url)')
            hostname = str(payload.get('hostname') or _default_observer_name()).strip()
            if not NODE_NAME_RE.match(hostname):
                hostname = _default_observer_name()

            raw_users = []
            try:
                raw_users = headscale_cli('users', 'list', timeout=4) or []
            except Exception:
                pass
            if not raw_users:
                headscale_cli('users', 'create', 'admin', timeout=6)
                raw_users = headscale_cli('users', 'list', timeout=4) or []
            uid = int(raw_users[0].get('id') or 1)
            key_res = headscale_cli('preauthkeys', 'create', '-u', str(uid), '-e', '1h', '--reusable', timeout=6) or {}
            auth_key = str(key_res.get('key') or '').strip()
            if not auth_key:
                raise ValueError('自动签发本机接入密钥失败')

            subprocess.run(
                [
                    TAILSCALE_BIN,
                    'up',
                    f'--login-server={server_url}',
                    f'--authkey={auth_key}',
                    f'--hostname={hostname}',
                    '--accept-routes',
                    '--reset',
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            try:
                nodes_after = headscale_cli('nodes', 'list', timeout=4) or []
                for n in nodes_after:
                    if str(n.get('given_name') or n.get('name')) == hostname and n.get('id'):
                        headscale_cli('nodes', 'expire', '-i', str(n['id']), '--disable', '--force', timeout=5)
                        break
            except Exception:
                pass
            get_netcheck(force=True, timeout=6)
            snapshot = collect()
            write_snapshot(snapshot)
            return {
                'ok': True,
                'message': f'本机节点 ({hostname}) 已成功接入组网并设为永不过期',
                'snapshot': snapshot,
            }

        raise ValueError(f'未知的操作类型：{action}')


def collect_safe():
    try:
        snapshot = collect()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, http.client.HTTPException):
        snapshot = {
            'schema': 1,
            'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'observer': _default_observer_name(),
            'control_state': 'Unknown',
            'interval_seconds': 15,
            'tailnet': {
                'control_url': '',
                'magic_dns_suffix': 'nodes.internal',
                'magic_dns_enabled': True,
                'client_version': '',
            },
            'dns': {
                'magic_dns': True,
                'base_domain': 'nodes.internal',
                'override_local_dns': False,
                'nameservers_global': [],
                'nameservers_split': {},
                'search_domains': [],
                'extra_records': [],
            },
            'acl': summarize_acl_policy(''),
            'diagnostics': build_diagnostics(),
            'nodes': [],
            'users': [],
            'preauthkeys': [],
            'routes': [],
            'errors': ['无法读取组网状态，请检查 Headscale、Tailscale 和采集服务。'],
        }
    write_snapshot(snapshot)
    return snapshot


class ControlServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True


def make_handler(expected_token):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def _send_json(self, status_code, data):
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _check_auth(self):
            supplied = self.headers.get('X-Control-Token') or ''
            return hmac.compare_digest(supplied, expected_token)

        def do_GET(self):
            if not self._check_auth():
                self._send_json(403, {'ok': False, 'error': '未授权的本地控制请求'})
                return
            if self.path == '/status':
                try:
                    data = json.loads(OUTPUT.read_text(encoding='utf-8'))
                except Exception:
                    data = collect_safe()
                self._send_json(200, {'ok': True, 'snapshot': data})
                return
            self._send_json(404, {'ok': False, 'error': '未知路径'})

        def do_POST(self):
            if not self._check_auth():
                self._send_json(403, {'ok': False, 'error': '未授权的本地控制请求'})
                return
            if self.path != '/action':
                self._send_json(404, {'ok': False, 'error': '未知路径'})
                return
            req_lang = 'zh'
            try:
                length = int(self.headers.get('Content-Length') or 0)
                if length <= 0 or length > 524288:
                    raise ValueError('请求体大小异常')
                payload = json.loads(self.rfile.read(length).decode('utf-8'))
                if isinstance(payload, dict):
                    req_lang = normalize_lang(payload.get('lang'))
                result = execute_action(payload)
                self._send_json(200, result)
            except ValueError as exc:
                self._send_json(400, {'ok': False, 'error': localize_message(str(exc), req_lang)})
            except subprocess.CalledProcessError as exc:
                stderr = (exc.stderr or exc.stdout or '').strip()
                first_line = stderr.splitlines()[0] if stderr else localize_message('命令执行失败', req_lang)
                self._send_json(500, {'ok': False, 'error': localize_message(f'Headscale 执行失败：{first_line}', req_lang)})
            except Exception as exc:
                self._send_json(500, {'ok': False, 'error': localize_message(f'操作失败：{exc}', req_lang)})

    return Handler


def run_daemon():
    token = ensure_control_token()
    server = ControlServer((CONTROL_HOST, CONTROL_PORT), make_handler(token))

    def periodic_worker():
        while True:
            with ACTION_LOCK:
                try:
                    ensure_control_token(token)
                    collect_safe()
                except Exception:
                    pass
            for _ in range(15):
                time.sleep(1)
                if not TOKEN_FILE.exists() or not OUTPUT.exists():
                    break

    worker = threading.Thread(target=periodic_worker, daemon=True)
    worker.start()

    try:
        server.serve_forever()
    finally:
        server.server_close()


def main():
    if '--daemon' in sys.argv[1:]:
        run_daemon()
    else:
        ensure_control_token()
        collect_safe()


if __name__ == '__main__':
    main()
