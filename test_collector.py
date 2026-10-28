import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from collector import (
    _restore_backup_bundle,
    _set_node_ipv4,
    build_diagnostics,
    build_export_bundle,
    build_snapshot,
    connection_result,
    execute_action,
    normalize_dns_record,
    parse_netcheck_output,
    parse_register_token,
    parse_timestamp,
    preferred_ip,
    prepare_derp_config_update,
    prepare_dns_config_update,
    probe,
    remove_dns_record,
    strip_hujson_to_json,
    summarize_acl_policy,
    upsert_dns_record,
    validate_acl_policy_structure,
)


class ConnectionTests(unittest.TestCase):
    def test_direct_latency_uses_structured_probe(self):
        result = connection_result({'Err': '', 'LatencySeconds': 0.02190668, 'Endpoint': '198.51.100.21:35710', 'DERPRegionID': 0})
        self.assertEqual(result, {'connection': 'direct', 'latency_ms': 21.9, 'relay': None})

    def test_derp_and_peer_relay_are_not_called_direct(self):
        self.assertEqual(connection_result({'LatencySeconds': .03, 'DERPRegionID': 999, 'DERPRegionCode': 'local'})['connection'], 'relay')
        self.assertEqual(connection_result({'LatencySeconds': .03, 'PeerRelay': '100.64.0.4', 'Endpoint': 'endpoint'})['connection'], 'peer-relay')

    def test_error_never_displays_a_successful_latency(self):
        self.assertEqual(connection_result({'Err': 'timeout', 'LatencySeconds': 0, 'Endpoint': 'old'}), {'connection': 'unreachable', 'latency_ms': None, 'relay': None})

    def test_unknown_path_is_not_assumed_direct(self):
        self.assertEqual(connection_result({'LatencySeconds': .01})['connection'], 'unknown')

    def test_only_valid_tailnet_addresses_are_probed(self):
        self.assertEqual(preferred_ip(['bad', '8.8.8.8', 'fd7a:115c:a1e0::2', '100.64.0.2']), '100.64.0.2')
        self.assertIsNone(preferred_ip(['127.0.0.1', '192.168.2.4']))

    def test_one_lost_probe_is_retried_before_showing_failure(self):
        with patch('collector.local_api', side_effect=[TimeoutError(), {'Endpoint': 'direct', 'LatencySeconds': .02}]):
            self.assertEqual(probe('100.64.0.3')['connection'], 'direct')

    def test_second_probe_can_observe_relay_to_direct_transition(self):
        with patch('collector.local_api', side_effect=[{'DERPRegionID': 999, 'LatencySeconds': .03}, {'Endpoint': 'direct', 'LatencySeconds': .02}]):
            self.assertEqual(probe('100.64.0.3')['connection'], 'direct')


class SnapshotTests(unittest.TestCase):
    def test_offline_and_local_nodes_do_not_trigger_network_probes(self):
        nodes = [
            {'id': 1, 'name': 'gateway', 'online': True, 'ip_addresses': ['100.64.0.1'], 'machine_key': 'must-not-leak'},
            {'id': 5, 'name': 'offline-mac', 'online': False, 'ip_addresses': ['100.64.0.5']},
            {'id': 3, 'name': 'node-1', 'online': True, 'ip_addresses': ['100.64.0.3'], 'user': {'id': 1, 'name': 'admin'}},
        ]
        calls = []

        def fake_probe(ip):
            calls.append(ip)
            return {'connection': 'direct', 'latency_ms': 12.0, 'relay': None}

        status = {
            'BackendState': 'Running',
            'Version': '1.104.4',
            'MagicDNSSuffix': 'nodes.internal',
            'Self': {'ID': '1', 'NodeID': 1, 'HostName': 'gateway', 'OS': 'linux', 'TailscaleIPs': ['100.64.0.1']},
            'Peer': {
                'k3': {
                    'ID': '3',
                    'NodeID': 3,
                    'HostName': 'node-1',
                    'DNSName': 'node-1.nodes.internal.',
                    'OS': 'linux',
                    'CurAddr': '198.51.100.32:41641',
                    'RxBytes': 2048,
                    'TxBytes': 1024,
                    'TailscaleIPs': ['100.64.0.3'],
                }
            },
        }
        data = build_snapshot(nodes, status, fake_probe)
        self.assertEqual(calls, ['100.64.0.3'])
        rows = {row['name']: row for row in data['nodes']}
        self.assertEqual(rows['gateway']['connection'], 'self')
        self.assertIsNone(rows['gateway']['latency_ms'])
        self.assertEqual(rows['offline-mac']['connection'], 'offline')
        self.assertEqual(rows['node-1']['os'], 'linux')
        self.assertEqual(rows['node-1']['active_endpoint'], '198.51.100.32:41641')
        self.assertEqual(rows['node-1']['dns_name'], 'node-1.nodes.internal')
        self.assertEqual(rows['node-1']['user'], 'admin')
        self.assertNotIn('machine_key', str(data))

    def test_probe_failure_preserves_control_online_state(self):
        def broken(ip):
            raise TimeoutError()

        data = build_snapshot([{'name': 'peer', 'online': True, 'ip_addresses': ['100.64.0.2']}], {'BackendState': 'Running'}, broken)
        row = data['nodes'][0]
        self.assertTrue(row['online'])
        self.assertEqual(row['connection'], 'unreachable')
        self.assertIsNone(row['latency_ms'])

    def test_stopped_daemon_does_not_probe_or_guess_paths(self):
        def forbidden(ip):
            raise AssertionError('must not probe')

        data = build_snapshot([{'name': 'peer', 'online': True, 'ip_addresses': ['100.64.0.2']}], {'BackendState': 'Stopped'}, forbidden)
        self.assertEqual(data['nodes'][0]['connection'], 'unknown')

    def test_protobuf_timestamps_and_preauthkeys_are_normalized(self):
        ts = parse_timestamp({'seconds': 1793163982, 'nanos': 0})
        self.assertTrue(ts.startswith('2026-10-28T'))
        self.assertIsNone(parse_timestamp('0001-01-01T00:00:00Z'))

        keys = [
            {
                'id': 10,
                'key': 'hskey-auth-abcdef123456-***',
                'used': False,
                'reusable': True,
                'ephemeral': False,
                'user': {'id': 1, 'name': 'admin'},
                'created_at': {'seconds': 1793157000, 'nanos': 0},
                'expiration': {'seconds': 1993157000, 'nanos': 0},
            }
        ]
        snap = build_snapshot([], {'BackendState': 'Running'}, preauthkeys=keys)
        self.assertEqual(len(snap['preauthkeys']), 1)
        self.assertEqual(snap['preauthkeys'][0]['state'], 'active')
        self.assertTrue(snap['preauthkeys'][0]['reusable'])


class ActionValidationTests(unittest.TestCase):
    def test_rename_rejects_invalid_hostname(self):
        with self.assertRaises(ValueError):
            execute_action({'action': 'rename_node', 'node_id': 2, 'name': '../bad name!'})

    def test_delete_observer_node_is_blocked(self):
        fake_snap = {
            'schema': 1,
            'nodes': [{'id': 1, 'name': 'gateway', 'is_observer': True}],
        }
        with patch('collector.collect', return_value=fake_snap):
            with self.assertRaises(ValueError) as ctx:
                execute_action({'action': 'delete_node', 'node_id': 1})
            self.assertIn('不能直接移除当前控制面所在的本机节点', str(ctx.exception))

    def test_dns_record_normalization_and_crud(self):
        rec = normalize_dns_record('nas', '100.64.0.2', base_domain='nodes.internal')
        self.assertEqual(rec, {'name': 'nas.nodes.internal', 'type': 'A', 'value': '100.64.0.2'})
        rec_v6 = normalize_dns_record('git.lan.', 'fd7a:115c:a1e0::3', base_domain='nodes.internal')
        self.assertEqual(rec_v6, {'name': 'git.lan', 'type': 'AAAA', 'value': 'fd7a:115c:a1e0::3'})

        records = upsert_dns_record([], rec)
        records = upsert_dns_record(records, rec_v6)
        self.assertEqual(len(records), 2)

        updated = normalize_dns_record('nas.nodes.internal', '100.64.0.4', base_domain='nodes.internal')
        records = upsert_dns_record(records, updated, old_name='nas.nodes.internal', old_type='A')
        self.assertEqual(len(records), 2)
        self.assertIn({'name': 'nas.nodes.internal', 'type': 'A', 'value': '100.64.0.4'}, records)

        records = remove_dns_record(records, 'git.lan', record_type='AAAA')
        self.assertEqual(records, [{'name': 'nas.nodes.internal', 'type': 'A', 'value': '100.64.0.4'}])

    def test_dns_config_validation_blocks_override_without_global_ns(self):
        base_cfg = {'dns': {'magic_dns': True, 'base_domain': 'nodes.internal'}}
        with self.assertRaises(ValueError):
            prepare_dns_config_update(base_cfg, {'override_local_dns': True, 'nameservers_global': []})

        valid_cfg = prepare_dns_config_update(
            base_cfg,
            {
                'magic_dns': True,
                'override_local_dns': True,
                'nameservers_global': '223.5.5.5, 1.1.1.1',
                'search_domains': 'home.lan',
                'nameservers_split': 'corp.local=10.0.0.53',
            },
        )
        self.assertEqual(valid_cfg['dns']['nameservers']['global'], ['223.5.5.5', '1.1.1.1'])
        self.assertEqual(valid_cfg['dns']['nameservers']['split'], {'corp.local': ['10.0.0.53']})
        self.assertEqual(valid_cfg['dns']['search_domains'], ['home.lan'])

    def test_hujson_acl_parsing_and_validation(self):
        hujson_text = """
        {
          // 管理员分组
          "groups": {
            "group:admin": ["admin@"],
          },
          "tagOwners": {
            "tag:server": ["group:admin"],
          },
          "acls": [
            {
              "action": "accept",
              "src": ["group:admin"],
              "dst": ["*:*"],
            },
          ],
        }
        """
        summary = summarize_acl_policy(hujson_text)
        self.assertEqual(summary['rules_count'], 1)
        self.assertIn('group:admin', summary['groups'])
        self.assertIn('tag:server', summary['tag_owners'])
        parsed = validate_acl_policy_structure(hujson_text)
        self.assertEqual(len(parsed['acls']), 1)

        with self.assertRaises(ValueError):
            validate_acl_policy_structure('{"acls": [{"action": "deny", "src": ["*"], "dst": ["*:*"]}]}')

    def test_user_validation_and_non_empty_delete_guard(self):
        with self.assertRaises(ValueError):
            execute_action({'action': 'create_user', 'name': '123bad'})

        fake_snap = {
            'schema': 1,
            'users': [{'id': 1, 'name': 'admin', 'node_count': 5}],
        }
        with patch('collector.collect', return_value=fake_snap):
            with self.assertRaises(ValueError) as ctx:
                execute_action({'action': 'delete_user', 'user_id': 1})
            self.assertIn('仍有 5 台设备', str(ctx.exception))

    def test_netcheck_and_derp_diagnostics_parsing(self):
        raw_netcheck = """# Warning: client version "1.96.5" != tailscaled server version "1.96.4"
2026/10/28 15:28:18 portmap: [v1] UPnP: failed
{
  "UDP": true,
  "IPv4": true,
  "IPv6": false,
  "IPv4CanSend": true,
  "IPv6CanSend": false,
  "ICMPv4": true,
  "MappingVariesByDestIP": false,
  "PreferredDERP": 999,
  "RegionLatency": {
    "999": 3363965
  },
  "GlobalV4": "203.0.113.10:56364"
}
"""
        nc = parse_netcheck_output(raw_netcheck, checked_at='2026-10-28T07:30:00Z')
        self.assertTrue(nc['udp'])
        self.assertTrue(nc['ipv4'])
        self.assertFalse(nc['mapping_varies'])
        self.assertEqual(nc['preferred_derp'], 999)
        self.assertEqual(nc['region_latency_ms'], {'999': 3.4})

        derpmap = {
            'Regions': {
                '999': {
                    'RegionID': 999,
                    'RegionCode': 'local',
                    'RegionName': 'local relay',
                    'Nodes': [{'Name': '999', 'RegionID': 999, 'HostName': '203.0.113.10', 'IPv4': '203.0.113.10', 'STUNPort': 3478, 'DERPPort': 443}],
                }
            }
        }
        nodes_rows = [
            {'name': 'node-1', 'connection': 'direct', 'relay': None},
            {'name': 'workstation', 'connection': 'relay', 'relay': 'local'},
        ]
        diag = build_diagnostics(derpmap=derpmap, netcheck=nc, nodes_rows=nodes_rows)
        self.assertEqual(len(diag['derp_regions']), 1)
        reg = diag['derp_regions'][0]
        self.assertEqual(reg['region_id'], 999)
        self.assertEqual(reg['latency_ms'], 3.4)
        self.assertTrue(reg['is_preferred'])
        self.assertEqual(reg['relay_nodes_count'], 1)
        self.assertEqual(reg['relay_node_names'], ['workstation'])

    def test_register_token_parsing_and_export_bundle(self):
        self.assertEqual(
            parse_register_token('https://hs.example.com/register/abcDEF123456'),
            ('auth_id', 'abcDEF123456'),
        )
        self.assertEqual(
            parse_register_token('headscale auth register --user admin --auth-id xyz987654321'),
            ('auth_id', 'xyz987654321'),
        )
        self.assertEqual(
            parse_register_token('nodekey:0123456789abcdef0123456789abcdef'),
            ('node_key', 'nodekey:0123456789abcdef0123456789abcdef'),
        )
        with self.assertRaises(ValueError):
            parse_register_token('short')

        bundle = build_export_bundle({
            'observer': 'gateway',
            'tailnet': {'control_url': 'https://hs.example.com'},
            'dns': {'base_domain': 'nodes.internal'},
            'acl': {'raw': '{"acls":[]}'},
            'users': [{'id': 1, 'name': 'admin'}],
            'nodes': [{'id': 1, 'name': 'gateway', 'hostname': 'gateway', 'user': 'admin', 'ips': ['100.64.0.1'], 'tags': [], 'routes': []}],
            'routes': [],
        })
        self.assertEqual(bundle['backup_schema'], 1)
        self.assertEqual(bundle['observer'], 'gateway')
        self.assertEqual(len(bundle['nodes']), 1)

    def test_prepare_derp_config_update(self):
        cfg = prepare_derp_config_update(
            {'server_url': 'https://hs.example.com'},
            {
                'enabled': True,
                'verify_clients': True,
                'private_only': True,
                'region_code': 'local',
                'region_name': 'local relay',
                'ipv4': '203.0.113.10',
                'stun_port': 3478,
            },
        )
        srv = cfg['derp']['server']
        self.assertTrue(srv['enabled'])
        self.assertTrue(srv['verify_clients'])
        self.assertEqual(srv['region_code'], 'local')
        self.assertEqual(srv['region_name'], 'local relay')
        self.assertEqual(srv['ipv4'], '203.0.113.10')
        self.assertEqual(srv['stun_listen_addr'], '0.0.0.0:3478')
        self.assertEqual(cfg['derp']['urls'], [])

    def test_set_node_ipv4_and_conflict_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / 'db.sqlite'
            conn = sqlite3.connect(str(db_path))
            conn.execute(
                'CREATE TABLE nodes (id INTEGER PRIMARY KEY, given_name TEXT, hostname TEXT, ipv4 TEXT, deleted_at TEXT)'
            )
            conn.execute("INSERT INTO nodes VALUES (1, 'gateway', 'gateway', '100.64.0.1', NULL)")
            conn.execute("INSERT INTO nodes VALUES (2, 'node-1', 'node-1', '100.64.0.2', NULL)")
            conn.commit()
            conn.close()

            with patch('collector.HEADSCALE_DB', db_path), \
                 patch('collector.subprocess.run'), \
                 patch('collector.headscale_cli', return_value=[]):
                with self.assertRaises(ValueError) as ctx_pub:
                    _set_node_ipv4(2, '8.8.8.8')
                self.assertIn('100.64.0.0/10', str(ctx_pub.exception))

                with self.assertRaises(ValueError) as ctx_dup:
                    _set_node_ipv4(2, '100.64.0.1')
                self.assertIn('已被节点「gateway」占用', str(ctx_dup.exception))

                updated = _set_node_ipv4(2, '100.64.0.20')
                self.assertEqual(updated, '100.64.0.20')

                check_conn = sqlite3.connect(str(db_path))
                row = check_conn.execute('SELECT ipv4 FROM nodes WHERE id = 2').fetchone()
                check_conn.close()
                self.assertEqual(row[0], '100.64.0.20')

    def test_restore_backup_bundle(self):
        bundle_json = """
        {
          "backup_schema": 1,
          "dns": {
            "magic_dns": true,
            "base_domain": "nodes.internal",
            "override_local_dns": false,
            "nameservers_global": ["223.5.5.5"],
            "extra_records": [{"name": "nas.nodes.internal", "type": "A", "value": "100.64.0.2"}]
          },
          "acl_policy_raw": "{\\"acls\\":[{\\"action\\":\\"accept\\",\\"src\\":[\\"*\\"],\\"dst\\":[\\"*:*\\"]}]}"
        }
        """
        with patch('collector._write_extra_records_file') as mock_write_rec, \
             patch('collector._check_and_apply_acl_policy') as mock_apply_acl, \
             patch('collector.headscale_cli', return_value=[]):
            parts = _restore_backup_bundle(bundle_json, restore_dns=True, restore_acl=True, restore_derp=False)
            self.assertIn('DNS 配置与解析记录', parts)
            self.assertIn('访问控制策略', parts)
            mock_write_rec.assert_called_once()
            mock_apply_acl.assert_called_once()


if __name__ == '__main__':
    unittest.main()
