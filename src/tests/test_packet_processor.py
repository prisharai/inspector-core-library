"""
Tests for libinspector.packet_processor.
"""

import json
import os
import unittest
from unittest import mock

import scapy.all as sc

import libinspector.global_state as global_state
import libinspector.mem_db as mem_db
import libinspector.packet_processor as packet_processor


class PacketProcessorTestCase(unittest.TestCase):
    """Base fixture: fresh in-memory DB and fake host identity in global_state."""

    HOST_MAC = "10:00:00:00:00:01"
    HOST_IP = "192.168.1.100"
    GATEWAY_MAC = "20:00:00:00:00:01"
    GATEWAY_IP = "192.168.1.1"
    DEVICE_MAC = "aa:bb:cc:dd:ee:ff"
    DEVICE_IP = "192.168.1.55"

    def setUp(self):
        env_patcher = mock.patch.dict(os.environ)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop("USE_IN_MEMORY_DB", None)
        os.environ.pop("SCAN_ALL_DEVICES", None)

        self.conn, self.rw_lock = mem_db.initialize_db()
        self.addCleanup(self.conn.close)

        with global_state.global_state_lock:
            self._saved_state = (
                global_state.db_conn_and_lock,
                global_state.host_mac_addr,
                global_state.host_ip_addr,
                global_state.gateway_ip_addr,
            )
            global_state.db_conn_and_lock = (self.conn, self.rw_lock)
            global_state.host_mac_addr = self.HOST_MAC
            global_state.host_ip_addr = self.HOST_IP
            global_state.gateway_ip_addr = self.GATEWAY_IP
        self.addCleanup(self._restore_global_state)

    def _restore_global_state(self):
        with global_state.global_state_lock:
            (
                global_state.db_conn_and_lock,
                global_state.host_mac_addr,
                global_state.host_ip_addr,
                global_state.gateway_ip_addr,
            ) = self._saved_state

    def count(self, table):
        with self.rw_lock:
            return self.conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()[
                "n"
            ]


class TestProcessArp(PacketProcessorTestCase):
    def _arp(self, op=2, hwsrc=None, psrc=None):
        return sc.ARP(
            op=op,
            hwsrc=hwsrc or self.DEVICE_MAC,
            psrc=psrc or self.DEVICE_IP,
        )

    def test_inserts_device_with_oui_vendor(self):
        packet_processor.process_arp(self._arp())

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT * FROM devices WHERE mac_address = ?", (self.DEVICE_MAC,)
            ).fetchone()

        self.assertEqual(row["ip_address"], self.DEVICE_IP)
        self.assertEqual(row["is_gateway"], 0)
        self.assertGreater(row["updated_ts"], 0)
        self.assertIn("oui_vendor", json.loads(row["metadata_json"]))

    def test_gateway_flag_set_for_gateway_ip(self):
        packet_processor.process_arp(
            self._arp(hwsrc=self.GATEWAY_MAC, psrc=self.GATEWAY_IP)
        )

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT is_gateway FROM devices WHERE mac_address = ?",
                (self.GATEWAY_MAC,),
            ).fetchone()

        self.assertEqual(row["is_gateway"], 1)

    def test_ignores_packet_from_host(self):
        packet_processor.process_arp(self._arp(hwsrc=self.HOST_MAC))
        self.assertEqual(self.count("devices"), 0)

    def test_ignores_zero_source_ip(self):
        packet_processor.process_arp(self._arp(psrc="0.0.0.0"))
        self.assertEqual(self.count("devices"), 0)

    def test_ignores_non_request_reply_opcodes(self):
        packet_processor.process_arp(self._arp(op=3))
        self.assertEqual(self.count("devices"), 0)

    def test_updates_ip_for_existing_device(self):
        packet_processor.process_arp(self._arp(psrc="192.168.1.55"))
        packet_processor.process_arp(self._arp(psrc="192.168.1.66"))

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT ip_address FROM devices WHERE mac_address = ?",
                (self.DEVICE_MAC,),
            ).fetchone()

        self.assertEqual(self.count("devices"), 1)
        self.assertEqual(row["ip_address"], "192.168.1.66")


class TestProcessDhcp(PacketProcessorTestCase):
    def _dhcp(
        self, ether_dst="ff:ff:ff:ff:ff:ff", ether_src=None, hostname=b"my-iot-device"
    ):
        options = [("message-type", "request")]
        if hostname is not None:
            options.append(("hostname", hostname))
        options.append("end")
        return (
            sc.Ether(src=ether_src or self.DEVICE_MAC, dst=ether_dst)
            / sc.IP(src=self.DEVICE_IP, dst="255.255.255.255")
            / sc.UDP(sport=68, dport=67)
            / sc.BOOTP()
            / sc.DHCP(options=options)
        )

    def test_inserts_device_with_dhcp_hostname(self):
        packet_processor.process_dhcp(self._dhcp())

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT * FROM devices WHERE mac_address = ?", (self.DEVICE_MAC,)
            ).fetchone()

        self.assertEqual(row["ip_address"], self.DEVICE_IP)
        metadata = json.loads(row["metadata_json"])
        self.assertEqual(metadata["dhcp_hostname"], "my-iot-device")

    def test_ignores_non_broadcast(self):
        packet_processor.process_dhcp(self._dhcp(ether_dst=self.HOST_MAC))
        self.assertEqual(self.count("devices"), 0)

    def test_ignores_missing_hostname_option(self):
        packet_processor.process_dhcp(self._dhcp(hostname=None))
        self.assertEqual(self.count("devices"), 0)

    def test_ignores_packet_from_host(self):
        packet_processor.process_dhcp(self._dhcp(ether_src=self.HOST_MAC))
        self.assertEqual(self.count("devices"), 0)


class TestWriteHostnameIpMappingToDb(PacketProcessorTestCase):
    def test_inserts_one_row_per_ip(self):
        packet_processor.write_hostname_ip_mapping_to_db(
            self.DEVICE_MAC, "example.com", {"1.2.3.4", "5.6.7.8"}, "dns"
        )

        with self.rw_lock:
            rows = self.conn.execute(
                "SELECT ip_address, hostname, data_source FROM hostnames"
            ).fetchall()

        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["hostname"], "example.com")
            self.assertEqual(row["data_source"], "dns")
        self.assertEqual({row["ip_address"] for row in rows}, {"1.2.3.4", "5.6.7.8"})

    def test_upsert_replaces_hostname_for_existing_ip(self):
        packet_processor.write_hostname_ip_mapping_to_db(
            self.DEVICE_MAC, "old.example.com", {"1.2.3.4"}, "dns"
        )
        packet_processor.write_hostname_ip_mapping_to_db(
            self.DEVICE_MAC, "new.example.com", {"1.2.3.4"}, "sni"
        )

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT hostname, data_source FROM hostnames WHERE ip_address = ?",
                ("1.2.3.4",),
            ).fetchone()

        self.assertEqual(self.count("hostnames"), 1)
        self.assertEqual(row["hostname"], "new.example.com")
        self.assertEqual(row["data_source"], "sni")


class TestUpdateHostnamesInFlows(PacketProcessorTestCase):
    def test_fills_missing_hostnames_from_hostnames_table(self):
        with self.rw_lock:
            self.conn.execute(
                """
                INSERT INTO network_flows (
                    timestamp, src_ip_address, dest_ip_address,
                    src_mac_address, dest_mac_address, src_port, dest_port, protocol
                ) VALUES (1000, '192.168.1.55', '1.2.3.4', ?, ?, '5000', '443', 'tcp')
                """,
                (self.DEVICE_MAC, self.GATEWAY_MAC),
            )
            self.conn.execute(
                "INSERT INTO hostnames (ip_address, hostname, data_source) "
                "VALUES ('192.168.1.55', 'device.local', 'dns')"
            )
            self.conn.execute(
                "INSERT INTO hostnames (ip_address, hostname, data_source) "
                "VALUES ('1.2.3.4', 'example.com', 'dns')"
            )

        packet_processor.update_hostnames_in_flows()

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT src_hostname, dest_hostname FROM network_flows"
            ).fetchone()

        self.assertEqual(row["src_hostname"], "device.local")
        self.assertEqual(row["dest_hostname"], "example.com")


if __name__ == "__main__":
    unittest.main()
