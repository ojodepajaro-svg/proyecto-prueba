import tempfile
import unittest
from pathlib import Path

from netmap import classify, demo, scan
from netmap.config import norm_mac


class ClassifyTest(unittest.TestCase):
    def test_types(self):
        self.assertEqual(classify.guess_type({"ports": [62078]}), "phone")
        self.assertEqual(classify.guess_type({"ports": [9100, 80]}), "printer")
        self.assertEqual(classify.guess_type({"ports": [554, 80]}), "camera")
        self.assertEqual(classify.guess_type({"vendor": "Espressif Inc."}), "iot")
        self.assertEqual(classify.guess_type({"is_gateway": True}), "router")

    def test_randomized_mac_is_wifi(self):
        conn, _ = classify.guess_connection({"mac": "da:a1:19:5e:22:10"})
        self.assertEqual(conn, "wifi")
        conn, _ = classify.guess_connection({"mac": "00:11:32:aa:bb:cc", "type": "unknown"})
        self.assertIsNone(conn)

    def test_norm_mac(self):
        self.assertEqual(norm_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(norm_mac("nope"))


class StateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        scan.set_data_dir(Path(self.tmp.name))
        self.cfg = demo.demo_config()
        scan.save_scan(demo.fake_scan())

    def tearDown(self):
        self.tmp.cleanup()

    def devices(self):
        return {d["key"]: d for d in scan.build_state(self.cfg)["devices"]}

    def test_infra_is_not_listed_as_device(self):
        ips = {d["ip"] for d in self.devices().values()}
        self.assertNotIn("192.168.1.1", ips)
        self.assertNotIn("192.168.1.3", ips)

    def test_site_follows_parent(self):
        d = self.devices()["5c:cf:7f:aa:bb:cc"]
        self.assertEqual((d["parent"], d["site"], d["connection"]), ("ap-fondito", "fondito", "wifi"))

    def test_switch_port_is_cable(self):
        d = self.devices()["00:11:32:aa:bb:cc"]
        self.assertEqual((d["connection"], d["confirmed"], d["port"]), ("cable", True, "2"))

    def test_shared_port_is_not_confirmed(self):
        d = self.devices()["f4:4d:30:aa:bb:01"]
        self.assertFalse(d["confirmed"])

    def test_manual_override_wins(self):
        scan.save_override("00:11:32:aa:bb:cc", {"connection": "wifi", "name": "NAS"})
        d = self.devices()["00:11:32:aa:bb:cc"]
        self.assertEqual((d["connection"], d["name"]), ("wifi", "NAS"))
        scan.save_override("00:11:32:aa:bb:cc", {"connection": "", "name": ""})
        self.assertEqual(self.devices()["00:11:32:aa:bb:cc"]["connection"], "cable")


if __name__ == "__main__":
    unittest.main()
