import unittest

from main import classify_host, parse_ss_output, split_endpoint


SAMPLE = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    127.0.0.1:631       0.0.0.0:*       users:(("cupsd",pid=900,fd=7))
tcp   LISTEN 0      4096   0.0.0.0:22         0.0.0.0:*       users:(("sshd",pid=700,fd=3))
tcp   LISTEN 0      128    [::]:443            [::]:*          users:(("nginx",pid=1000,fd=6))
udp   UNCONN 0      0      127.0.0.53%lo:53    0.0.0.0:*       users:(("systemd-resolve",pid=500,fd=14))
"""


class SocketScoutTests(unittest.TestCase):
    def test_parses_listener_rows(self):
        report = parse_ss_output(SAMPLE)
        self.assertEqual(report["socket_count"], 4)
        self.assertEqual(report["wildcard_bind_count"], 2)

    def test_ipv4_loopback_is_classified(self):
        report = parse_ss_output(SAMPLE)
        self.assertEqual(report["sockets"][0]["bind_scope"], "loopback")

    def test_ipv6_bracketed_endpoint(self):
        host, port = split_endpoint("[::]:443")
        self.assertEqual(host, "::")
        self.assertEqual(port, "443")
        self.assertEqual(classify_host(host), "wildcard")

    def test_interface_zone_is_handled(self):
        self.assertEqual(classify_host("127.0.0.53%lo"), "loopback")

    def test_malformed_rows_are_counted(self):
        report = parse_ss_output("bad row\n")
        self.assertEqual(report["malformed_lines_ignored"], 1)


if __name__ == "__main__":
    unittest.main()
