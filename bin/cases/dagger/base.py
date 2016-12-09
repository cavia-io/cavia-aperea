# -*- coding: UTF-8 -*-

import re
import time
from ngta import TestCase, parametrize

import logging
logger = logging.getLogger(__name__)


@parametrize("channel", type=int, default=0)
@parametrize("duration", type=int, default=5)
@parametrize("psk", type=str, default="12345678")

class BaseDaggerTestCase(TestCase):
    def make_connected(self, sta):
        if not sta.is_connected():
            ssid = self._test_sta_scan(sta)
            self._test_sta_connect(sta, ssid)

    def _test_sta_reconnect(self, sta):
        self._test_sta_disconnect(sta)
        ssid = self._test_sta_scan(sta)
        self._test_sta_connect(sta, ssid)

    def _test_sta_disconnect(self, sta):
        sta.disconnect()
        self.assertFalse(sta.is_connected(), msg="%s should be disconnected." % sta)

    def _test_sta_scan(self, sta):
        ssid = []
        resp = sta.scan(self.parameters.channel)
        match1 = re.findall(r"SSID: (.*)",resp)
        self.assertGreaterEqual(len(match1), 1, msg="SSIDs should be found in %s"%match1)
        ssid.extend(match1)
        match2 = re.findall(r"BSS (.*)\(+on (.*)\)+",resp)
        self.assertGreaterEqual(len(match2), 1, msg="BSSs should be found in %s"%match2)
        return ssid

    def _test_sta_connect(self, sta, ssid, attempts=5, waiting=5):
        i = 0
        while i <= attempts:
            i += 1
            sta.connect(ssid)
            time.sleep(waiting)
            if sta.is_connected():
                break
            else:
                sta.scan("")

        self.assertLessEqual(i, attempts,
                             msg="%s connect %s attempts should no more than %s times." % (sta, ssid, attempts))
        self.assertEqual(i, 1, msg="%s connect %s should succeed without retry." % (sta, ssid), is_warning=True)

    def _test_ping(self, dut, addr, duration):
        resp = dut.ping(addr, duration)
        self._check_ping(addr, duration, resp)

    def _check_ping(self, addr, duration, resp):
        lines = resp.split("\n")
        success = True
        if not lines:
            success = False
        else:
            for index in range(1, duration + 1):
                line = lines[index]
                match = re.search(r"(.*) bytes from %s: icmp_seq=(.*) ttl=(.*) time=(.*) ms" % addr, line)
                if not match:
                    success = False
                    break
        self.assertTrue(success, "Ping %s should succeed in %ss." % (addr, duration))

        match = re.search(r'ping statistics(?:.*)\n(.*\n.*)', resp, re.MULTILINE)
        self.assertTrue(match, msg="Ping response should include statistics.")
        self.add_concern("statistics", match.group(1))

    def _check_iperf3_measure_result(self, resp, duration):
        for second in range(int(duration)):
            cur_second = "%s.00-%s.00"%(int(second), int(second)+1)
            match_1 = re.search(str(cur_second), resp ,re.I)
            if not match_1:
                break
        self.assertTrue(match_1,"Each second test log should be found during %ss!" % duration)
        match_2 = re.search("0.00 bits/sec", resp, re.I)
        self.assertFalse(match_2, "Iperf3 TCP/UDP throughput should not drop to 0 during %ss!" % duration)

    def _check_iperf_measure_result(self, resp, duration):
        match_1=None
        for second in range(int(duration)):
            if second < 9:
                cur_second = "%s.0- %s.0"%(int(second), int(second)+1)
            else:
                cur_second = "%s.0-%s.0"%(int(second), int(second)+1)
            match_1 = re.search(str(cur_second), resp, re.I)
            if not match_1:
                break
        self.assertTrue(match_1,"Each second test log should be found during %ss!" % duration)
        match_2 = re.search("0.0 bits/sec", resp, re.I)
        self.assertFalse(match_2, "Iperf TCP/UDP throughput should not drop to 0 during %ss!" % duration)

    def _str_compare(self, string, resp):
        match = re.search(string, resp, re.MULTILINE)
        return match


