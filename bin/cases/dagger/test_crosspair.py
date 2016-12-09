# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase


class CrossPairScanTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp_1 = context.fixture.acquire_pcp(0)
        self.pcp_2 = context.fixture.acquire_pcp(1)
        self.sta = context.fixture.acquire_sta(0)

    @name("Cross Pairs General SSID Active Scan Test")
    def test_all_ssid_active_scan(self):
        pass

    @name("Cross Pairs Active Scan On Same Channel Test")
    def test_active_scan_on_same_channel(self):
        pass


class CrossPairAssociationTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp_1 = context.fixture.acquire_pcp(0)
        self.pcp_2 = context.fixture.acquire_pcp(1)
        self.sta = context.fixture.acquire_sta(0)

    @name("Cross Pairs Association Disassociation Test")
    def test_associate_sta_ping(self):
        raise NotImplementedError

    @name("Cross Pairs Association Disassociation On Same Channel Test")
    def test_associate_sta_ping_on_same_channel(self):
        raise NotImplementedError

    @name("Cross Pairs Association Disassociation after DISC On Scanning Test")
    def test_disc_on_associate_sta_ping(self):
        raise NotImplementedError

    @name("Cross Pairs Association Disassociation with Different Scanning Mode Test")
    def test_diff_scan_mode_associate_sta_ping(self):
        raise NotImplementedError

    @name("Cross Pairs Association Disassociation WPA2 Test")
    def test_associate_sta_ping_wpa(self):
        raise NotImplementedError

    @name("Cross Pairs Association Disassociation WPA2 without psk Test")
    def test_associate_sta_ping_nopsk(self):
        raise NotImplementedError

    @name("Cross Pairs Association Disassociation with one pair WPA2")
    def test_associate_sta_ping_one_psk(self):
        raise NotImplementedError


class CrossPairIperf3TestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp_1 = context.fixture.acquire_pcp(0)
        self.pcp_2 = context.fixture.acquire_pcp(1)
        self.sta = context.fixture.acquire_sta(0)

    @name("Cross Pairs Iperf3 TCP Bidirectional Package Test")
    def test_tcp_iperf3(self):
        raise NotImplementedError

    @name("Cross Pairs Iperf3 UDP Bidirectional Package Test")
    def test_udp_iperf3(self):
        raise NotImplementedError

    @name("Cross Pairs Iperf3 TCP Bidirectional Package Test On Same Channel")
    def test_tcp_iperf3_on_same_channel(self):
        raise NotImplementedError

    @name("Cross Pairs Iperf3 UDP Bidirectional Package Test On Same Channel")
    def test_udp_iperf3_on_same_channel(self):
        raise NotImplementedError

    @name("Cross Pairs Iperf3 TCP Bidirectional Package with WPA2  psk Test")
    def test_tcp_iperf3_wpa(self):
        raise NotImplementedError

    @name("Cross Pairs Iperf3 UDP Bidirectional Package with WPA2  psk Test")
    def test_udp_iperf3_wpa(self):
        raise NotImplementedError
