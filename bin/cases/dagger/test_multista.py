# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase


class MultiSTAScanTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.sta_1 = context.fixture.acquire_sta(0)
        self.sta_2 = context.fixture.acquire_sta(1)
        self.pcp = context.fixture.acquire_pcp(0)

    def tearDown(self):
        pass

    @name("Multiple Stations General SSID Active Scan Test")
    def test_all_ssid_mulitsta_active_scan(self):
        pass

    @name("Multiple Stations Negative General SSID Active Scan Test")
    def test_all_ssid_multista_negative_active_scan(self):
        pass


class MultiSTAAssociationTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.sta_1 = context.fixture.acquire_sta(0)
        self.sta_2 = context.fixture.acquire_sta(1)
        self.pcp = context.fixture.acquire_pcp(0)

    def tearDown(self):
        pass

    @name("Multiple Stations Basic Association Disassociation Test")
    def test_multista_associate_sta_ping(self):
        pass

    @name("Multiple Stations One by One Association Disassociation Test")
    def test_multista_associate_1by1_sta_ping(self):
        pass

    @name("Multiple Stations One Association Disassociation during The Other One Ping Test")
    def test_all_ssid_mulitpcp_association_disassociation(self):
        pass


class MultiSTAIperf3TestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.sta_1 = context.fixture.acquire_sta(0)
        self.sta_2 = context.fixture.acquire_sta(1)
        self.pcp = context.fixture.acquire_pcp(0)

    def tearDown(self):
        pass

    @name("Multiple Stations Iperf3 TCP Package Test")
    def test_multista_iperf3_tcp(self):
        pass

    @name("Multiple Stations Iperf3 UDP Package Test")
    def test_multista_iperf3_udp(self):
        pass

    @name("Multiple Stations Iperf3 TCP Package Bi-direction Test")
    def test_multista_bidirect_iperf3_tcp(self):
        pass

    @name("Multiple Stations Iperf3 UDP Package Bi-direction Test")
    def test_multista_bidirect_iperf3_udp(self):
        pass

    @name("Multiple Stations Concurrent Bidirection TCP Transmission between STAs")
    def test_multista_bidirection_tcp_between_stas(self):
        pass

    @name("Multiple Stations Concurrent UDP Transmission from STA1 to PCP and PCP to STA2")
    def test_multista_udp_sta1_to_pcp_and_pcp_to_sta2(self):
        pass

    @name("Multiple Stations Concurrent UDP Transmission from PCP to STA1 and STA1 to STA2")
    def test_multista_udp_pcp_to_sta1_and_sta1_to_sta2(self):
        pass


class MultiSTAPingTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.sta_1 = context.fixture.acquire_sta(0)
        self.sta_2 = context.fixture.acquire_sta(1)
        self.pcp = context.fixture.acquire_pcp(0)

    def tearDown(self):
        pass

    @name("Multiple Stations Side Ping Test")
    def test_multista_sta_ping(self):
        pass

    @name("Multiple Stations PCP Side Ping Test")
    def test_multista_pcp_ping(self):
        pass

    @name("Multiple Stations Side and PCP Side Bi-direction Ping Test")
    def test_multista_both_ping(self):
        pass

    @name("Multiple Stations Concurrent Ping from STA1 to PCP and PCP to STA2")
    def test_multista_sta1_ping_pcp_and_pcp_ping_sta2(self):
        pass

    @name("Multiple Stations Concurrent Ping from PCP to STA1 and STA1 to STA2")
    def test_multista_pcp_ping_sta1_and_sta1_ping_sta2(self):
        pass

    @name("Multiple Stations Concurrent Bidirection Ping in STA1 STA2 PCP")
    def test_multista_bidirection_ping_in_sta1_sta2_pcp(self):
        pass
