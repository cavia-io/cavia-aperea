# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase

def ping_with_latest_cycle(self):
    resp = self._test_sta_scan(self.sta)
    self._test_sta_connect(self.sta, resp[0])
    self._test_ping(self.sta,self.pcp_1.interface_addr ,self.parameters.duration)
    self._test_sta_disconnect(self.sta)
    resp = self._test_sta_scan(self.sta)
    print "11111111111 resp %s"%resp
    self._test_sta_connect(self.sta,resp[1])
    self._test_ping(self.sta,self.pcp_2.interface_addr ,self.parameters.duration)

class MultiPCPScanTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp_1 = context.fixture.acquire_pcp(0)
        self.pcp_2 = context.fixture.acquire_pcp(1)
        self.sta = context.fixture.acquire_sta(0)
        self._test_sta_disconnect(self.sta)


    @name("Different channel Multiple Pcps scan Test")
    def test_diff_channel_mulitpcp_scan(self):
        if self.index == 1:
            self._test_sta_disconnect(self.sta)
            self.pcp_2.hostapd({"channel": 3, "ssid": "simg_ssid_ch3"})
        self._test_sta_scan(self.sta)
        if self.index == self.repeat:
            ping_with_latest_cycle(self)

    def tearDown(self):
        pass
    @name("The same channel with different SSID Multiple Pcps scan Test")
    def test_diff_ssid_mulitpcp_scan(self):
        if self.index == 1:
            self.pcp_2.hostapd({"ssid": "simg_ssid2"})
        self._test_sta_scan(self.sta)
        if self.repeat == self.index:
           ping_with_latest_cycle(self)

class MultiPCPAssociationTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp_1 = context.fixture.acquire_pcp(0)
        self.pcp_2 = context.fixture.acquire_pcp(1)
        self.sta= context.fixture.acquire_sta(0)
        self._test_sta_disconnect(self.sta)

    def tearDown(self):
        pass

    @name("Multiple Pcps association disassociation Test")
    def test_all_ssid_mulitpcp_association_disassociation(self):
        pcp_1_addr = self.pcp_1.interface_addr
        duration = self.parameters.duration
        pcp_2_addr = self.pcp_2.interface_addr
        if self.index == 1:
            self.pcp_2.hostapd({"channel": 3, "ssid": "simg_ssid_ch3"})
        resp = self._test_sta_scan(self.sta)
        self._test_sta_connect(self.sta,resp[0])
        self._test_ping(self.sta,pcp_1_addr,duration)
        self._test_sta_disconnect(self.sta)
        resp = self._test_sta_scan(self.sta)
        self._test_sta_connect(self.sta,resp[1])
        self._test_ping(self.sta,pcp_2_addr,duration)
        if self.index == self.repeat:
            self._test_sta_disconnect(self.sta)
            ping_with_latest_cycle(self)




