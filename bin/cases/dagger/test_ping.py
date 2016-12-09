# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase


class PingTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp, self.sta = context.fixture.acquire_pair()
        self.make_connected(self.sta)

    def tearDown(self):
        pass

    @name("Station Side Ping Test")
    def test_sta_ping(self):
        pcp_addr = self.pcp.interface_addr
        duration = self.parameters.duration
        self._test_ping(self.sta, pcp_addr, duration)

    @name("PCP Side Ping Test")
    def test_pcp_ping(self):
        sta_addr = self.sta.interface_addr
        duration = self.parameters.duration
        self._test_ping(self.pcp, sta_addr, duration)

    @name("Station Side and PCP Side Bi-direction Ping Test")
    @parametrize("packet_size", type=int, default=1500)
    def test_both_ping(self):
        pcp_addr = self.pcp.interface_addr
        sta_addr = self.sta.interface_addr
        duration = self.parameters.duration
        packet_size = self.parameters.packet_size

        pcp_result = self.pcp.ping(sta_addr, duration, packet_size, block=False)
        sta_result = self.sta.ping(pcp_addr, duration, packet_size, block=False)

        pcp_resp = pcp_result.fetch()[1]
        self._check_ping(sta_addr, duration, pcp_resp)

        sta_resp = sta_result.fetch()[1]
        self._check_ping(pcp_addr, duration, sta_resp)
