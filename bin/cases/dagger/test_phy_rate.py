# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase


class PhyRateTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()

    def tearDown(self):
        pass

    @name("Fixed PHY Rate Bi-direction TCP Throughput Test")
    def test_phy_rate_tcp(self):
        pass

    @name("All PHY Rate Bi-direction TCP Throughput Test")
    def test_all_phy_rate_tcp(self):
        pass

    @name("Ch3 All PHY Rate Bi-direction TCP Throughput Test")
    def test_all_phy_rate_tcp_ch3(self):
        pass

    @name("Fixed PHY Rate Bi-direction UDP Throughput Test")
    def test_phy_rate_udp(self):
        pass

    @name("All PHY Rate Bi-direction UDP Throughput Test")
    def test_all_phy_rate_udp(self):
        pass

    @name("Fixed PHY Rate Association and Ping Test")
    def test_phy_rate_association(self):
        pass

    @name("Attenuation Sweep Up Link Quality Test")
    def test_link_quality_sweep_up(self):
        pass

    @name("Attenuation Sweep Down Link Quality Test")
    def test_link_quality_sweep_down(self):
        pass

    @name("Signal Block Unblock Test")
    def test_link_quality_block_unblock(self):
        pass