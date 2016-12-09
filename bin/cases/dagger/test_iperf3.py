# -*- coding: UTF-8 -*-

from ngta import TestContextManager, name, parametrize
from .base import BaseDaggerTestCase
import re
import logging
logger = logging.getLogger(__name__)


@parametrize("interval", type=int, default=1)
class Iperf3TestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp, self.sta = context.fixture.acquire_pair()
        self.make_connected(self.sta)

    def tearDown(self):
        pass



    @name("Iperf3 TCP Package Test")
    def test_iperf3_tcp(self):
        with self.pcp.iperf3.start_as_server():
            resp = self.sta.iperf3.measure(self.pcp.interface_addr, self.parameters.interval, self.parameters.duration)
        self._check_iperf3_measure_result(resp, self.parameters.duration)

    @name("Iperf3 UDP Package Test")
    def test_iperf3_udp(self):
        with self.pcp.iperf3.start_as_server():
            resp = self.sta.iperf3.measure(self.pcp.interface_addr,
                                           self.parameters.interval,
                                           self.parameters.duration,
                                           udp=True)
        self._check_iperf3_measure_result(resp, self.parameters.duration)

    @name("Iperf3 TCP Package Bi-direction Test")
    def test_bidirect_iperf3_tcp(self):
        with self.pcp.iperf3.start_as_server(), self.sta.iperf3.start_as_server():
            resp1 = self.sta.iperf3.measure(self.pcp.interface_addr, self.parameters.interval, self.parameters.duration)
            resp2 = self.pcp.iperf3.measure(self.sta.interface_addr, self.parameters.interval, self.parameters.duration)
        self._check_iperf3_measure_result(resp1, self.parameters.duration)
        self._check_iperf3_measure_result(resp2, self.parameters.duration)

    @name("Iperf3 UDP Package Bi-direction Test")
    def test_bidirect_iperf3_udp(self):
        with self.pcp.iperf3.start_as_server(), self.sta.iperf3.start_as_server():
            resp1 = self.sta.iperf3.measure(self.pcp.interface_addr,
                                            self.parameters.interval,
                                            self.parameters.duration,
                                            udp=True)
            resp2 = self.pcp.iperf3.measure(self.sta.interface_addr,
                                            self.parameters.interval,
                                            self.parameters.duration,
                                            udp=True)
        self._check_iperf3_measure_result(resp1, self.parameters.duration)
        self._check_iperf3_measure_result(resp2, self.parameters.duration)

    @name("Iperf3 TCP Package Bi-direction Different Pksize Test")
    def test_bidirect_iperf3_tcp_pksize(self):
        raise NotImplementedError

    @name("Iperf3 UDP Package Bi-direction Different Pksize Test")
    def test_bidirect_iperf3_udp_pksize(self):
        raise NotImplementedError
