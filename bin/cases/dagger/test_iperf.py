# -*- coding: UTF-8 -*-

from ngta import TestContextManager, name, parametrize
from .base import BaseDaggerTestCase
import logging
logger = logging.getLogger(__name__)
import re

@parametrize("interval", type=int, default=1)
class IperfTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp, self.sta = context.fixture.acquire_pair()
        self.make_connected(self.sta)

    def tearDown(self):
        pass

   # def _check_measure_result(self, server_resp, client_resp):


    @name("Iperf TCP Package Test")
    def test_iperf_tcp(self):
        with self.pcp.iperf.start_as_server() as server:
            client_resp = self.sta.iperf.measure(self.pcp.hostname, self.parameters.interval, self.parameters.duration)
        self._check_iperf_measure_result(client_resp, self.parameters.duration)

    @name("Iperf UDP Package Test")
    def test_iperf_udp(self):
        with self.pcp.iperf.start_as_server(udp=True) as server:
            client_resp = self.sta.iperf.measure(self.pcp.hostname,
                                                 self.parameters.interval,
                                                 self.parameters.duration,
                                                 udp=True)
        self._check_iperf_measure_result(client_resp, self.parameters.duration)

    @name("Iperf TCP Package Bi-direction Test")
    def test_bidirect_iperf_tcp(self):
        with self.pcp.iperf.start_as_server() as pcp_server, self.sta.iperf.start_as_server() as sta_server:
            sta_client_resp = self.sta.iperf.measure(self.pcp.hostname,
                                                     self.parameters.interval,
                                                     self.parameters.duration,
                                                     dualtest=True)
            pcp_client_resp = self.pcp.iperf.measure(self.sta.hostname,
                                                     self.parameters.interval,
                                                     self.parameters.duration,
                                                     dualtest=True)
        self._check_iperf_measure_result(sta_client_resp, self.parameters.duration)
        self._check_iperf_measure_result(pcp_client_resp, self.parameters.duration)
        #raise NotImplementedError

    @name("Iperf UDP Package Bi-direction Test")
    def test_bidirect_iperf_udp(self):
        with self.pcp.iperf.start_as_server(udp=True) as pcp_server, \
                self.sta.iperf.start_as_server(udp=True) as sta_server:
            sta_client_resp = self.sta.iperf.measure(self.pcp.hostname,
                                                     self.parameters.interval,
                                                     self.parameters.duration,
                                                     udp=True,
                                                     dualtest=True)
            pcp_client_resp = self.pcp.iperf.measure(self.sta.hostname,
                                                     self.parameters.interval,
                                                     self.parameters.duration,
                                                     udp=True,
                                                     dualtest=True)
        self._check_iperf_measure_result(sta_client_resp, self.parameters.duration)
        self._check_iperf_measure_result(pcp_client_resp, self.parameters.duration)
