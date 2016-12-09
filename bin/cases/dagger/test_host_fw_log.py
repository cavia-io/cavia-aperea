# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase


class HostFirmwareLogTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp, self.sta = context.fixture.acquire_pair()

    @name("Host FW log Test")
    def test_host_fw_log(self):
        self.sta.sendcmd("rm -f /tmp/host_fw.log")
        self.pcp.sendcmd("rm -f /tmp/host_fw.log")

        self.sta.send_debug_fs_cmd("/tmp/host_fw.log", "fw_logfile")
        self.pcp.send_debug_fs_cmd("/tmp/host_fw.log", "fw_logfile")

        pcp_addr = self.pcp.interface_addr
        duration = self.parameters.duration
        self._test_sta_reconnect(self.sta)
        self._test_ping(self.sta, pcp_addr, duration)

        raise NotImplementedError
