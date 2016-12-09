# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase


class DriverInstallTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp, self.sta = context.fixture.acquire_pair()
        self.make_connected(self.sta)

    def tearDown(self):
        pass

    @name("Driver Station Side Install Uninstall Test")
    def test_sta_install(self):
        pass

    @name("Driver PCP Side Install Uninstall Test")
    def test_pcp_install(self):
        pass

    @name("Driver Multi DUT Install Unistall Test")
    def test_both_ping(self):
        pass
