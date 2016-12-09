# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase


class ScanTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp, self.sta = context.fixture.acquire_pair()
        self.make_connected(self.sta)

    def tearDown(self):
        pass

    @name("General SSID Active Scan Test")
    def test_all_ssid_active_scan(self):
        pass

    @name("Specified SSID Active Scan Test")
    def test_spec_ssid_active_scan(self):
        pass

    @name("Negative General SSID Active Scan Test")
    def test_all_ssid_negative_active_scan(self):
        pass

    @name("Negative Specified SSID Passive Scan Test")
    def test_spec_ssid_negative_active_scan(self):
        raise NotImplementedError("Not Ready")

    @name("General SSID Active Scan with Discovery Mode On Test")
    def test_all_ssid_active_scan_disc_on(self):
        pass

    @name("Specified SSID Active Scan with Discovery Mode On Test")
    def test_spec_ssid_active_scan_disc_on(self):
        raise NotImplementedError("Not Ready")

    @name("Negative General SSID Active Scan with Discovery Mode On Test")
    def test_all_ssid_negative_active_scan_disc_on(self):
        raise NotImplementedError("Not Ready")

    @name("Negative Specified SSID Active Scan with Discovery Mode On Test")
    def test_spec_ssid_negative_active_scan_disc_on(self):
        raise NotImplementedError("Not Ready")

    @name("Negative Scan Test Between Two Active Scanning STA")
    def test_negative_scan_between_2active_scan(self):
        pass

    @name("Negative Scan Test Between Active Scanning STA and Active Scanning DISC On STA")
    def test_negative_scan_between_active_scan_and_active_scan_disc_on(self):
        pass

    @name("General SSID Active Scan after Scan Failed Old")
    def test_general_scan_after_scan_failed_old(self):
        pass

    @name("General SSID Active Scan after Scan Failed")
    def test_general_scan_after_scan_failed(self):
        pass

    @name("General SSID Active Scan with Discovery Mode On after Scan Failed Old")
    def test_general_scan_disc_on_after_scan_failed_old(self):
        pass

    @name("General SSID Active Scan with Discovery Mode On after Scan Failed")
    def test_general_scan_disc_on_after_scan_failed(self):
        pass

    @name("General SSID Active Scan after IP Changed")
    def test_general_scan_after_ip_changed(self):
        pass

    @name("General SSID Active Scan with Discovery Mode On after IP Changed")
    def test_general_scan_disc_on_after_ip_changed(self):
        pass