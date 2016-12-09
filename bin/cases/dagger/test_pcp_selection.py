# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name, parametrize

from .base import BaseDaggerTestCase


class PCPSelectionTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()

    def tearDown(self):
        pass

    @name("PCP Selected by Greater MAC and Greater MAC Device Is Beacon Source Test")
    def test_pcp_selection_greater_mac_bsource(self):
        pass

    @name("PCP Selected by Greater MAC and Greater MAC Device Is Beacon Source Scanning Test")
    def test_pcp_selection_greater_mac_bsource_scan(self):
        pass

    @name("PCP Selected by Greater MAC and Greater MAC Device Is Beacon Source Association/Disassociation Test")
    def test_pcp_selection_greater_mac_bsource_assoc(self):
        pass
