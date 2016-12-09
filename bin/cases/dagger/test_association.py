# -*- coding: UTF-8 -*-

import logging
logger = logging.getLogger(__name__)

from ngta import TestContextManager, name

from .base import BaseDaggerTestCase


class AssociationTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()

    def tearDown(self):
        pass

    @name("Basic Association Disassociation Test")
    def test_association(self):
        pass

    @name("Basic Association Disassociation Test via iwlist and iwconfig")
    def test_association_via_iwlist_and_iwconfig(self):
        pass

    @name("Association Disassociation during Data Transmission Test")
    def test_association_data_trans(self):
        pass

    @name("Reassociation Test after IP changed")
    def test_reassociate_after_ip_changed(self):
        pass

    @name("Reassociation Test after IP changed with Discovery mode on")
    def test_reassociate_after_ip_changed_with_disc_on(self):
        pass

    @name("Reassociation test after sta power cycle")
    def test_reassociate_after_sta_powercycle(self):
        pass
