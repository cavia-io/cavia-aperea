# -*- coding: UTF-8 -*-
import time
from ngta import TestContextManager, name
from .base import BaseDaggerTestCase

import logging
logger = logging.getLogger(__name__)


def setUpModule():
    pcp, sta = TestContextManager.current_context().fixture.acquire_pair()
    pcp.hostapd({"wpa": 2, "wpa_passphrase": 12345678, "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "GCMP"})


def tearDownModule():
    pcp, sta = TestContextManager.current_context().fixture.acquire_pair()
    pcp.hostapd()


def _get_wpa_network_id(self, sta):
    res = self._str_compare("\d+", sta.wpa_add_network())
    self.assertTrue(res, msg="Get network id succeed!")
    network_id = res.group()
    return network_id


def _make_wpa_connected(self, sta, pcp):
    sta_interface = sta.interface_name
    pcp_ssid = pcp.info()[2]
    pcp_psk = self.parameters.psk
    print "111111111" + pcp_psk

    network_id = _get_wpa_network_id(self, sta)

    self.assertTrue(self._str_compare("OK", sta.wpa_set_network_ssid(pcp_ssid, network_id)), msg=
                    "set network %s for %s should be OK with ssid %s " % (network_id, sta_interface, pcp_ssid))

    self.assertTrue(self._str_compare("OK", sta.wpa_set_network_psk(pcp_psk, network_id)), msg=
                    "set wpa psk %s for network %s should be OK" % (pcp_psk, network_id))

    self.assertTrue(self._str_compare("OK", sta.wpa_set_network_key("WPA-PSK", network_id)), msg=
                    "set wpa key roll %s for network %s should be OK" % ("WPA-PSK", network_id))

    self.assertTrue(self._str_compare("OK", sta.wpa_set_network_rsn(network_id)), msg=
                    "set network RSN for network %s should be OK" % network_id)

    self.assertTrue(self._str_compare("OK", sta.wpa_set_network_pairwise_cypher(network_id)), msg=
                    "set wpa pairwise cypher to network %s should be OK" % network_id)

    self.assertTrue(self._str_compare("OK", sta.wpa_set_network_group_cypher(network_id)), msg=
                    "set wpa group cypher to network %s should be OK" % network_id)

    sta.wpa_connect(network_id)
    if sta.rx_sector_sweep:
        time.sleep(60)
    else:
        time.sleep(10)
    self.assertTrue(self._str_compare("COMPLETED", sta.wap_stat()), msg=
                    "connect with wpa supplicant should be COMPLETED")


class WPAConnectTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp, self.sta = context.fixture.acquire_pair()

    def tearDown(self):
        pass

    @name("WPA Supplicant STA Reconfiguration Test with wpa_supplicant")
    def test_wpa_reconfig_wpasupplicant(self):
        pcp_ip = self.pcp.interface_addr
        duration = self.parameters.duration

        self.assertTrue(self._str_compare("Successfully initialized wpa_supplicant", self.sta.wpa_config()), msg=
                        "Init WPA Supplicant should init succeed")
        if self.index == self.repeat:
            _make_wpa_connected(self, self.sta, self.pcp)
            self._test_ping(self.sta, pcp_ip, duration)

    @name("WPA Supplicant STA Reconfiguration Test with wpa_cli")
    def test_wpa_reconfig_wpacli(self):
        pcp_ip = self.pcp.interface_addr
        duration = self.parameters.duration

        if self.index == 1:
            self.assertTrue(self._str_compare("Successfully initialized wpa_supplicant", self.sta.wpa_config()), msg=
                            "Init WPA Supplicant should init succeed")

        self.assertTrue(self._str_compare("OK", self.sta.wpa_reconfig()), msg=
                        "Init WPA Supplicant should init succeed")

        if self.index == self.repeat:
            _make_wpa_connected(self, self.sta, self.pcp)
            self._test_ping(self.sta, pcp_ip, duration)

    @name("Multiple Network Add Test")
    def test_wpa_multi_addnw(self):
        sta_interface = self.sta.interface_name
        pcp_ssid = self.pcp.info()[2]

        if self.index == 1:
            self.assertTrue(self._str_compare("Successfully initialized wpa_supplicant", self.sta.wpa_config()), msg=
                            "Init WPA Supplicant should init succeed")

        network_id = _get_wpa_network_id(self, self.sta)
        self.assertEqual(network_id, str(self.index-1), msg="Network ID should be correct")

        self.assertTrue(self._str_compare("OK", self.sta.wpa_set_network_ssid(pcp_ssid, network_id)), msg=
                        "set network %s for %s should be OK with ssid %s " % (network_id, sta_interface, pcp_ssid))

        network_list = self.sta.wpa_list_network()
        self.assertIn(network_id, network_list, msg=
                      "Network ID %s should in the Network_list %s" % (network_id, network_list))

        #self.assertEqual(pcp_ssid, network_list[network_id]["ssid"], msg=
              #           "ssid is correct for network ID %s" % network_id)
       # "network id / ssid / bssid / flags
	#simg_ssid	any	[DISABLED]"

    @name("Multiple Disabled Network Remove Test")
    def test_wpa_multi_rmnw(self):
        pass

    @name("Mixed Enabled Disabled Networks Select One by One Test")
    def test_wpa_nw_enable_select_nokey(self):
        pass

    @name("WPA Supplicant Connect with WPA-PSK Key Test")
    def test_wpa_connect_psk_sta_ping(self):
        pass

    @name("WPA Supplicant Connect without Key Test")
    def test_wpaconnect_nokey_sta_ping(self):
        pass


class WPAIperf3TestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()

    def tearDown(self):
        pass

    @name("WPA2 Security Single Direction TCP Test")
    def test_wpa_ping_tcp(self):
        pass

    @name("WPA2 Security Single Direction UDP Test")
    def test_wpa_ping_udp(self):
        pass

    @name("WPA2 Security Bidrection TCP Test")
    def test_wpa_ping_bidirection_tcp(self):
        pass

    @name("WPA2 Security Bidrection UDP Test")
    def test_wpa_ping_bidirection_udp(self):
        pass


class WPAMultiSTATestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()
        self.pcp1, self.sta1 = context.fixture.acquire_pair()
        self.sta2=context.fixture.acquire_sta(1)

    def tearDown(self):
        pass

    @name("Multiple Stations Assoc Disassoc Test with Security On for Multi STAs without Key")
    def test_multista_asso_disasso_security_without_key(self):
        pass

    @name("Multiple Stations Assoc Disassoc Test with Security On for Multi STAs with PSK Key")
    def test_multista_asso_disasso_security_with_psk(self):
        pass

    @name("Multiple Stations TCP Packets Test with Security On for Multi STAs with PSK Key")
    def test_multista_tcp_security_with_psk(self):
        pass

    @name("Multiple Stations UDP Packets Test with Security On for Multi STAs with PSK Key")
    def test_multista_udp_security_with_psk(self):
        pass


class WPAPingTestCase(BaseDaggerTestCase):
    def setUp(self):
        context = TestContextManager.current_context()

    def tearDown(self):
        pass

    @name("WPA2 Security Station Side Ping Test")
    def test_wpa_ping_sta(self):
        pass

    @name("WPA2 Security PCP Side Ping Test")
    def test_wpa_ping_pcp(self):
        pass

    @name("WPA2 Security Both Sides Ping Test")
    def test_wpa_ping_both(self):
        pass
