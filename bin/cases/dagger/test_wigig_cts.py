# -*- coding: UTF-8 -*-

import os
import re
import subprocess
import collections
from ngta import TestContextManager, name, parametrize
from ngta.util import etree
from simg.util.text import TextEditor

from .base import BaseDaggerTestCase

import logging
logger = logging.getLogger(__name__)

CTS_MAPPING = collections.OrderedDict([
    ("4.1 STAUT Out of Box (OOB)", "_60G-4.1"),
    ("4.2.1 Discovery Subtest 1 test bed STA beacon is received by the STAUT", "_60G-4.2.1"),
    ("4.2.2 Discovery Subtest 2 STAUT beacon is received by the Test bed STA", "_60G-4.2.2"),
    ("4.3.1.1 DTI Operation with DMG Beacon frame", "_60G-4.3.1.1"),
    ("4.3.1.2 DTI Operation with Announce frame", "_60G-4.3.1.2"),
    ("4.3.1.3 CBAP Operation", "_60G-4.3.1.3"),
    ("4.3.2 Association", "_60G-4.3.2"),
    ("4.3.3 Ability to test the reception and optional transmission of the A-MSDU frame", "_60G-4.3.3"),
    ("4.3.4 Ability to test the transmission and reception of the A-MPDU frame", "_60G-4.3.4"),
    ("4.4 STAUT power save without wakeup schedule", "_60G-4.4"),
    ("4.5.1 STAUT BRP frame exchange", "_60G-4.5.1"),
    ("4.5.2 STAUT SLS frame exchange", "_60G-4.5.2"),
    ("4.5.3 STAUT Beam Tracking", "_60G-4.5.3"),
    ("4.6.1 STA WPA2-Personal Initial Ping Interoperability Test", "_60G-4.6.1"),
    ("4.6.3 Multicast with WPA2-Personal Mode", "_60G-4.6.3"),
    ("4.6.4 WPA2 Negative Test Case Non-Association with a PCP not using WPA2", "_60G-4.6.4"),
    ("4.6.5 A-MPDU Aggregation when the STA is the Recipient with and without WPA2-Personal", "_60G-4.6.5"),

    ("5.1.1 CBAP Operation", "_60G-5.1.1"),
    ("5.1.2 Ability to test the reception and transmission of Basic A-MSDU frame", "_60G-5.1.2"),
    ("5.1.3 Ability to test the transmission and reception of the A-MPDU frame", "_60G-5.1.3"),
    ("5.2.1 PCP WPA2 Personal Initial Ping Interoperability Test", "_60G-5.2.1"),
    ("5.2.2 PCP & STA Association and Throughput using WPA2-Personal GCMP", "_60G-5.2.2"),
    ("5.2.3 WPA2 Negative Test Case No Association with WPA2-Personal Configured PCP", "_60G-5.2.3"),
    ("5.2.4 A-MPDU Aggregation when the PCP is the Recipient with and without WPA2-Personal", "_60G-5.2.4"),
    ("5.3 PCPUT BRP frame exchange", "_60G-5.3")
])


@parametrize("cts_tool_path", default=r"C:\dagger\Sigma_UCC-Windows_60GHz_8.0-60GHz-PF12-01")
@parametrize("cts_test_title", choice=CTS_MAPPING.keys(), iteration=CTS_MAPPING.keys())
class WiGigCTSTestCase(BaseDaggerTestCase):
    @classmethod
    def setUpClass(cls):
        context = TestContextManager.current_context()
        pcp, sta = context.acquire_pair()
        pcp.cts_control_agent.start()
        sta.cts_control_agent.start()

    @classmethod
    def tearDownClass(cls):
        context = TestContextManager.current_context()
        pcp, sta = context.acquire_pair()
        pcp.cts_control_agent.stop()
        sta.cts_control_agent.stop()

    def setUp(self):
        path = os.path.join(self.cts_root, "cmds", "Sigma-60G", "DUTInfo.txt")
        with TextEditor(path) as editor:
            if re.search("_60G-4.(.*)", self.parameters.title):
                editor.replace("#60G_DUTTYPE!STAUT!", "60G_DUTTYPE!STAUT!")
                editor.replace("60G_DUTTYPE!PCPUT!", "#60G_DUTTYPE!PCPUT!")
            elif re.search("_60G-5.(.*)", self.parameters.title):
                editor.replace("60G_DUTTYPE!STAUT!", "#60G_DUTTYPE!STAUT!")
                editor.replace("#60G_DUTTYPE!PCPUT!", "60G_DUTTYPE!PCPUT!")

    @name("%(cts_test_title)s")
    def test_cts(self):
        bin_dir = os.path.join(self.cts_tool_path, "bin")
        cmd = "wfa_ucc.exe 60GHz %s" % self.parameters.cts_test_title
        logger.debug("CTS command: %s", cmd)
        process = subprocess.Popen(cmd, cwd=bin_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout = process.communicate()[0]
        code = process.returncode
        logger.debug("Sigma UCC code: %s, resp: %s", code, stdout)

        log_dir = os.path.join(bin_dir, "log")
        log_sub_dirs = os.listdir(log_dir)
        log_sub_dirs.sort(
            key=lambda n: os.path.getmtime(os.path.join(log_dir, n)) if os.path.isdir(log_dir, n) else 0
        )

        cur_dir = os.path.join(log_dir, log_sub_dirs[-1])

        result_xml = None
        for filename in os.listdir(cur_dir):
            if filename.lower().endswith(".xml"):
                break

        self.assertIsNone(result_xml, msg="Result xml file should exists.")
        tree = etree.parse(os.path.join(cur_dir, result_xml))
        status = tree.findtext("TestCaseResult", "UNKNOWN")
        reason = tree.findall("LogItem/CommandGroup/Command")[-1].text
        logger.debug("status: %s, reason: %s", status, reason)
        self.assertEqual(status, "PASS", msg="Result status should be PASS, the reason is %s" % reason)
