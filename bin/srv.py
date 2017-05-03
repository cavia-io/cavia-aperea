# -*- coding: utf-8 -*-

import os
import common
from ngta.agent import TestAgent

import logging
logger = logging.getLogger(__name__)


def main():
    agent = TestAgent(
        os.path.join(common.CFG_DIR, "srvconf.xml"),
        os.path.join(common.CFG_DIR, "resconf.xml"),
    )
    agent.enable_logging(common.LOG_DIR)
    agent.startup()

if __name__ == '__main__':
    main()
