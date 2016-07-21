# -*- coding: utf-8 -*-

import os
import sys
import logging
logger = logging.getLogger(__name__)

BIN_DIR = sys.path[0]
ROOT_DIR = os.path.dirname(BIN_DIR)
CASE_DIR = os.path.join(ROOT_DIR, "cases")
LOG_DIR = os.path.join(ROOT_DIR, "logs")
CFG_DIR = os.path.join(ROOT_DIR, "conf")
LIB_DIR = os.path.join(ROOT_DIR, "lib")
sys.path.append(LIB_DIR)
