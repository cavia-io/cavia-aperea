# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
import common

from ngta import TestProgram
from fixture import TestFixtureFactory


def main():
    print("sys.argv: %s" % sys.argv)
    print("sys.path: %s" % sys.path)

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--xml', action='store', required=True)
    parser.add_argument('--failfast', action='store_true', default=False)
    args = parser.parse_args()

    output = os.path.join(common.LOG_DIR, time.strftime("%Y-%m-%d_%H-%M-%S"))
    program = TestProgram(args.xml, output, TestFixtureFactory)
    program.run()

if __name__ == "__main__":
    main()
