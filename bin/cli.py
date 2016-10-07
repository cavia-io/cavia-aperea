# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
import common

from ngta import TestProgram, SimpleTestProgram
from fixture import TestFixtureFactory


def main():
    print("sys.argv: %s" % sys.argv)
    print("sys.path: %s" % sys.path)

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--xml', action='store', required=True)
    parser.add_argument('--failfast', action='store_true', default=False)
    parser.add_argument('--couping', action='store_true', default=False)
    args = parser.parse_args()

    output = os.path.join(common.LOG_DIR, time.strftime("%Y-%m-%d_%H-%M-%S"))
    if args.couping:
        program = TestProgram(args.xml, args.failfast)
    else:
        program = SimpleTestProgram(args.xml, output, args.failfast, TestFixtureFactory)
    program.run()

if __name__ == "__main__":
    main()
