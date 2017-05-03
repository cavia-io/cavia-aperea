# -*- coding: utf-8 -*-

import argparse

import common
import logging
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest="func")

    grs_subparser = subparsers.add_parser("generate_report_from_shelve")
    grs_subparser.add_argument('--shelve', action='store', dest="shelve")

    imp_subparser = subparsers.add_parser("import_hierarchy_into_magna")
    imp_subparser.add_argument('--host', action='store', dest="server")
    imp_subparser.add_argument('--port', action='store', type=int, dest="port", default=8080)
    imp_subparser.add_argument('--module', action='store', dest="module")
    imp_subparser.add_argument('--project_id', action='store', type=int, dest="project_id")
    args = parser.parse_args()

    if args.func == "generate_report_from_shelve":
        from ngta.util import generate_report_from_shelve
        generate_report_from_shelve(args.shelve)
    elif args.func == "import_hierarchy_into_magna":
        from magna.client import RestClient
        client = RestClient("http://%s:%s/magna/api/rest/" % (args.server, args.port))
        client.export_hierarchy_to_magna(args.module, args.project_id)
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)-15s [%(levelname)-8s] - %(message)s'
    )
    main()
