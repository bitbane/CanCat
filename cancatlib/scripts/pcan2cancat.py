# Command line entry point for pcan2cancat

import sys
import argparse
from cancatlib.utils import convert


def main():
    argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
            prog='pcan2cancat',
            description='Utility to convert a PCAN-Explorer log into a CanCat session')
    parser.add_argument('log', help='input pcan log')
    parser.add_argument('output', help='output cancat session')
    args = parser.parse_args(argv)

    convert.pcan2cancat(args.log, args.output)
