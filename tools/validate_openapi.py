#!/usr/bin/env python3

"""
This file validate that a file contains a valid OpenAPI 3.0 specification.
"""

import argparse


def main():
    args = argparse.ArgumentParser("Validate an OpenAPI 3.0 specification file")
    args.add_argument("file", help="File to validate")
    args.add_argument("--debug", help="Enable debug mode", action="store_true")

    args = args.parse_args()

    with open(args.file, "r") as f:
        data = f.read(500)

        if "openapi" not in data:

            if args.debug:
                print(f"File '{args.file}' is not a valid OpenAPI 3.0 specification")
            exit(1)

        if "3.0" not in data:
            if args.debug:
                print(f"File '{args.file}' is not a valid OpenAPI 3.0 specification")
            exit(1)


if __name__ == '__main__':
    main()
