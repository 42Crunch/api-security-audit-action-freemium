#!/usr/bin/env python3

"""
Audit Freemium Action Tester:

This script is used to test the GitHub Action for audit-freemium action locally.
"""
import os
import random
import string
import argparse
import contextlib

import xliic_sdk.vendors
import xliic_sdk.vendors.github.code_scanning


@contextlib.contextmanager
def monkey_patched():
    """ Temporarily monkey patches an object. """

    pre_patched_value = xliic_sdk.vendors.upload_sarif
    xliic_sdk.vendors.upload_sarif = lambda *args, **kwargs: None

    yield

    xliic_sdk.vendors.upload_sarif = pre_patched_value


def random_string(length: int = 10, prefix: str = "42c_test") -> str:
    """
    Generate a random string of given length

    :param length: Length of the string to generate
    :param prefix: Prefix of the string to generate

    :return: Random string
    """
    text = "".join(random.choices(string.ascii_letters + string.digits, k=length))

    return f"{prefix}_{text}"


def main():
    arg_parser = argparse.ArgumentParser(description='Audit Freemium Action Tester')

    # Map inputs to args
    arg_parser.add_argument('--input-openapi-path', type=str, help='Openapi path', default=None, required=True)
    arg_parser.add_argument('--input-log-level', type=str, help='Log level', default='debug', choices=['debug', 'info', 'warn', 'error', 'critical'])
    arg_parser.add_argument('--input-data-enrich', help='Data enrich', default=False, action='store_true')
    arg_parser.add_argument('--input-enforce-sqg', help='Enforce sqg', default=False, action='store_true')
    arg_parser.add_argument('--input-upload-to-code-scanning', help='Upload to code scanning', default=True, action='store_true')
    arg_parser.add_argument('--input-sarif-report', type=str, help='Sarif report', default=None)
    arg_parser.add_argument('--input-export-as-pdf', type=str, help='Export as pdf', default=None)
    arg_parser.add_argument('--input-token', type=str, help='Token', default=lambda: random_string(40))
    arg_parser.add_argument('--input-audit-reports-dir', type=str, help='Audit reports dir', default=None)

    # Map envs to args
    arg_parser.add_argument('--github-repository-owner', type=str, help='Github repository owner', default=lambda: random_string(10))
    arg_parser.add_argument(
        '--github-repository',
        type=str,
        help='Github repository',
        default=lambda: f"{random_string(10)}/{random_string(10)}"
    )
    arg_parser.add_argument('--github-ref', type=str, help='Github ref', default='refs/heads/main')
    arg_parser.add_argument('--github-sha', type=str, help='Github sha', default=lambda: random_string(40))

    args = arg_parser.parse_args()

    # Set environment variables
    for arg in vars(args):
        if arg.startswith('input_'):
            env_name = arg.upper().replace('INPUT_', '').replace('_', '-')
            env_name = f"INPUT_{env_name}"
            env_value = getattr(args, arg)

        elif arg.startswith('github_'):
            env_name = arg.upper()
            env_value = getattr(args, arg)

        else:
            env_name = None
            env_value = None

        if env_name and env_value:
            if hasattr(env_value, '__call__'):
                os.environ[env_name] = env_value()
            else:
                os.environ[env_name] = str(env_value)

    #
    # Set Dev Environment Variables
    #
    os.environ['42C_DEV_TESTING'] = 'true'

    # Load GitHub action Python script file
    with monkey_patched():
        __import__('entrypoint_github_actions_audit').main()


if __name__ == '__main__':
    main()
