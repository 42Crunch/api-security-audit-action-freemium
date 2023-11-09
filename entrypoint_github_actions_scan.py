#!/usr/bin/env python3

import os
import sys
import gzip
import json
import base64
import platform
import subprocess
import urllib.request

from typing import Tuple
from dataclasses import dataclass


class ExecutionError(Exception):
    pass


@dataclass
class RunningConfiguration:
    #
    # Configurable parameters
    #
    target_host: str
    api_definition: str
    log_level: str = "INFO"
    data_enrich: bool = False
    upload_to_code_scanning: bool = False
    api_credential: str = None

    sarif_report: str = None
    export_as_pdf: str = None

    # Internal parameters
    github_token: str = None
    github_repository: str = None
    github_organization: str = None
    github_repository_owner: str = None
    github_ref: str = None
    github_sha: str = None

    def __repr__(self):
        return f"""
RunningConfiguration:
    target_host: {self.target_host}
    log_level: {self.log_level}
    data_enrich: {self.data_enrich}
    upload_to_code_scanning: {self.upload_to_code_scanning}
    sarif_report: {self.sarif_report}
    export_as_pdf: {self.export_as_pdf}
    github_token: {self.github_token}
    github_repository: {self.github_repository}
    github_organization: {self.github_organization}
    github_repository_owner: {self.github_repository_owner}
    github_ref: {self.github_ref}
    github_sha: {self.github_sha}
    """

    def __post_init__(self):
        if self.log_level:
            self.log_level = self.log_level.lower()


def is_security_issues_found(sarif_report: str) -> Tuple[bool, int]:
    """
    Check if security issues were found in the SARIF report.

    If the SARIF report has no results, it means that no security issues were found. So, we return False. Otherwise, True
    """
    with open(sarif_report, "r") as f:
        data = json.load(f)

        try:
            issues_found = len(data["runs"][0]["results"])

            if issues_found > 0:
                return True, issues_found
            else:
                return False, -1
        except (KeyError, IndexError):
            return False, -1


def upload_sarif(github_token, github_repository, github_sha, ref, sarif_file_path):
    if not github_token:
        print("[!] Missing or empty GitHub token")
        exit(1)

    # Convert the SARIF file to base64 after gzip compression
    try:
        with open(sarif_file_path, 'rb') as f:
            zipped_sarif = base64.b64encode(gzip.compress(f.read())).decode()
    except FileNotFoundError:
        print(f"[!] File {sarif_file_path} not found")
        exit(1)

    # Extract owner and repo from the provided repository
    try:
        owner, repo = github_repository.split('/')
    except ValueError:
        print(f"[!] Invalid repository {github_repository}")
        exit(1)

    # Current directory as a URL (approximation)
    checkout_uri = f"file://{os.getcwd()}"

    # Construct the request
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/sarifs"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {
        "commit_sha": github_sha,
        "ref": ref,
        "sarif": zipped_sarif,
        "tool_name": "42Crunch REST API Static Security Testing",
        "checkout_uri": checkout_uri
    }
    req = urllib.request.Request(url, headers=headers, data=json.dumps(data).encode())

    # Send the request
    try:
        with urllib.request.urlopen(req) as response:
            response.read()
    except Exception as e:
        print(f"[!] HTTP Error: {e}", flush=True)
        exit(1)


def display_header(title: str, text: str):
    print()
    print("!" * 80)
    print(f"! {title}")
    print("!")
    print(f"{text}")
    print("!" * 80)
    print()


def execute(command: str | list):
    if type(command) is str:
        cmd = command.split(" ")
    else:
        cmd = command

    result = subprocess.run(cmd, capture_output=True)

    if result.returncode != 0:
        message = [f"Command failed with exit code {result.returncode}"]

        if result.stdout:
            message.append(f"stdout: {result.stdout.decode()}")

        if result.stderr:
            message.append(f"stderr: {result.stderr.decode()}")

        raise ExecutionError("\n".join(message))

    return result


def get_binary_path() -> str:
    def _get_audit_binary(_is_local_development: bool) -> str:

        if _is_local_development:
            return "/usr/local/bin/42c-ast-darwin-amd64"

        else:

            if platform.system() == "Windows":
                return "/usr/local/bin/42c-ast-windows-amd64.exe"
            elif platform.system() == "Darwin":
                return "/usr/local/bin/42c-ast-darwin-amd64"
            elif platform.system() == "Linux":
                return "/usr/local/bin/42c-ast-linux-amd64"
            else:
                print()
                print("[!] Unable to detect operating system from GitHub action environment variables")
                print()
                sys.exit(1)

    def _check_binary_exists(ast_binary):
        if not os.path.isfile(ast_binary):
            print()
            print(f"[!] Unable to find binary at {ast_binary}")
            print()
            sys.exit(1)

    if os.getenv("LOCAL_DEVELOPMENT"):
        binary_path = _get_audit_binary(True)
    else:
        binary_path = _get_audit_binary(False)

    # Check that binaries exist
    _check_binary_exists(binary_path)

    return binary_path


def get_running_configuration() -> RunningConfiguration:
    def _to_bool(value: str) -> bool:
        if value is None:
            return False
        elif value.lower() == "true":
            return True
        else:
            return False

    def _none_or_empty(value: str) -> str | None:
        if value is None:
            return None
        elif value.strip() == "":
            return None
        else:
            return value

    data_enrich = _to_bool(os.getenv("INPUT_DATA-ENRICH", "false"))
    upload_to_code_scanning = _to_bool(os.getenv("INPUT_UPLOAD-TO-CODE-SCANNING", "false"))

    log_level = os.getenv("INPUT_LOG-LEVEL", "INFO")
    if log_level is None:
        log_level = "INFO"
    elif log_level.upper() not in ["FAIL", "ERROR", "WARN", "INFO", "DEBUG"]:
        log_level = "INFO"
    else:
        log_level = log_level.upper()

    return RunningConfiguration(
        log_level=log_level,
        data_enrich=data_enrich,
        api_definition=os.getenv("INPUT_API-DEFINITION", None),
        sarif_report=_none_or_empty(os.getenv("INPUT_SARIF-REPORT", None)),
        export_as_pdf=_none_or_empty(os.getenv("INPUT_EXPORT-AS-PDF", None)),
        upload_to_code_scanning=upload_to_code_scanning,
        target_host=os.getenv("INPUT_TARGET-HOST", None),
        api_credential=os.getenv("INPUT_API-CREDENTIAL", None),

        github_token=os.getenv("INPUT_TOKEN", None),
        github_repository=os.getenv("GITHUB_REPOSITORY", None),
        github_organization=os.getenv("GITHUB_REPOSITORY_OWNER", None),
        github_repository_owner=os.getenv("GITHUB_REPOSITORY_OWNER", None),
        github_ref=os.getenv("GITHUB_REF", None),
        github_sha=os.getenv("GITHUB_SHA", None)
    )


def scan_run(running_config: RunningConfiguration, base_dir: str, binaries: str):

    # Create output file name for report from input file name
    openapi_file = os.path.splitext(os.path.basename(running_config.api_definition))[0]
    scan_output_report = os.path.join(base_dir, f"{openapi_file}.audit-report.json")

    # TODO: FIX THIS
    openapi_file = "vampy-openapi"
    running_config.api_definition = "vampy-openapi.json"
    scan_output_report = "vampy-openapi.scan-result.json"

    #
    # Run 42Crunch cli scan
    #
    audit_cmd = [
        "42ctl",
        "scan",
        "run",
        "local",
        "-b", binaries,
        "-i", base_dir,
        "-r", scan_output_report,
        "-c",  # Copy original OpenAPI file that generated report
        "--github-user", running_config.github_repository_owner,
        "--github-org", running_config.github_organization,
        "--log-level", running_config.log_level
    ]

    if running_config.data_enrich:
        audit_cmd.append("--enrich")

    try:
        # Binary fix pending
        # execute(audit_cmd)
        pass
    except ExecutionError as e:
        display_header("Audit command failed", str(e))
        exit(1)

    #
    # Convert to SARIF
    #

    # Related OpenAPI file.
    #
    # IMPORTANT: FOR GitHub Code Scanning, the OpenAPI file must be relative to the repository root,
    # and can't start with: /github/workspace

    if running_config.sarif_report:
        sarif_report = running_config.sarif_report
    else:
        sarif_report = os.path.join(base_dir, f"{openapi_file}.sarif")

    cmd = [
        "42ctl",
        "scan",
        "report",
        "sarif",
        "convert",
        "-r", scan_output_report,
        "-a", running_config.api_definition,
        "-o", sarif_report
    ]

    try:
        execute(cmd)
    except ExecutionError as e:
        display_header("Convert to SARIF command failed", str(e))
        return

    #
    # Upload to GitHub code scanning
    #
    if running_config.upload_to_code_scanning:
        print("#" * 80)
        print("Uploading to GitHub code scanning")
        print("#" * 80)

        upload_sarif(
            github_token=running_config.github_token,
            github_repository=running_config.github_repository,
            github_sha=running_config.github_sha,
            ref=running_config.github_ref,
            sarif_file_path=sarif_report
        )


def main():
    binary = get_binary_path()
    current_dir = os.getcwd()
    running_config = get_running_configuration()

    # Run discovery
    scan_run(running_config, current_dir, binary)


# Main script execution
if __name__ == "__main__":
    main()
