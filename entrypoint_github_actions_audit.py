#!/usr/bin/env python3

import os
import sys
import gzip
import json
import uuid
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
    enforce: bool = False
    log_level: str = "INFO"
    data_enrich: bool = False
    upload_to_code_scanning: bool = False

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
    log_level: {self.log_level}
    data_enrich: {self.data_enrich}
    enforce_sqgl: {self.enforce}
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

        self.github_repository = self.github_repository.split("/")[1] # trim owner from repo name

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


def execute(command: str | list, verbose: bool = False):
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

    if verbose:
        if result.stdout:
            print(result.stdout.decode())

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

    enforce = _to_bool(os.getenv("INPUT_ENFORCE-SQG", "false"))
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
        enforce=enforce,
        sarif_report=_none_or_empty(os.getenv("INPUT_SARIF-REPORT", None)),
        export_as_pdf=_none_or_empty(os.getenv("INPUT_EXPORT-AS-PDF", None)),
        upload_to_code_scanning=upload_to_code_scanning,

        github_token=os.getenv("INPUT_TOKEN", None),
        github_repository=os.getenv("GITHUB_REPOSITORY", None),
        github_organization=os.getenv("GITHUB_REPOSITORY_OWNER", None),
        github_repository_owner=os.getenv("GITHUB_REPOSITORY_OWNER", None),
        github_ref=os.getenv("GITHUB_REF", None),
        github_sha=os.getenv("GITHUB_SHA", None)
    )


def discovery_run(running_config: RunningConfiguration, base_dir: str, binaries: str):
    output_directory = os.path.join(base_dir, uuid.uuid4().hex)

    #
    # Run 42Crunch cli audit
    #
    audit_cmd = [
        "42ctl",
        "audit",
        "run",
        "local",
        "-b", binaries,
        "-i", base_dir,
        "-r", output_directory,
        "-c",  # Copy original OpenAPI file that generated report
        "--github-user", running_config.github_repository_owner,
        "--github-org", running_config.github_organization,
        "--log-level", running_config.log_level,
        "--github-repo", running_config.github_repository,
    ]

    if running_config.data_enrich:
        audit_cmd.append("--enrich")

    try:
        execute(audit_cmd, True)
    except ExecutionError as e:
        display_header("Audit command failed", str(e))
        exit(1)

    #
    # Convert to SARIF
    #
    sarif_reports = []

    for report in os.listdir(output_directory):

        # Try to locate report files
        if "audit-report" not in report:
            continue

        # Report file found
        report_path = os.path.join(output_directory, report)

        # Related OpenAPI file.
        #
        # IMPORTANT: FOR GitHub Code Scanning, the OpenAPI file must be relative to the repository root,
        # and can't start with: /github/workspace
        openapi_file = report.replace(".audit-report.json", "")

        # SARIF file name
        sarif_file = f"{os.path.splitext(os.path.basename(report_path))[0]}.sarif"

        cmd = [
            "42ctl",
            "audit",
            "report",
            "sarif",
            "convert",
            "-r", report_path,
            "-a", openapi_file,
            "-o", sarif_file
        ]

        try:
            execute(cmd)

            sarif_reports.append(sarif_file)
        except ExecutionError as e:
            display_header("Convert to SARIF command failed", str(e))
            continue

        #
        # Upload to GitHub code scanning
        #
        if running_config.upload_to_code_scanning:
            upload_sarif(
                github_token=running_config.github_token,
                github_repository=running_config.github_repository,
                github_sha=running_config.github_sha,
                ref=running_config.github_ref,
                sarif_file_path=sarif_file
            )

        if running_config.enforce:

            ## If enforce is set to false, we'll fail if security issues were found
            found, issues = is_security_issues_found(sarif_file)
            if found:
                display_header("Security issues found", f"{issues} issues found")
                sys.exit(1)

    #
    # Merge SARIF files
    #
    if running_config.sarif_report:
        cmd = [
            "42ctl",
            "audit",
            "report",
            "sarif",
            "merge",
            "-o", running_config.sarif_report,
            *sarif_reports
        ]

        try:
            execute(cmd)
        except ExecutionError as e:
            display_header("Merge SARIF files command failed", str(e))
            exit(1)


def main():
    binary = get_binary_path()
    current_dir = os.getcwd()
    running_config = get_running_configuration()

    # Run discovery
    discovery_run(running_config, current_dir, binary)


# Main script execution
if __name__ == "__main__":
    main()
