#!/usr/bin/env python3

import os
import sys
import json
import platform
import subprocess

from glob import glob
from dataclasses import dataclass
from typing import Tuple

AUDIT_CONFIG = """
audit:
  branches:
    main:
      fail_on:
        score:
          data: 70
          security: 30
"""

CLEAN_SARIF_REPORT = """
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "templateanalyzer",
          "organization": "Microsoft",
          "fullName": "Template Analyzer",
          "version": "0.5.2",
          "informationUri": "https://github.com/Azure/template-analyzer",
          "properties": {
            "RawName": "templateanalyzer"
          }
        }
      },
      "invocations": [
        {
          "startTimeUtc": "2023-10-19T21:57:06.696Z",
          "endTimeUtc": "2023-10-19T21:57:11.166Z",
          "toolExecutionNotifications": [
            {
              "message": {
                "text": "Discovered 1 template-parameter pairs to analyze"
              },
              "level": "note"
            }
          ],
          "executionSuccessful": true
        }
      ],
      "versionControlProvenance": [
        {
          "repositoryUri": "https://dev.azure.com/AnnotationsRuntimeE2E/AnnotationsRuntimeE2E/_git/AnnotationsRuntimeE2E-KoreaCentral",
          "revisionId": "7462c01d45e26176afe4e6543fda84dd0881ea20",
          "branch": "HEAD",
          "properties": {
            "RepositoryRoot": "D:\\a\\1\\s"
          }
        }
      ],
      "originalUriBaseIds": {
        "ROOTPATH": {
          "uri": "file:///D:/a/1/s"
        }
      },
      "results": [],
      "automationDetails": {
        "id": "AnnotationsRuntimeE2E-KoreaCentral"
      },
      "columnKind": "utf16CodeUnits",
      "policies": [
        {
          "name": "AzureDevOps",
          "version": "1.0.0"
        }
      ],
      "properties": {
        "toolInfoId": "templateanalyzer>>0>>202310192157"
      }
    }
  ]
}
"""


@dataclass
class Binaries:
    audit: str
    convert_to_sarif: str
    upload_to_github_code_scanning: str


@dataclass
class RunningConfiguration:
    #
    # Configurable parameters
    #
    log_level: str = "INFO"
    data_enrich: bool = False
    enforce_sqgl: bool = False
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
    enforce_sqgl: {self.enforce_sqgl}
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


class InvalidOpenAPIFile(Exception):
    ...


def get_binaries_paths() -> Binaries:
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
                print("[!] Unable to detect operating system from GitHub action environment variables")
                sys.exit(1)

    def _check_binary_exists(ast_binary):
        if not os.path.isfile(ast_binary):
            print(f"[!] Unable to find binary at {ast_binary}")
            sys.exit(1)

    if os.getenv("LOCAL_DEVELOPMENT"):
        binaries = Binaries(
            audit=_get_audit_binary(True),
            convert_to_sarif="/usr/local/bin/convert-to-sarif",
            upload_to_github_code_scanning="/usr/local/bin/upload-sarif"
        )
    else:
        binaries = Binaries(
            audit=_get_audit_binary(False),
            convert_to_sarif="/usr/local/bin/convert-to-sarif",
            upload_to_github_code_scanning="/usr/local/bin/upload-sarif"
        )

    # Check that binaries exist
    _check_binary_exists(binaries.audit)
    _check_binary_exists(binaries.convert_to_sarif)
    _check_binary_exists(binaries.upload_to_github_code_scanning)

    return binaries


def validate_openapi(openapi_file: str):
    with open(openapi_file, "r") as f:
        data = f.read(500)

        if "openapi" not in data:
            raise InvalidOpenAPIFile(f"File '{openapi_file}' is not a valid OpenAPI 3.0 specification")

        if "3.0" not in data:
            raise InvalidOpenAPIFile(f"File '{openapi_file}' is not a valid OpenAPI 3.0 specification")


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


def discovery_run(running_config: RunningConfiguration, base_dir: str, binaries: Binaries):
    json_files = glob('**/*.json', recursive=True)
    yaml_files = glob('**/*.yaml', recursive=True) + glob('**/*.yml', recursive=True)

    for file_path in json_files + yaml_files:
        full_path = os.path.abspath(os.path.join(base_dir, file_path))

        #
        # Valida OpenAPI file
        #
        try:
            validate_openapi(full_path)
        except InvalidOpenAPIFile as e:
            print(f"[!] {full_path} is not a valid OpenAPI file")
            continue

        #
        # Run audit
        #
        audit_report = f"{full_path}.report"

        audit_command = [
            binaries.audit,
            "audit",
            "run",
            "--enrich=false",
            "--org", running_config.github_repository,
            "--user", running_config.github_repository_owner,
            "--output-format", "json",
            "-v", running_config.log_level,
            "-o", audit_report,
            full_path
        ]

        print(f"    > Running audit on {full_path}")
        audit_command_result = subprocess.run(audit_command)
        if audit_command_result.returncode != 0:
            print(f"[!] Unable to run audit on {full_path}")
            continue

        # If report doesn't exists, skip
        if not os.path.isfile(audit_report):
            print(f"[!] Unable to find audit report at {audit_report}")
            continue

        #
        # Convert to SARIF
        #
        print(f"    > Converting {audit_report} to SARIF format")

        if running_config.sarif_report:
            sarif_report = running_config.sarif_report
        else:
            sarif_report = f"{full_path}.sarif"

        sarif_converter_command = [
            binaries.convert_to_sarif,
            "-a", full_path,
            "-i", audit_report,
            "-o", sarif_report
        ]

        conversion_result = subprocess.run(sarif_converter_command)

        if conversion_result.returncode != 0:
            print(f"[!] Unable to convert {audit_report} to SARIF format")
            continue

        #
        # Upload to GitHub scanning code
        #
        if running_config.upload_to_code_scanning:
            print(f"    > Uploading SARIF report to GitHub code scanning")

            upload_to_code_scanning_command = [
                binaries.upload_to_github_code_scanning,
                '--github-token', running_config.github_token,
                '--github-repository', running_config.github_repository,
                '--github-sha', running_config.github_sha,
                '--ref', running_config.github_ref,
                sarif_report
            ]

            upload_to_code_scanning_results = subprocess.run(upload_to_code_scanning_command, capture_output=True)

            if upload_to_code_scanning_results.returncode != 0:
                print(f"[!] Unable to upload SARIF report to GitHub code scanning: {upload_to_code_scanning_results.stdout.decode()}")
                continue

        #
        # Check if security issues were found
        #

        ## If enforce_sqgl is set to true, We'll success although security issues were found
        if running_config.enforce_sqgl:
            continue

        else:

            ## If enforce_sqgl is set to false, we'll fail if security issues were found
            found, issues = is_security_issues_found(sarif_report)
            if found:
                print(f"[!] Security issues found in '{full_path}'. '{issues}' issues found")
                sys.exit(1)

        #
        # Export as PDF
        #
        if running_config.export_as_pdf:
            print(f"    > Exporting {sarif_report} to PDF")


def setup_audit_configuration(file_path: str = '.42c/conf.yaml'):
    base_path = os.path.dirname(file_path)

    os.makedirs(base_path, exist_ok=True)

    with open(file_path, 'w') as source_config:
        source_config.write(AUDIT_CONFIG)
        source_config.flush()


def get_running_configuration() -> RunningConfiguration:
    def _to_bool(value: str) -> bool:
        if value is None:
            return False
        elif value.lower() == "true":
            return True
        else:
            return False

    def _none_or_empty(value: str) -> str:
        if value is None:
            return None
        elif value.strip() == "":
            return None
        else:
            return value

    data_enrich = _to_bool(os.getenv("INPUT_DATA-ENRICH", "false"))
    enforce_sqgl = _to_bool(os.getenv("INPUT_ENFORCE-SQGL", "false"))
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
        enforce_sqgl=enforce_sqgl,
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


def main():
    current_dir = os.getcwd()
    binaries = get_binaries_paths()
    running_config = get_running_configuration()

    scan_audit_config = os.path.join(current_dir, '.42c/conf.yaml')

    # Write audit configuration to temporary file
    setup_audit_configuration(scan_audit_config)

    # Run discovery
    discovery_run(running_config, current_dir, binaries)


# Main script execution
if __name__ == "__main__":
    main()
