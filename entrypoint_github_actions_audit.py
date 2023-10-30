#!/usr/bin/env python3

import os
import sys
import platform
import subprocess

from glob import glob
from dataclasses import dataclass

AUDIT_CONFIG = """
audit:
  branches:
    main:
      fail_on:
        score:
          data: 70
          security: 30
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

    def __post_init__(self):
        if self.github_repository:
            self.github_repository = self.github_repository.split("/")[-1]

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
            "--org", f"{running_config.github_organization}/{running_config.github_repository}",
            "--user", running_config.github_repository_owner,
            "--output-format", "json",
            "-o", audit_report,
            full_path
        ]

        print("Command:", flush=True)
        print(" ".join(audit_command), flush=True)

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

            upload_to_code_scanning_results = subprocess.run(upload_to_code_scanning_command)

            if upload_to_code_scanning_results.returncode != 0:
                print(f"[!] Unable to upload SARIF report to GitHub code scanning")
                continue


def setup_audit_configuration(file_path: str = '.42c/conf.yaml'):
    base_path = os.path.dirname(file_path)

    os.makedirs(base_path, exist_ok=True)

    with open(file_path, 'w') as source_config:
        source_config.write(AUDIT_CONFIG)
        source_config.flush()


def get_running_configuration() -> RunningConfiguration:
    def _to_bool(value: str) -> bool:
        print("Raw bool value:", value)
        if value is None:
            return False
        elif value.lower() == "true":
            return True
        else:
            return False

    data_enrich = _to_bool(os.getenv("INPUT_DATA_ENRICH", "false"))
    enforce_sqgl = _to_bool(os.getenv("INPUT_ENFORCE_SQGL", "false"))
    upload_to_code_scanning = _to_bool(os.getenv("INPUT_UPLOAD_TO_CODE_SCANNING", "false"))

    log_level = os.getenv("INPUT_LOG_LEVEL", "INFO")
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
        sarif_report=os.getenv("INPUT_SARIF_REPORT", None),
        export_as_pdf=os.getenv("INPUT_EXPORT_AS_PDF", None),
        upload_to_code_scanning=upload_to_code_scanning,

        github_token=os.getenv("GITHUB_TOKEN", None),
        github_repository=os.getenv("GITHUB_REPOSITORY", None),
        github_organization=os.getenv("GITHUB_REPOSITORY_OWNER", None),
        github_repository_owner=os.getenv("GITHUB_REPOSITORY_OWNER", None),
        github_ref=os.getenv("GITHUB_REF", None),
        github_sha=os.getenv("GITHUB_SHA", None)
    )


def main():

    print("Starting 42Crunch API Security Audit")
    print("===================================")

    current_dir = os.getcwd()
    binaries = get_binaries_paths()
    running_config = get_running_configuration()

    print("Environment variables:")
    print(running_config)

    scan_audit_config = os.path.join(current_dir, '.42c/conf.yaml')

    # Write audit configuration to temporary file
    setup_audit_configuration(scan_audit_config)

    # Run discovery
    discovery_run(running_config, current_dir, binaries)


# Main script execution
if __name__ == "__main__":
    main()
