#!/usr/bin/env python3

import os
import uuid
import logging

from dataclasses import dataclass

from xliic_sdk.audit import load_metadata
from xliic_sdk.audit.report import AuditReport
from xliic_sdk.helpers import get_binary_path, execute, ExecutionError
from xliic_sdk.vendors import github_running_configuration, display_header, setup_logger, upload_sarif

logger = logging.getLogger(__name__)


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

    @classmethod
    def from_github(cls) -> "RunningConfiguration":

        config = github_running_configuration(
            inputs={
                "log-level": "str",
                "data-enrich": "bool",
                "enforce-sqg": "bool",
                "upload-to-code-scanning": "bool",
                "sarif-report": "str",
                "export-as-pdf": "str",
                "token": "str"
            },
            envs={
                "github_repository": "str",
                "github_repository_owner": "str",
                "github_ref": "str",
                "github_sha": "str",
            }
        )

        o = cls(
            log_level=config["log-level"],
            data_enrich=config["data-enrich"],
            enforce=config["enforce-sqg"],
            upload_to_code_scanning=config["upload-to-code-scanning"],
            sarif_report=config["sarif-report"],
            export_as_pdf=config["export-as-pdf"],

            github_token=config["token"],
            github_repository=config["github_repository"],
            github_organization=config["github_repository_owner"],
            github_repository_owner=config["github_repository_owner"],
            github_ref=config["github_ref"],
            github_sha=config["github_sha"]
        )

        # Ensure log level value is valid
        o.log_level = o.log_level.lower()

        if o.log_level is None:
            o.log_level = "info"
        elif o.log_level not in ["fatal", "error", "warn", "info", "debug"]:
            o.log_level = "info"

        return o

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


def discovery_run(running_config: RunningConfiguration, binaries: str):
    base_dir = os.getcwd()
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
        "--github-repo", running_config.github_repository
    ]

    # Show, only in debug, audit parameters
    logger.debug(f"Running audit with the following parameters:")
    logger.debug(f"Using GitHub user: {running_config.github_repository_owner}")
    logger.debug(f"Using GitHub org: {running_config.github_organization}")
    logger.debug(f"Using GitHub repo: {running_config.github_repository.split('/')[1]}")
    logger.debug(f"Using log level: {running_config.log_level}")
    logger.debug(f"Using '{output_directory}' as result directory")
    logger.debug(f"Using '{base_dir}' as input directory to look for OpenAPI files")

    if running_config.data_enrich:
        audit_cmd.append("--enrich")

    try:

        stdout_response, stderr_response = execute(audit_cmd, True)
    except ExecutionError as e:
        logger.error(display_header("Audit command failed", str(e)))
        exit(1)

    # TODO:
    # Audit log is a JSON-like object. We need to parse it to get the results
    # try:
    #     audit_logs: dict = json.loads(audit_response)
    # except json.JSONDecodeError as e:
    #     logger.error(display_header("Unable to parse audit logs", str(e)))
    #     exit(1)

    # Show, only in debug, audit logs

    #
    # Convert to SARIF
    #
    sarif_reports = []
    results_files = os.listdir(output_directory)

    # Show, only in debug, Found reports
    logger.debug(f"Reports are generated at: '{output_directory}'")
    logger.debug(f"Found {len(results_files)} files in '{output_directory}'")
    for report in results_files:
        logger.debug(f" - {report}")

    logger.debug(f"Converting the audit reports to SARIF")
    for report in os.listdir(output_directory):

        # Try to locate report files
        if "audit-report" not in report or "metadata" in report:
            continue

        # Report file found
        report_path = os.path.join(output_directory, report)

        logger.debug(f"Converting '{report_path}' to SARIF")

        # Load metadata
        metadata = load_metadata(report_path)

        #
        # IMPORTANT: FOR GitHub Code Scanning, the OpenAPI file must be relative to the repository root,
        # and can't start with: /github/workspace
        #
        # So, we need to remove the /github/workspace prefix from the OpenAPI file
        #
        openapi_file = metadata.openapi_file.replace("/github/workspace/", "")

        # User log info
        report_obj = AuditReport.from_file(report_path)
        logger.info(f"Audited '{openapi_file}'")
        logger.info(f"Issues Found: {report_obj.total_issues}")
        logger.info(f"Global score: {report_obj.score}")

        logger.debug(f"Using '{openapi_file}' as input OpenAPI file for the SARIF generator")

        # SARIF file name
        sarif_file = f"{report_path}.sarif"
        logger.debug(f"Using '{sarif_file}' as output SARIF file")

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
            logger.error(display_header("Convert to SARIF command failed", str(e)))
            continue

        # TODO: Enforce security issues
        # logger.debug(
        #     f"Enforce security issues is {'enabled' if running_config.enforce else 'disabled'}"
        # )
        # if running_config.enforce:
        #     logger.debug(f"Checking for security issues in '{sarif_file}'")
        #
        #     ## If enforce is set to false, we'll fail if security issues were found
        #     found, issues = is_security_issues_found(sarif_file)
        #
        #     logger.debug(f"Security issues found: {found}")
        #
        #     if found:
        #         logger.error(display_header("Security issues found", f"{issues} issues found"))
        #         sys.exit(1)

    #
    # Merge SARIF files
    #
    logger.debug(
        f"Merging SARIF files is {'enabled' if running_config.sarif_report else 'disabled'}"
    )
    if running_config.sarif_report:
        sarif_report_name = running_config.sarif_report
    else:
        sarif_report_name = os.path.join(base_dir, "audit.sarif")

    logger.debug(f"Merging SARIF files into '{sarif_report_name}'")

    for s in sarif_reports:
        logger.debug(f" - {s}")

    cmd = [
        "42ctl",
        "audit",
        "report",
        "sarif",
        "merge",
        "-o", sarif_report_name,
        *sarif_reports
    ]

    try:
        execute(cmd)
    except ExecutionError as e:
        logger.error(display_header("Merge SARIF files command failed", str(e)))
        exit(1)

    #
    # Upload to GitHub code scanning
    #
    logger.debug(
        f"Uploading SARIF file to GitHub code scanning is {'enabled' if running_config.upload_to_code_scanning else 'disabled'}"
    )
    if running_config.upload_to_code_scanning:
        logger.debug(f"Uploading '{sarif_report_name}' to GitHub code scanning")
        upload_sarif(
            github_token=running_config.github_token,
            github_repository=running_config.github_repository,
            github_sha=running_config.github_sha,
            ref=running_config.github_ref,
            sarif_file_path=sarif_report_name
        )

    logger.info("Successfully uploaded results to Code Scanning")


def main():
    try:
        binary_path = get_binary_path()
    except ExecutionError as e:
        logger.error(display_header("Unable to get 42c-ast binary", str(e)))
        exit(1)

    try:
        running_config = RunningConfiguration.from_github()
    except ValueError as e:
        logger.error(display_header("Invalid configuration", str(e)))
        exit(1)

    # -------------------------------------------------------------------------
    # Setup logging
    # -------------------------------------------------------------------------
    setup_logger(logger, running_config.log_level)

    # -------------------------------------------------------------------------
    # Run discovery
    # -------------------------------------------------------------------------

    # Run discovery
    discovery_run(running_config, binary_path)


# Main script execution
if __name__ == "__main__":
    main()
