#!/usr/bin/env python3

import os
import uuid
import logging

from dataclasses import dataclass

from xliic_sdk.audit import load_metadata
from xliic_sdk.helpers import ExecutionError
from xliic_sdk.audit.report import AuditReport
from xliic_cli.audit.reports.pdf.convert_to_pdf import create_html_report, RunningConfig as PDFRunningConfig
from xliic_cli.audit.reports.sarif.merge_sarif.app import merge_sarif_files
from xliic_cli.audit.reports.sarif.convert_to_sarif.app import convert_to_sarif
from xliic_cli.audit.run.local_run import run_audit_locally, AuditExecutionConfig
from xliic_sdk.vendors import github_running_configuration, display_header, upload_sarif

logger = logging.getLogger("42crunch-audit")


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
    audit_reports_dir: str = None
    export_as_pdf: str = None

    # Internal parameters
    github_token: str = None
    github_repository: str = None
    github_organization: str = None
    github_repository_owner: str = None
    github_ref: str = None
    github_sha: str = None

    input_openapi_path: str = None

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
                "token": "str",
                "audit-reports-dir": "str",
                "openapi-path": "str",
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
            input_openapi_path=config["openapi-path"],
            data_enrich=config["data-enrich"],
            enforce=config["enforce-sqg"],
            upload_to_code_scanning=config["upload-to-code-scanning"],
            sarif_report=config["sarif-report"],
            audit_reports_dir=config["audit-reports-dir"],
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
    audit_reports_dir: {self.audit_reports_dir}
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

        if not self.input_openapi_path:
            self.input_openapi_path = os.getcwd()


def discovery_run(running_config: RunningConfiguration):

    if running_config.audit_reports_dir:
        output_directory = running_config.audit_reports_dir

    else:
        output_directory = os.path.join(running_config.input_openapi_path, uuid.uuid4().hex)

    # Show, only in debug, audit parameters
    logger.debug(f"Running audit with the following parameters:")
    logger.debug(f"Using GitHub user: {running_config.github_repository_owner}")
    logger.debug(f"Using GitHub org: {running_config.github_organization}")
    logger.debug(f"Using GitHub repo: {running_config.github_repository.split('/')[1]}")
    logger.debug(f"Using log level: {running_config.log_level}")
    logger.debug(f"Using '{output_directory}' as result directory")
    logger.debug(f"Using '{running_config.input_openapi_path}' as input directory to look for OpenAPI files")

    execution_config = AuditExecutionConfig(
        github_repo=running_config.github_repository,
        enrich=running_config.data_enrich,
        github_org=running_config.github_organization,
        github_user=running_config.github_repository_owner,
        log_level=running_config.log_level,
        enrich_mode=running_config.data_enrich

    )

    sqgs = {}
    quotas = {}
    raw_audit_reports = []

    try:
        for quota_msg, report_path, sqg, in run_audit_locally(
                open_api_file_or_path=running_config.input_openapi_path,
                output_file_or_dir=output_directory,
                include_metadata=True,
                audit_config=execution_config
        ):
            file_name = os.path.basename(report_path)

            sqgs[file_name] = report_path
            quotas[file_name] = quota_msg
            raw_audit_reports.append(report_path)
    except Exception as e:
        logger.error(f"[!] {str(e)}")
        exit(1)

    results_files = os.listdir(output_directory)

    #
    # Show, only in debug, Found reports
    #
    logger.debug(f"Analyzed {len(results_files)} files")
    logger.debug(f"Reports are generated at: '{output_directory}'")
    logger.debug(f"Found {len(results_files)} files in '{output_directory}'")
    for report in results_files:
        logger.debug(f" - {report}")
    logger.debug(f"Converting the audit reports to SARIF")

    #
    # Convert to SARIF
    #
    sarif_reports = []
    audit_reports = []
    for report in raw_audit_reports:

        # Try to locate report files
        if "audit-report" not in report or "metadata" in report:
            continue

        # Report file found
        report_path = os.path.join(output_directory, report)

        # Add report to list
        audit_reports.append(report_path)

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

        #
        # Show audit results
        #
        # We se print instead of logger.info because we want to show this information in the GitHub Action output

        ## Global score
        print(f"Audited '{openapi_file}'")
        print(f"Global score: {report_obj.score} (security {report_obj.security_score}/30, data {report_obj.data_score}/70)")
        print(f"Issues Found: {report_obj.total_issues}")

        ## Display sqg score
        if running_config.enforce:
            print()
            print("Checking security quality gates")

            sqg = sqgs[report]

            if sqg:
                print(f'    The API failed the security quality gate "Default Audit SQG"')

                for rule in sqg.sqg_blocking_rules:
                    print(f"    - {rule}")

        ## Display Quotas
        print(f"\n{quotas[report]}\n")

        ## Display separator
        print("------------------------------------------------------------------------")

        logger.debug(f"Using '{openapi_file}' as input OpenAPI file for the SARIF generator")

        # SARIF file name
        sarif_file = f"{report_path}.sarif"
        logger.debug(f"Using '{sarif_file}' as output SARIF file")

        try:
            convert_to_sarif(openapi_file, report_path, sarif_file)
        except ExecutionError as e:
            print(f"[!] {str(e)}")
            exit(1)

        sarif_reports.append(sarif_file)

    #
    # Merge SARIF files
    #
    logger.debug(
        f"Merging SARIF files is {'enabled' if running_config.sarif_report else 'disabled'}"
    )
    if running_config.sarif_report:
        sarif_report_name = running_config.sarif_report
    else:
        sarif_report_name = os.path.join(running_config.input_openapi_path, "audit.sarif")

    logger.debug(f"Merging SARIF files into '{sarif_report_name}'")

    for s in sarif_reports:
        logger.debug(f" - {s}")

    merge_sarif_files(sarif_reports, sarif_report_name)

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

        logger.debug("Successfully uploaded results to Code Scanning")

    #
    # Make PDF report
    #
    if running_config.export_as_pdf:
        logger.debug(f"Generating PDF report '{running_config.export_as_pdf}'")

        config = PDFRunningConfig(
            collection_id=None,
            api_id=None,
            report_files=audit_reports,
            output_file=running_config.export_as_pdf,
            abort_on_error=False,
            client_email=None,
            severity="low",
            source="GitHub Actions"
        )

        create_html_report(config, audit_reports)

    #
    # Check if pipeline should fail
    #
    ## If any SQG has to fail, exit with error
    for sqg in sqgs.values():
        if sqg.has_to_fail(running_config.enforce):
            print(f"The API failed the security quality gate 'Default Audit SQG'")
            exit(1)


def main():

    try:
        running_config = RunningConfiguration.from_github()
    except ValueError as e:
        logger.error(display_header("Invalid configuration", str(e)))
        exit(1)

    # -------------------------------------------------------------------------
    # Setup logging
    # -------------------------------------------------------------------------

    ## Logger handlers for console
    console = logging.StreamHandler()

    if running_config.log_level == "debug":
        logger.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    else:
        logger.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(console)

    # -------------------------------------------------------------------------
    # Run discovery
    # -------------------------------------------------------------------------

    # Run discovery
    discovery_run(running_config)


# Main script execution
if __name__ == "__main__":
    main()
