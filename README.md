# GitHub Action: 42Crunch REST API Static Security Testing (Freemium version)

The REST API Static Security Testing action locates REST API contracts that follow the OpenAPI Specification (OAS, formerly known as Swagger) and runs thorough security checks on them. Both OAS v2 and v3.0.x are supported, in both JSON and YAML format.

This Github action is working in a freemium mode: organizations can run 25 audits per month per repository, with a maximum of three repositories per organization.

You can use this action in the following scenarios:
- Add an automatic static API security testing (SAST) task to your CI/CD workflows.
- Perform these checks on pull request reviews and/or code merges.
- Flag the located issues in GitHub's Security / Code Scanning Alerts.

## Discover APIs in your repositories

By default, this action will:

1. Look for any `.json` and `.yaml` or ``.yml` files in the repository.
2. Pick the files that use OpenAPI (a.k.a Swagger ) 2.0 or 3.0x schemas.
3. Perform security audit on each OpenAPI definition.

## Action inputs

### `upload-to-code-scanning` (GitHub Actions only)

Upload the audit results in SARIF format to [Github Code Scanning](https://docs.github.com/en/github/finding-security-vulnerabilities-and-errors-in-your-code/about-code-scanning).  Note that the workflow must have specific permissions for this step to be successful. This assumes you have Github Advanced security enabled.
Default is `false`.

```YAML
...
jobs:
  run_42c_audit:
    permissions:
      contents: read # for actions/checkout to fetch code
      security-events: write # for results upload to Github Code Scanning
...
```

### `enforce-sqg`

If set to `true`, the task returns a failure when security quality gates (SQG) criteria have failed.
If set to `false`, the action reports SQG failures scenarios without enforcing them, giving a grace period to development teams before breaking builds.

Default is `false`.  

### `log-level`

Sets the level of details in the action logs, one of: `FATAL`, `ERROR`, `WARN`, `INFO`, `DEBUG`. 
Default is `INFO`.

### `data-enrich`

Enrichs the OpenAPI file leveraging 42Crunch default data dictionary. For each property with a standard format (such as uuid or date-time), patterns and constraints are added to the OpenAPI file before it is audited.

Default is ` false`.

### `sarif-report`

Converts the audit raw JSON format to SARIF and saves the results into a specified file.
If not present, the SARIF report is not generated.

### `export-as-pdf`

Exports a summary of the audit reports as PDF.

If not present, the PDF report is not generated.

## Examples

### Single step example

A typical new step in an existing workflow would look like this:

```yaml
- name: 42crunch-static-api-testing
        uses: 42Crunch/api-security-audit-action-freemium@v1
        with:
        	upload-to-code-scanning: true
        	enforce-sqg: false
          sarif-report: 42Crunch_AuditReport_${{ github.run_id }}.SARIF
          export-as-pdf: audit-report-${{ github.run_id }}.pdf
          log-level: info
```

### Full workflow example

A typical workflow which checks the contents of the repository, runs Security Audit on each of the OpenAPI files found in the project and saves the SARIF file as an artifact would look like this:

```yaml
name: "42Crunch API Security Audit"

on: 
  pull_request:
    # The branches below must be a subset of the branches above
    branches: [ main ]

jobs:
  run_42c_audit:
    permissions:
      contents: read # for actions/checkout to fetch code
      security-events: write # for results upload to Github Code Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repo
        uses: actions/checkout@v3
      - name: Audit API definition for security issues
        uses: 42Crunch/api-security-audit-action-freemium@v1
        with:
          # Upload results to Github Code Scanning
          # Set to false if you don't have Github Advanced Security.
          upload-to-code-scanning: true
          log-level: info
          sarif-report: 42Crunch_AuditReport_${{ github.run_id }}.SARIF
      - name: save-audit-report
        if: always()        
        uses: actions/upload-artifact@v3
        with:
          name: 42Crunch_AuditReport_${{ github.run_id }}
          path: 42Crunch_AuditReport_${{ github.run_id }}.SARIF
          if-no-files-found: error
```
