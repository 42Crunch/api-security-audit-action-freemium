# GitHub Action: 42Crunch REST API Static Security Testing

The REST API Static Security Testing action locates REST API contracts that follow the OpenAPI Specification (OAS, formerly known as Swagger) and runs thorough security checks on them. Both OAS v2 and v3.0.x are supported, in both JSON and YAML format.

You can use this action in the following scenarios:

- Add automatic static application security testing (SAST) task to your CI/CD workflows.
- Perform these checks on pull request reviews and/or code merges.
- Flag the located issues in GitHub's Security / Code Scanning Alerts.

## Discover APIs in your repositories

By default, this action will:

1. Look for any `.json` and `.yaml` files in the repository.
2. Pick the files that use OpenAPI schema.
3. Perform security audit on the OpenAPI definitions.

This way, you can locate any new or changed API contracts in the repository.

All discovered APIs are uploaded to an API collection in 42Crunch Platform. The action uses the environment variables `GITHUB_REPOSITORY` and `GITHUB_REF` to name the repository and the branch/tag/PR name from where the API collection originated from. During the subsequent action runs, the APIs in the collection are kept in sync with the changes in your repository.

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

If set to `true`, forces to complete execution successfully even if the failures conditions (SQG criteria) you have set are met.

This parameter can be useful if you want to detect SQG failures scenarios without enforcing them (i.e. give a grace period to development teams before you start breaking builds).

Default is `false`.

Implementation: get the SQG status from audit report - 

### `log-level`

Sets the level of details in the logs, one of: `FATAL`, `ERROR`, `WARN`, `INFO`, `DEBUG`. 
Default is `INFO`.

### `data-enrich`

Enrichs the OpenAPI file leveraging the default data dictionary. For each property with a standard format (such as uuid or date-time), patterns and constraints will be added to the OpenAPI file before it is audited. 
Default is ` true`.

### `sarif-report`

Converts the audit raw JSON format to SARIF and save the results into a specified file. 
If not present, the SARIF report is not generated.

> **Special case**: when an OpenAPI has no issues (clean report), we must still export a SARIF file, similar to [this one](../01.documentation/z.Assets/7-Security_Audit/cleanreport.sarif) so that Microsoft can distinguish between clean reports and no reports (i.e. the task has not run).
>
> Important details is that report must contain this empty result array : `"results": []`

### `export-as-pdf`

Exports the audit report as PDF, based on the already existing format documented [[here](https://github.com/42c-presales/automation-scripts/tree/main/audit-reports-as-html)] .

If not present, the PDF report is not generated.

## Example usage

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

A typical workflow which checks the contents of the repository, runs Security Audit on each of the OpenAPI files found in the project and saves the execution file as artifact would look like this:

```yaml
name: "pr-workflow"

# follow standard Code Scanning triggers
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
      - name: checkout repo
        uses: actions/checkout@v3
      - name: get PR number
        id: getprnumber
        run: |
          pr_id=$(jq --raw-output .pull_request.number "$GITHUB_EVENT_PATH")
          echo "PR_ID=$pr_id" >> $GITHUB_OUTPUT
      - name: 42crunch-static-api-testing
        uses: 42Crunch/api-security-audit-action-freemium@v1
        with:
          # Upload results to Github code scanning
          upload-to-code-scanning: true
          log-level: info
          sarif-report: 42Crunch_AuditReport_${{ github.run_id }}.SARIF
          enforce-sqg: true
      - name: save-audit-report
        if: always()        
        uses: actions/upload-artifact@v3
        with:
          name: 42Crunch_AuditReport_${{ github.run_id }}
          path: 42Crunch_AuditReport_${{ github.run_id }}.SARIF
          if-no-files-found: error
```
