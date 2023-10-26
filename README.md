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

## Example usage

### Basic usage of the action is as follows:

```yaml
name: 42Crunch API Security Audit

on:
  workflow_dispatch:
  push:
    branches:
      - main

jobs:
  run_42c_audit:
    name: 42Crunch API Security Audit
    runs-on: ubuntu-latest
    steps:
      - name: checkout repo
        uses: actions/checkout@v3

      - name: 42crunch-static-api-testing
        uses: 42crunch/api-security-audit-action-freemium@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Specify the API files to be checked

```yaml
name: 42Crunch API Security Audit

on:
  workflow_dispatch:
  push:
    branches:
      - main

jobs:
  run_42c_audit:
    name: 42Crunch API Security Audit
    runs-on: ubuntu-latest
    steps:
      - name: checkout repo
        uses: actions/checkout@v3

      - name: 42crunch-static-api-testing
        uses: 42crunch/api-security-audit-action-freemium@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openapi_file: 'openapi.json'
```

## Inputs

Inputs for the action are defined in the `with` section of the action step. The following inputs are supported:

| Name           | Description                                                       | Required  |     | Default |
|----------------|-------------------------------------------------------------------|-----------|:----|---------|
| `github_token` | GitHub token used to create the Security / Code Scanning Alerts   | Yes       |     |         |
| `openapi_file` | Name of the OpenAPI file to be checked                            | No        |     |         |
