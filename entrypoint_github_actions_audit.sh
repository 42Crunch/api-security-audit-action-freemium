#!/usr/bin/env sh

#
# Detect operating system from GitHub action environment variables
#

# If Windows
if [ -n "${RUNNER_OS}" ] && [ "${RUNNER_OS}" = "Windows" ]; then
  AST_BINARY="/usr/local/bin/42c-ast-windows-amd64.exe"

# If macOS
elif [ -n "${RUNNER_OS}" ] && [ "${RUNNER_OS}" = "macOS" ]; then
  AST_BINARY="/usr/local/bin/42c-ast-darwin-amd64"

# If Linux
elif [ -n "${RUNNER_OS}" ] && [ "${RUNNER_OS}" = "Linux" ]; then
  AST_BINARY="/usr/local/bin/42c-ast-linux-amd64"

else
  echo "[!] Unable to detect operating system from GitHub action environment variables"
  exit 1
fi


if [ -n "$LOCAL_DEVELOPMENT" ]; then
  AST_BINARY="binaries/42c-ast-darwin-amd64"
  UPLOAD_SARIF_BINARY="tools/upload_sarif.py"
  CONVERT_TO_SARIF_BINARY="tools/convert_to_sarif.py"
  VALIDATE_OPENAPI_BINARY="tools/validate_openapi.py"

else
  UPLOAD_SARIF_BINARY="upload-sarif"
  CONVERT_TO_SARIF_BINARY="convert-to-sarif"
  VALIDATE_OPENAPI_BINARY="validate-openapi"
fi

# Check that binary exists
if [ ! -f "$AST_BINARY" ]; then
  echo "[!] Unable to find binary at $AST_BINARY"
  exit 1
fi

LOG_LEVEL=${LOG_LEVEL:-"info"}
EXECUTION_REPORT_NAME=${EXECUTION_REPORT_NAME:-"execution_report.json"}
UPLOAD_TO_SCANNING_CODE=${UPLOAD_TO_SCANNING_CODE:-"false"}

#
# Find .json and .yaml files in the repository
#

# Find all .json files in the repository
JSON_FILES=$(find . -type f -name "*.json")

# Find all .yaml files in the repository
YAML_FILES=$(find . -type f -name "*.yaml|*.yml")

for FILE in $JSON_FILES $YAML_FILES; do

  #
  # Check if file is a valid OpenAPI file
  #
  if ! $VALIDATE_OPENAPI_BINARY "$FILE"; then
    echo "[!] $FILE is not a valid OpenAPI file"
    continue
  fi

  AUDIT_REPORT="$FILE.report"

  echo "[*] Analyzing '$FILE'"

  # Run 42Crunch Audit
  echo "    > Running 42Crunch Audit"
  $AST_BINARY audit run --enrich=false --org "$GITHUB_REPOSITORY" --user "$GITHUB_REPOSITORY_OWNER" --output-format json -o "$AUDIT_REPORT" "$FILE" > /dev/null 2>&1

  # Convert o SARIF format
  echo "    > Converting $AUDIT_REPORT to SARIF format"
  $CONVERT_TO_SARIF_BINARY -a "$FILE" -i "$AUDIT_REPORT" -o "$AUDIT_REPORT.sarif"

  # If the previous execution was successful then stop the loop
  if [ $? -eq 0 ]; then

    # Scanning and generating sarif success. Now we need to upload the report to scanning code if the is set
    if [ -n "$UPLOAD_TO_SCANNING_CODE" ]; then

      # Upload report to GitHub scanning code
      echo "    > Uploading $AUDIT_REPORT.sarif to GitHub scanning code"
      $UPLOAD_SARIF_BINARY --github-token "$GITHUB_TOKEN" --github-repository "$GITHUB_REPOSITORY" --github-sha "$GITHUB_SHA" --ref "$GITHUB_REF" "$AUDIT_REPORT.sarif"
    fi
  fi

done