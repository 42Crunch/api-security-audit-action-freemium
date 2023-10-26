#!/usr/bin/env sh


if [ -n "$LOCAL_DEVELOPMENT" ]; then
  UPLOAD_SARIF_BINARY="tools/upload_sarif.py"
  CONVERT_TO_SARIF_BINARY="tools/convert_to_sarif.py"
  VALIDATE_OPENAPI_BINARY="tools/validate_openapi.py"

else
  UPLOAD_SARIF_BINARY="upload-sarif"
  CONVERT_TO_SARIF_BINARY="convert-to-sarif"
fi

LOG_LEVEL=${LOG_LEVEL:-"info"}
EXECUTION_REPORT_NAME=${EXECUTION_REPORT_NAME:-"execution_report.json"}
UPLOAD_TO_SCANNING_CODE=${UPLOAD_TO_SCANNING_CODE:-"false"}

#
# Find .json and .yaml files in the repository
#
OPENAPI_FILE="openapi.yaml"
REPORT_FILE="audit-report.json.report"

 # Convert o SARIF format
echo "    > Converting $REPORT_FILE to SARIF format"
$CONVERT_TO_SARIF_BINARY -a "$OPENAPI_FILE" -i "$REPORT_FILE" -o "$REPORT_FILE.sarif"

# If the previous execution was successful then stop the loop
if [ $? -eq 0 ]; then

  # Scanning and generating sarif success. Now we need to upload the report to scanning code if the is set
  if [ -n "$UPLOAD_TO_SCANNING_CODE" ]; then

    # Upload report to GitHub scanning code
    echo "    > Uploading $REPORT_FILE.sarif to GitHub scanning code"
    $UPLOAD_SARIF_BINARY --github-token "$GITHUB_TOKEN" --github-repository "$GITHUB_REPOSITORY" --github-sha "$GITHUB_SHA" --ref "$GITHUB_REF" "$REPORT_FILE.sarif"
  fi
fi
