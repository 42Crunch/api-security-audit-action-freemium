#!/usr/bin/env python3

import json
import uuid
import argparse

from typing import Dict


def resolve_criticality(criticality: int) -> str:
    try:
        criticality = int(criticality)
    except ValueError:
        return "warning"

    levels = {
        0: "Informational",
        1: "Low",
        2: "Medium",
        3: "Warning",
        4: "High",
        5: "Critical"
    }

    return levels.get(criticality, "warning")


def get_rules(report: dict) -> Dict[str, dict]:
    """
    Get rules from 42Crunch audit report.

    Return example:

    {
        "api1-broken-object-level-authorization": {
            "name": "api1-broken-object-level-authorization",
            "slug": "api1-broken-object-level-authorization",
            "id": "d1b0e0a0-0e1a-5b1a-9a0e-1a0e1a0e1a0e",
            "description": "Broken Object Level Authorization",
            "criticality": 0,
            "type": "security",
        },

        ...
    }
    """

    rules_map = {}
    total_rules = (
        ("warning", _get_security(report)),
        ("security", _get_security(report))
    )

    for rule_type, rules in total_rules:

        for rule_name, rule_data in rules.items():
            rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, rule_name))

            rules_map[rule_name] = {
                "name": rule_name.replace("-", " "),
                "slug": rule_name,
                "description": rule_data["description"],
                "id": rule_id,
                "criticality": rule_data.get("criticality", 0),
                "type": rule_type,
            }

    return rules_map


def search_in_file(file_content: str, key: str) -> dict:
    """
    Search for a key in a file content.

    Return format:

    {
      "start_line": 2,
      "start_column": 5,
      "end_line": 2,
      "end_column": 10
    }
    """
    # Search for the key in the file
    key_index = file_content.find(key)

    if key_index == -1:
        raise ValueError(f"Can't find key {key} in file")

    # Get the line number
    line_number = file_content.count("\n", 0, key_index) + 1

    # Get the column number
    column_number = key_index - file_content.rfind("\n", 0, key_index)

    return {
        "start_line": line_number,
        "start_column": column_number,
        "end_line": line_number,
        "end_column": column_number + len(key),
    }


def _get_warnings(report: dict) -> dict:
    try:
        warnings: dict = report["warnings"]["issues"]
    except KeyError:
        warnings = {}

    return warnings


def _get_security(report: dict) -> dict:
    try:
        security: dict = report["security"]["issues"]
    except KeyError:
        security = {}

    return security


def convert_to_sarif(filename: str, file_content: str | bytes, report: dict, urls_map: dict, rules: dict) -> dict:
    sarif_rules = [
        {
            "id": rule["id"],
            "name": rule["name"],
            f"helpUri": f"https://docs.42crunch.com/latest/content/oasv3/datavalidation/schema/{rule_name}.htm",
            "shortDescription": {
                "text": rule["description"],
            },
            "help": {
                "text": "Description\n-----------\n\nA string schema does not define any pattern for the accepted strings. This means that it does not limit the values that get passed to the API.\n\nFor more details, see the [OpenAPI Specification](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md#schemaObject).\n\nExample\n-------\n\nThe following is an example of how this type of risk could look in your API definition. Because no pattern is defined, the API accepts a string of any size and value:\n\n    {\n        \"post\": {\n            \"description\": \"Creates a new pet in the store\",\n            \"operationId\": \"addPet\",\n            \"requestBody\": {\n                \"description\": \"Pet to add to the store\",\n                \"required\": true,\n                \"content\": {\n                    \"application/json\": {\n                        \"schema\": {\n                            \"$ref\": \"#/components/schemas/NewPet\"\n                        }\n                    }\n                }\n            }\n        },\n        // ...\n        \"NewPet\": {\n            \"type\": \"object\",\n            \"description\": \"JSON defining a Pet object\",\n            \"additionalProperties\": false,\n            \"required\": [\n                \"name\"\n            ],\n            \"properties\": {\n                \"name\": {\n                    \"type\": \"string\"\n                }       \n            }\n        }\n    }\n\nPossible exploit scenario\n-------------------------\n\nIf you do not define a pattern for strings, any string is accepted as the input. This could open your backend server to various attacks, such as SQL injection.\n\nRemediation\n-----------\n\nSet a well-defined regular expression that matches your requirements in the `pattern` field of string parameters. This ensures that only strings matching the set pattern get passed to your API.\n\nFor example, the API below only accepts UUIDs that are compliant with [RFC 4122](https://www.ietf.org/rfc/rfc4122.txt):\n\n    {\n        \"post\": {\n            \"description\": \"Creates a new pet in the store\",\n            \"operationId\": \"addPet\",\n            \"requestBody\": {\n                \"description\": \"Pet to add to the store\",\n                \"required\": true,\n                \"content\": {\n                    \"application/json\": {\n                        \"schema\": {\n                            \"$ref\": \"#/components/schemas/NewPet\"\n                        }\n                    }\n                }\n            }\n        },\n        // ...\n        \"NewPet\": {\n            \"type\": \"object\",\n            \"description\": \"JSON defining a Pet object\",\n            \"additionalProperties\": false,\n            \"required\": [\n                \"name\"\n            ],\n            \"properties\": {\n                \"name\": {\n                    \"type\": \"string\",\n                    \"maxLength\": 10,\n                    \"pattern\": \"^[A-Za-z0-9]{3,10}$\"\n                }       \n            }\n        }\n    }\n\nWe recommend that you carefully think what kind of regular expression best matches your needs. Do not simply blindly copy the pattern from the code example.\n\nRemember to include the anchors `^` and `$` in your regular expression, otherwise the overall length of the pattern could be considered infinite. If you include the anchors in the regular expression _and_ the pattern _only_ has fixed or constant quantifiers (like `{10,64}`, for example), you do not have to define the property `maxLength` separately for the object, as the length is fully constrained by the pattern. However, if the regular expression does not include the anchors _or_ its quantifiers are not fixed (like in `^a.*b$`), it can be considered to be just a part of a longer string and the property `maxLength` is required to constrain the length.\n\nFor more information on regular expressions, see the following:\n\n*   Language-agnostic information on regular expressions at [Base Definitions page on regular expressions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html)\n*   [OWASP Validation Regex Repository](https://owasp.org/www-community/OWASP_Validation_Regex_Repository)\n*   [RegExr](https://regexr.com/), an online tool for building and testing regular expressions\n\nFor examples on some of the common regulars expressions, see the [full article](https://docs.42crunch.com/latest/content/oasv3/datavalidation/schema/v3-schema-request-string-pattern.htm)."
            },
            "properties": {
                "tags": [
                    rule["type"],
                ],
                "criticality": resolve_criticality(rule["criticality"]),
            }
        }

        for rule_name, rule in rules.items()
    ]

    warnings_issues = _get_warnings(report)
    security_issues = _get_security(report)

    total_issues = {**warnings_issues, **security_issues}

    results = []

    index = 0
    for issue_name, issue in total_issues.items():

        # Get end-point for this issue
        end_points_indexes = []

        # TODO: Map global issues
        try:
            for local_issue in issue["issues"]:
                end_points_indexes.extend(local_issue["pointersAffected"])
        except KeyError:
            end_points_indexes.append("global")

        # Resolve end-points with reals end-points
        endpoints = [
            urls_map[str(ei)]
            for ei in end_points_indexes
            if str(ei) in urls_map and ei != "global"
        ]

        # Get physical location in file
        for endpoint in endpoints:

            if endpoint != "global":
                try:
                    region = search_in_file(file_content, endpoint)
                except ValueError:
                    print(f"[!] Can't find endpoint {endpoint} in file {filename}")
                    continue

            else:
                region = {
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 1,
                }

            # Make a great description

            if endpoint != "global":
                description = ["**Scope:** Global"]
            else:
                description = ["**Scope:** Endpoint"]

            description.append(
                f"**Description:** {issue['description']}\n\n",
            )

            results.append({
                "ruleId": "3f292041e51d22005ce48f39df3585d44ce1b0ad",
                "ruleIndex": index,
                "level": resolve_criticality(issue["criticality"]),
                "message": {
                    "text": "\n".join(description)
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"file:///{filename}",
                                "index": 0,
                            },
                            "region": {
                                "startLine": region["start_line"],
                                "startColumn": region["start_column"],
                                "endColumn": region["end_column"],
                            }
                        }
                    }
                ]
            })

            index += 1

    return {
        "version": "2.1.0",
        "$schema": "http://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "42Crunch API Audit",
                        "version": "1.0.0",
                        "informationUri": "https://42crunch.com/",
                        "rules": sarif_rules,
                    },
                },
                "results": results,
            },
        ],
    }


def get_url_map(report: dict) -> Dict[str, str]:
    urls = {
        str(i): url
        for i, url in enumerate(report["index"])
    }

    return urls


def check_analysis_result_is_valid(report: dict) -> bool:
    return report["openapiState"] == "fileInvalid"


def main():
    # Create argparse parser with two parameter: the input file and output file
    # Parse the arguments
    args = argparse.ArgumentParser(description='Convert 42Crunch API Conformance Scan reports to SARIF format')
    args.add_argument('-a', '--open-api', help='OpenAPI path location', required=True)
    args.add_argument('-i', '--input', help='42Crunch report file name', required=True)
    args.add_argument('-o', '--output', help='Output file name', required=True)
    args.add_argument('--debug', help='Enable debug mode', action='store_true')
    args = args.parse_args()

    # Some debug messages
    if args.debug:
        print("[*] Start converting 42Crunch API Conformance Scan reports to SARIF format")

    # Read the input file
    if args.debug:
        print(f"[*] Reading input file: {args.input}")

    with open(args.input) as f:
        try:
            report_content = f.read()
        except Exception as e:
            print("[!] Can't read input file: ", str(e))
            exit(1)

    try:
        scan_reports_json = json.loads(report_content)
    except Exception as e:
        print("[!] Can't read input file: ", str(e))
        exit(1)

    if args.debug:
        print("[*] Checking 42Crunch result file...")

    if check_analysis_result_is_valid(scan_reports_json):
        print("[!] Analysis result is invalid")
        exit(0)

    # Convert the input file to SARIF format
    if args.debug:
        print("[*] Preparing report...")

    rules = get_rules(scan_reports_json)
    urls_map = get_url_map(scan_reports_json)

    sarif_log = convert_to_sarif(
        args.open_api,
        report_content,
        scan_reports_json,
        urls_map,
        rules
    )

    # Write the SARIF file
    if args.debug:
        print(f"[*] Writing SARIF file: {args.output}")
    with open(args.output, 'w') as f:
        try:
            json.dump(sarif_log, f, indent=4)
        except Exception as e:
            print("[!] Can't write output file: ", str(e))

    if args.debug:
        print("[*] Done")


if __name__ == '__main__':
    main()
