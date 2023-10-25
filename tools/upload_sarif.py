#!/usr/bin/env python3

import os
import gzip
import json
import base64
import argparse
import urllib.request


def upload_sarif(github_token, github_repository, github_sha, sarif_file_path, ref):
    if not github_token:
        print("[!] Missing or empty GitHub token")
        exit(1)

    # Convert the SARIF file to base64 after gzip compression
    try:
        with open(sarif_file_path, 'rb') as f:
            zipped_sarif = base64.b64encode(gzip.compress(f.read())).decode()
    except FileNotFoundError:
        print(f"[!] File {sarif_file_path} not found")
        exit(1)

    # Extract owner and repo from the provided repository
    try:
        owner, repo = github_repository.split('/')
    except ValueError:
        print(f"[!] Invalid repository {github_repository}")
        exit(1)

    # Current directory as a URL (approximation)
    checkout_uri = f"file://{os.getcwd()}"

    # Construct the request
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/sarifs"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }
    data = {
        "commit_sha": github_sha,
        "ref": ref,
        "sarif": zipped_sarif,
        "tool_name": "42Crunch REST API Static Security Testing",
        "checkout_uri": checkout_uri
    }
    req = urllib.request.Request(url, headers=headers, data=json.dumps(data).encode())

    # Send the request
    with urllib.request.urlopen(req) as response:
        print(response.read().decode())


def main():
    parser = argparse.ArgumentParser(description="Upload SARIF to GitHub")
    parser.add_argument('sarif_file', help="Path to SARIF file")
    parser.add_argument('--github-token', required=True, help="GitHub Token")
    parser.add_argument('--github-repository', required=True, help="GitHub repository in format owner/repo")
    parser.add_argument('--github-sha', required=True, help="Commit SHA")
    parser.add_argument('--ref', required=True, help="Reference (branch or tag)")

    args = parser.parse_args()

    upload_sarif(args.github_token, args.github_repository, args.github_sha, args.sarif_file, args.ref)


if __name__ == '__main__':
    main()
