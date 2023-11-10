FROM cr0hn/sample-an-testing-for-documentation:v1.0.2

#
# Specific instructions for GitHub
#
COPY ./entrypoint_github_actions_audit.py /entrypoint-github-actions-audit
#COPY ./entrypoint_github_actions_scan.py /entrypoint-github-actions-scan
RUN chmod +x /entrypoint-*

WORKDIR /github/workspace
ENTRYPOINT ["/entrypoint-github-actions-audit"]
#ENTRYPOINT ["/entrypoint-github-actions-scan"]
