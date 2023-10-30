FROM cr0hn/sample-an-testing-for-documentation:v1.0.0

#
# Specific instructions for GitHub
#
#COPY ./entrypoint_github_actions_audit.sh /entrypoint-github-actions-audit
#COPY ./entrypoint_github_actions_audit_without_binaries.sh /entrypoint-github-actions-audit-without-binaries
COPY ./entrypoint_github_actions_audit.py /entrypoint-github-actions-audit
RUN chmod +x /entrypoint-*

WORKDIR /github/workspace
ENTRYPOINT ["/entrypoint-github-actions-audit"]
