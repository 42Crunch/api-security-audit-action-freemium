FROM 42crunch/github-api-security-audit-base-image:v1.0.0

COPY ./entrypoint_github_actions_audit.sh /entrypoint-github-actions-audit
COPY ./entrypoint_github_actions_audit_without_binaries.sh /entrypoint-github-actions-audit-without-binaries
RUN chmod +x /entrypoint-github-actions-audit

#ENTRYPOINT ["/entrypoint-github-actions-audit-without-binaries"]
ENTRYPOINT ["/entrypoint-github-actions-audit"]
