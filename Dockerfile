FROM 42crunch/github-api-security-audit-base-image:v1.0.0

COPY ./entrypoint_github_actions_audit.sh /entrypoint-github-actions-audit
RUN chmod +x /entrypoint-github-actions-audit

ENTRYPOINT ["/entrypoint-github-actions-audit"]
