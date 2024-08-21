FROM 42crunch/github-api-security-base-image:v1.2-rc

#
# Specific instructions for GitHub
#
COPY ./entrypoint_github_actions_audit.py /entrypoint-github-actions-audit
RUN chmod +x /entrypoint-*

WORKDIR /github/workspace
ENTRYPOINT ["/entrypoint-github-actions-audit"]
