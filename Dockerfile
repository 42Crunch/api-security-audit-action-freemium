FROM cr0hn/sample-an-testing-for-documentation:v1.0.8

#
# Specific instructions for GitHub
#
COPY ./entrypoint_github_actions_audit.py /entrypoint-github-actions-audit
RUN chmod +x /entrypoint-*

WORKDIR /github/workspace
ENTRYPOINT ["/entrypoint-github-actions-audit"]
