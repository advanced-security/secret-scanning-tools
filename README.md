# secret-scanning-tools

Testing Suite for GitHub Secret Scanning Custom Patterns

## Usage

```yaml
- name: Secret Scanning Test Suite
  uses: advanced-security/secret-scanning-tools@main
```

**Advanced Configurations:**

```yaml
- name: Secret Scanning Test Suite
  uses: advanced-security/secret-scanning-tools@main
  with:
    # Modes to run
    # > 'validate' (default), 'all', 'snapshot', 'markdown'
    mode: 'validate'
```

**Using GitHub App Token:**

```yaml
- name: Get Token
  id: get_workflow_token
  uses: peter-murray/workflow-application-token-action@v1
  with:
    application_id: ${{ secrets.ADVANCED_SECURITY_APP_ID }}
    application_private_key: ${{ secrets.ADVANCED_SECURITY_APP_KEY }}

- name: Secret Scanning Test Suite
  uses: advanced-security/secret-scanning-tools@main
  with:
    token: ${{ steps.get_workflow_token.outputs.token }}
```
