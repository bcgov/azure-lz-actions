# NSG JIT Rule Action - Usage Guide

## Quick Start

Resolve runner private IP, then use the action.

```yaml
name: Create NSG JIT Rule

on: workflow_dispatch

permissions:
  id-token: write
  contents: read

jobs:
  create-rule:
    runs-on: ubuntu-latest
    steps:
      - name: Azure Login (OIDC)
        uses: azure/login@v3
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Resolve runner private IP
        id: runner_ip
        shell: bash
        run: |
          set -euo pipefail

          RUNNER_PRIVATE_IP="$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
          if [[ ! "$RUNNER_PRIVATE_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "Failed to resolve private IPv4 from routing table."
            exit 1
          fi

          echo "runner_ip=$RUNNER_PRIVATE_IP" >> "$GITHUB_OUTPUT"
          echo "runner_private_ip=$RUNNER_PRIVATE_IP" >> "$GITHUB_OUTPUT"
          echo "Resolved runner private IP (VNet/internal): $RUNNER_PRIVATE_IP"

      - name: Create NSG JIT Rule
        uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
        with:
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          resource-group: my-rg
          nsg-name: my-nsg
          rule-name: jit-rdp-access
          source-ip: ${{ steps.runner_ip.outputs.runner_private_ip }}
          destination-ports: 3389
          protocol: Tcp
          direction: Inbound
          destination-prefixes: '*'
```

No dependency installation step is required in workflows.
Runtime dependencies are bundled into the committed distribution files.

## Optional Behavior

Disable automatic post-action cleanup when you intentionally want to retain the rule:

```yaml
- name: Create NSG JIT Rule
  uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: my-rg
    nsg-name: my-nsg
    rule-name: jit-rdp-access
    source-ip: ${{ steps.runner_ip.outputs.runner_private_ip }}
    source-prefixes: 10.10.1.5/32,10.10.2.0/24
    destination-ports: 3389
    protocol: Tcp
    direction: Inbound
    destination-prefixes: 10.20.1.0/24,10.20.2.10/32
    cleanup-enabled: 'false'
```

Use outputs `operation-id`, `github-run-id`, and `github-run-attempt` for audit correlation.

## Troubleshooting

### Cannot find distribution file (dist/index.js)

Cause: The action branch/tag was updated without committing rebuilt distribution files.

Fix:

1. Rebuild the action bundle locally.
2. Commit both `dist/index.js` and `dist-cleanup/cleanup.js`.
3. Push the updated branch/tag.

### OIDC Authentication Failures

Confirm that:

1. `permissions.id-token` is set to `write`
2. The service principal has a matching federated credential
3. Subscription/tenant/client IDs are correct

## Maintainer Notes

When source changes are made to `index.js` or `cleanup.js`, rebuild and commit bundles:

```bash
npm ci
npm run build
git add action.yml dist/index.js dist-cleanup/cleanup.js
```
