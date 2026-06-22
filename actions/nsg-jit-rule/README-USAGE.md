# NSG JIT Rule Action - Usage Guide

## Quick Start

Use the action directly after Azure login.

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
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Create NSG JIT Rule
        uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
        with:
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          resource-group: my-rg
          nsg-name: my-nsg
          rule-name: jit-rdp-access
          destination-ports: 3389
          protocol: Tcp
          direction: Inbound
          destination-prefix: '*'
```

No dependency installation step is required in workflows.
Runtime dependencies are bundled into the committed distribution files.

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
