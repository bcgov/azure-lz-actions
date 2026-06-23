# NSG JIT Rule Action

Create or update a Network Security Group (NSG) just-in-time (JIT) access rule in Azure.

This action includes built-in post-action cleanup that automatically removes the temporary rule at the end of the job.

## Usage

### Prerequisites

1. Azure Workload Identity Federation configured for your GitHub repository
2. Service principal with NSG management permissions
3. `id-token: write` and `contents: read` workflow permissions
4. Resolve the runner private IP in your workflow before calling this action

### Basic Example

```yaml
name: Create NSG JIT Rule

on:
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  create-jit-rule:
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
          # source-prefixes omitted => defaults to source-ip/32
          destination-ports: 3389
          protocol: Tcp
          direction: Inbound
          # destination-prefixes omitted => defaults to *
```

Runtime dependencies are bundled in the committed action distribution, so no `npm ci` step is required in workflows.

### Runner Private IP Prerequisite Step

Add this step before invoking the action:

The action does not resolve runner IP internally; it expects `source-ip` to be provided.

```yaml
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
```

Then pass it to the action input:

```yaml
source-ip: ${{ steps.runner_ip.outputs.runner_private_ip }}
```

## Inputs

### Required

| Input | Description | Example |
| --- | --- | --- |
| `subscription-id` | Azure subscription ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `resource-group` | Azure resource group name | `my-resource-group` |
| `nsg-name` | Network Security Group name | `my-nsg` |
| `rule-name` | Name for the JIT access rule | `jit-rdp-access` |
| `destination-ports` | Destination ports (single, CSV, or range) | `3389`, `80,443`, `1024-65535` |
| `protocol` | Protocol (`Tcp`, `Udp`, or `*`) | `Tcp` |
| `direction` | Rule direction (`Inbound` or `Outbound`) | `Inbound` |

### Optional

| Input | Description | Default |
| --- | --- | --- |
| `source-ip` | Source IPv4 address to allow. Required when `source-prefixes` is not set. | Empty |
| `source-prefixes` | Source address prefixes as CSV (IP/CIDR/*) | `source-ip/32` |
| `destination-prefixes` | Destination address prefixes as CSV (IP/CIDR/*) | `*` |
| `priority` | Rule priority (`100-4096`, auto-assigned if omitted) | Auto |
| `cleanup-enabled` | Whether post-action cleanup should delete the rule (`true`/`false`) | `true` |

## Outputs

| Output | Description |
| --- | --- |
| `rule-id` | Resource ID of the created NSG rule |
| `rule-name` | Name of the NSG rule |
| `nsg-name` | NSG name used by the action |
| `resource-group` | Resource group used by the action |
| `subscription-id` | Subscription used by the action |
| `source-ip` | Source IP provided to the action |
| `source-cidr` | Canonical source CIDR derived from `source-ip` |
| `source-prefixes` | Effective source prefixes used for the rule |
| `destination-prefixes` | Effective destination prefixes used for the rule |
| `pre-state` | NSG state before rule creation |
| `post-state` | NSG state after rule creation |
| `status` | Action status |
| `timestamp` | Operation timestamp (ISO 8601) |
| `operation-id` | Correlation ID for action and cleanup logs |
| `github-run-id` | GitHub workflow run ID |
| `github-run-attempt` | GitHub workflow run attempt number |
| `error` | Error message (only set on failure) |

## Authentication

This action uses Azure Workload Identity Federation. Ensure your workflow is configured with:

1. Azure OIDC provider and federated credentials
2. Service principal with NSG permissions
3. `azure/login@v3` before running the action

### Minimal Required Permissions

```
Microsoft.Network/networkSecurityGroups/securityRules/write
Microsoft.Network/networkSecurityGroups/securityRules/read
Microsoft.Network/networkSecurityGroups/read
```

## Advanced Examples

### Multiple Ports

```yaml
- uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: my-rg
    nsg-name: my-nsg
    rule-name: jit-multi-ports
    source-ip: ${{ steps.runner_ip.outputs.runner_private_ip }}
    destination-ports: 80,443,8080,8443
    protocol: Tcp
    direction: Inbound
    destination-prefixes: 10.0.0.0/8
```

### Port Range

```yaml
- uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: my-rg
    nsg-name: my-nsg
    rule-name: jit-ephemeral-ports
    source-ip: ${{ steps.runner_ip.outputs.runner_private_ip }}
    destination-ports: 49152-65535
    protocol: Tcp
    direction: Inbound
    destination-prefixes: 192.168.0.0/16

### Multiple Source And Destination Prefixes

```yaml
- uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: my-rg
    nsg-name: my-nsg
    rule-name: jit-flex-prefixes
    source-ip: ${{ steps.runner_ip.outputs.runner_private_ip }}
    source-prefixes: 10.10.1.5/32,10.10.2.0/24
    destination-ports: 443
    protocol: Tcp
    direction: Inbound
    destination-prefixes: 10.20.0.0/16,10.30.1.25/32
```

## Automatic Cleanup

Cleanup is built in and runs as a post-action (`post-if: always()`).

- No explicit cleanup step is required.
- Cleanup executes on success and failure.
- Missing or already-deleted rules are handled gracefully.

If you need to retain the rule after workflow completion, set:

```yaml
cleanup-enabled: 'false'
```

The action writes a GitHub Job Summary for both create and cleanup phases.

## Troubleshooting

### Error: OIDC token acquisition failed

Cause: Azure Workload Identity Federation is not configured correctly.

Fix:

1. Verify OIDC provider in the tenant
2. Verify federated credential mapping for repo/branch/environment
3. Verify service principal permissions

### Error: NSG not found in resource group

Cause: Wrong resource group or NSG name, or missing read permissions.

Fix:

1. Verify resource group and NSG names
2. Verify subscription context used by `azure/login`
3. Verify principal has read access to the resource group

### Rule cleanup not occurring

Cause: Job canceled before post-action or environment-level interruption.

Fix:

1. Confirm post-action is present in action metadata
2. Review job cancellation behavior in workflow settings
3. Manually remove the temporary rule if needed

## Security Considerations

- Use GitHub Secrets for sensitive values
- Keep destination prefixes and ports as narrow as possible
- Use explicit source prefixes when possible
- Enable NSG flow logs for audit requirements

## License

Licensed under Apache 2.0. See repository root `LICENSE`.
