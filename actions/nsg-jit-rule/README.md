# NSG JIT Rule Action

Create or update a Network Security Group (NSG) just-in-time (JIT) access rule in Azure.

This action includes built-in post-action cleanup that automatically removes the temporary rule at the end of the job.

## Usage

### Prerequisites

1. Azure Workload Identity Federation configured for your GitHub repository
2. Service principal with NSG management permissions
3. `id-token: write` and `contents: read` workflow permissions

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

Runtime dependencies are bundled in the committed action distribution, so no `npm ci` step is required in workflows.

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
| `destination-prefix` | Destination address prefix | `*`, `10.0.0.0/8` |

### Optional

| Input | Description | Default |
| --- | --- | --- |
| `source-address-prefix` | Source address prefix for the rule | `*` |
| `priority` | Rule priority (`100-4096`, auto-assigned if omitted) | Auto |

## Outputs

| Output | Description |
| --- | --- |
| `rule-id` | Resource ID of the created NSG rule |
| `rule-name` | Name of the NSG rule |
| `nsg-name` | NSG name used by the action |
| `resource-group` | Resource group used by the action |
| `subscription-id` | Subscription used by the action |
| `source-ip` | Runner private source IP |
| `source-cidr` | Source CIDR used for the rule |
| `pre-state` | NSG state before rule creation |
| `post-state` | NSG state after rule creation |
| `status` | Action status |
| `timestamp` | Operation timestamp (ISO 8601) |
| `error` | Error message (only set on failure) |

## Authentication

This action uses Azure Workload Identity Federation. Ensure your workflow is configured with:

1. Azure OIDC provider and federated credentials
2. Service principal with NSG permissions
3. `azure/login@v2` before running the action

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
    destination-ports: 80,443,8080,8443
    protocol: Tcp
    direction: Inbound
    destination-prefix: 10.0.0.0/8
```

### Port Range

```yaml
- uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: my-rg
    nsg-name: my-nsg
    rule-name: jit-ephemeral-ports
    destination-ports: 49152-65535
    protocol: Tcp
    direction: Inbound
    destination-prefix: 192.168.0.0/16
```

## Automatic Cleanup

Cleanup is built in and runs as a post-action (`post-if: always()`).

- No explicit cleanup step is required.
- Cleanup executes on success and failure.
- Missing or already-deleted rules are handled gracefully.

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
