# NSG JIT Rule Action

Create or update a Network Security Group (NSG) just-in-time (JIT) access rule in Azure.

This GitHub Action provides enterprise-grade management of temporary NSG rules for secure, time-limited access to Azure resources.

## Usage

### Basic Example

```yaml
name: Create NSG JIT Rule

on:
  workflow_dispatch:
    inputs:
      duration:
        description: 'Duration for JIT access (minutes)'
        required: false
        default: '60'

jobs:
  create-jit-rule:
    runs-on: ubuntu-latest
    steps:
      - uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
        with:
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          resource-group: 'my-rg'
          nsg-name: 'my-nsg'
          rule-name: 'jit-rdp-access'
          destination-ports: '3389'
          protocol: 'Tcp'
          direction: 'Inbound'
          destination-prefix: '*'
          source-address-prefix: ${{ secrets.MY_IP_ADDRESS }}
```

## Inputs

### Required

| Input | Description | Example |
|-------|-------------|---------|
| `subscription-id` | Azure Subscription ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `resource-group` | Azure Resource Group name | `my-resource-group` |
| `nsg-name` | Network Security Group name | `my-nsg` |
| `rule-name` | Name for the JIT access rule | `jit-rdp-access` |
| `destination-ports` | Destination ports (comma-separated or range) | `3389` or `80,443` or `1024-65535` |
| `protocol` | Protocol (Tcp, Udp, or *) | `Tcp` |
| `direction` | Rule direction (Inbound or Outbound) | `Inbound` |
| `destination-prefix` | Destination address prefix | `*` or `10.0.0.0/8` |

### Optional

| Input | Description | Default |
|-------|-------------|---------|
| `source-address-prefix` | Source address prefix for the rule | `*` |
| `priority` | Rule priority (100-4096, auto-assigned if omitted) | Auto |

## Outputs

| Output | Description |
|--------|-------------|
| `rule-id` | Resource ID of the created/updated NSG rule |
| `rule-name` | Name of the NSG rule |
| `pre-state` | Previous state of the rule (if it existed) |
| `post-state` | Current state of the rule after the action |
| `status` | Status of the operation (Created, Updated, or NoChange) |

## Authentication

This action uses Azure Workload Identity Federation for authentication. Ensure your GitHub Actions workflow is configured with:

1. Azure Workload Identity OIDC provider configured
2. Federated credentials set up for your GitHub organization
3. Service Principal with appropriate NSG permissions

### Minimal Required Permissions

```
Microsoft.Network/networkSecurityGroups/securityRules/write
Microsoft.Network/networkSecurityGroups/securityRules/read
Microsoft.Network/networkSecurityGroups/read
```

## Advanced Examples

### With Dynamic Source IP

```yaml
- uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: 'prod-rg'
    nsg-name: 'prod-nsg'
    rule-name: 'jit-ssh-${{ github.actor }}'
    destination-ports: '22'
    protocol: 'Tcp'
    direction: 'Inbound'
    destination-prefix: '*'
    source-address-prefix: ${{ github.event.client_ip }}
    priority: '100'
```

### Multiple Ports

```yaml
- uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: 'my-rg'
    nsg-name: 'my-nsg'
    rule-name: 'jit-multi-ports'
    destination-ports: '80,443,8080,8443'
    protocol: 'Tcp'
    direction: 'Inbound'
    destination-prefix: '10.0.0.0/8'
```

### Port Range

```yaml
- uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: 'my-rg'
    nsg-name: 'my-nsg'
    rule-name: 'jit-ephemeral-ports'
    destination-ports: '49152-65535'
    protocol: 'Tcp'
    direction: 'Inbound'
    destination-prefix: '192.168.0.0/16'
```

## Implementation Status

This action is a framework template ready for enterprise-grade implementation. The boilerplate structure supports:

- Azure identity and authentication
- NSG resource management
- Rule lifecycle operations (create, update, verify)
- Output reporting and state tracking
- Error handling and logging

**Ready to accept sample code for integration.**

## Security Considerations

- Use GitHub Secrets for sensitive inputs (subscription IDs, IP addresses)
- Limit JIT rule duration to minimize exposure
- Always specify the most restrictive source and destination prefixes
- Enable NSG flow logs for audit trails
- Consider using network watchers for additional monitoring

## License

Licensed under the Apache License, Version 2.0. See LICENSE in the repository root.
