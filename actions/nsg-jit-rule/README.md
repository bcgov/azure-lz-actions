# NSG JIT Rule Action

Create or update a Network Security Group (NSG) just-in-time (JIT) access rule in Azure.

This GitHub Action provides enterprise-grade management of temporary NSG rules for secure,
time-limited access to Azure resources.

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

| Input                  | Description                                    | Example                              |
| ---------------------- | ---------------------------------------------- | ------------------------------------ |
| `subscription-id`      | Azure Subscription ID                          | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `resource-group`       | Azure Resource Group name                      | `my-resource-group`                  |
| `nsg-name`             | Network Security Group name                    | `my-nsg`                             |
| `rule-name`            | Name for the JIT access rule                   | `jit-rdp-access`                     |
| `destination-ports`    | Destination ports (comma-separated or range)   | `3389` or `80,443` or `1024-65535`   |
| `protocol`             | Protocol (Tcp, Udp, or *)                      | `Tcp`                                |
| `direction`            | Rule direction (Inbound or Outbound)           | `Inbound`                            |
| `destination-prefix`   | Destination address prefix                     | `*` or `10.0.0.0/8`                  |
| `subscription-id` | Azure Subscription ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `resource-group` | Azure Resource Group name | `my-resource-group` |
| `nsg-name` | Network Security Group name | `my-nsg` |
| `rule-name` | Name for the JIT access rule | `jit-rdp-access` |
| `destination-ports` | Destination ports (comma-separated or range) | `3389` or `80,443` or `1024-65535` |
| `protocol` | Protocol (Tcp, Udp, or *) | `Tcp` |
| `direction` | Rule direction (Inbound or Outbound) | `Inbound` |
| `destination-prefix` | Destination address prefix | `*` or `10.0.0.0/8` |

### Optional

| Input                  | Description                                    | Default |
| ---------------------- | ---------------------------------------------- | ------- |
| `source-address-prefix` | Source address prefix for the rule             | `*`     |
| `priority`             | Rule priority (100-4096, auto-assigned)        | Auto    |
| `source-address-prefix` | Source address prefix for the rule | `*` |
| `priority` | Rule priority (100-4096, auto-assigned if omitted) | Auto |

## Outputs

| Output      | Description                                   |
| ----------- | --------------------------------------------- |
| `rule-id`   | Resource ID of the created/updated NSG rule   |
| `rule-name` | Name of the NSG rule                          |
| `pre-state` | Previous state of the rule (if it existed)    |
| `post-state` | Current state of the rule after the action    |
| `status`    | Status of the operation (Created/Updated)     |
| `rule-id` | Resource ID of the created/updated NSG rule |
| `rule-name` | Name of the NSG rule |
| `pre-state` | Previous state of the rule (if it existed) |
| `post-state` | Current state of the rule after the action |
| `status` | Status of the operation (Created, Updated, or NoChange) |

## Authentication

This action uses Azure Workload Identity Federation for authentication. Ensure your GitHub
Actions workflow is configured with:

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

## Enterprise Features

### Automatic Cleanup (Built-in Post-Action)

**No manual cleanup required.** This action automatically reverts NSG rules via a built-in
post-action that executes after the main action completes, regardless of success or failure.
This eliminates the risk of orphaned rules that could create security vulnerabilities.

The post-action cleanup:

- ✓ Runs automatically — no explicit cleanup step needed
- ✓ Executes on both success and failure (`always()`)
- ✓ Gracefully handles already-deleted rules
- ✓ Includes retry logic for transient failures
- ✓ Logs comprehensive audit trail

**Simple usage** — no cleanup configuration required:

```yaml
- uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@main
  with:
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    resource-group: 'my-rg'
    nsg-name: 'my-nsg'
    rule-name: 'jit-access-rule'
    destination-ports: '3389'
    protocol: 'Tcp'
    direction: 'Inbound'
    destination-prefix: '*'

# Cleanup happens automatically — no additional steps needed!
```

### Input Validation

The action validates all inputs before execution:

- **Subscription ID**: UUID format validation
- **Resource names**: Azure naming conventions (alphanumeric, hyphens, underscores, dots only)
- **Protocol**: Must be TCP, UDP, or *
- **Direction**: Must be Inbound or Outbound
- **Priority**: Range 100-4096
- **Ports**: Single port, range (e.g., 80-443), or comma-separated list
- **CIDR blocks**: Valid IPv4 CIDR notation

Invalid inputs fail fast with descriptive error messages.

### Pre-flight Verification

Before rule creation, the action verifies:

- Azure authentication and OIDC token validity
- Resource group exists and is accessible
- NSG exists in the resource group
- Current NSG rule state (for conflict detection)
- Sufficient permissions via Microsoft.Network/networkSecurityGroups/* roles

### Retry Logic with Exponential Backoff

Critical operations retry automatically on transient failures:

- Azure authentication (3 attempts)
- Resource verification (3 attempts)
- Rule creation (3 attempts)
- Cleanup operations (2 attempts)

Retry delays: 1s → 2s → 4s (exponential backoff)

### Structured Audit Logging

All operations log structured JSON audit trails including:

- Timestamp (ISO 8601)
- GitHub context (run ID, actor, repository, workflow name)
- Azure context (subscription, resource group, NSG, rule details)
- Operation status and duration
- Error details on failure

**Example audit log:**

```json
{
  \"timestamp\": \"2024-12-20T15:30:45.123Z\",
  \"action\": \"nsg-jit-rule-created\",
  \"github\": {
    \"run_id\": \"12345678\",
    \"actor\": \"github-user\",
    \"repository\": \"org/repo\",
    \"workflow\": \"Create NSG Access\"
  },
  \"azure\": {
    \"subscription_id\": \"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\",
    \"resource_group\": \"prod-rg\",
    \"nsg_name\": \"prod-nsg\",
    \"rule\": {
      \"name\": \"jit-ssh-access\",
      \"priority\": 3000,
      \"direction\": \"Inbound\",
      \"protocol\": \"TCP\",
      \"source_ip\": \"203.0.113.42\",
      \"source_cidr\": \"203.0.113.42/32\",
      \"destination_ports\": \"22\"
    }
  },
  \"status\": \"success\",
  \"duration_ms\": 8500
}\n```

### Error Recovery

The action handles common failure scenarios gracefully:

- **Authentication failures**: Clear error message about OIDC setup
- **Missing resources**: Guides user to verify RG/NSG exists
- **Permission errors**: References required RBAC roles
- **Rule conflicts**: Warns about existing rules but proceeds
- **Transient failures**: Retries automatically with backoff
- **Timeout errors**: Reports specific operation that timed out

### Runner IP Auto-detection

The action automatically detects the runner's private IP via:

1. **Routing table lookup** (primary): `ip -4 route get 1.1.1.1`
2. **Environment variable** (fallback): `RUNNER_PRIVATE_IP`
3. **Error handling**: Clear guidance if neither method succeeds

The resolved IP is used as the source CIDR (`/32` subnet mask) for the rule.

## Security Considerations

- Use GitHub Secrets for sensitive inputs (subscription IDs, IP addresses)
- Limit JIT rule duration to minimize exposure
- Always specify the most restrictive source and destination prefixes
- Enable NSG flow logs for audit trails
- Consider using network watchers for additional monitoring

## License

Licensed under the Apache License, Version 2.0. See LICENSE in the repository root.
