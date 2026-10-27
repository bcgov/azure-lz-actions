# NSG JIT Rule Action

Create a temporary Azure Network Security Group rule for a GitHub-hosted runner
with private Azure VNet connectivity. The action creates a uniquely named rule
and removes it in its post-action step.

The caller resolves the runner's private IPv4 address at runtime, then passes it
as `source-ip`. The example reads the global IPv4 address on the interface used
by the runner's default route.

## Prerequisites

- Configure the GitHub-hosted runner for Azure VNet connectivity and confirm it
  can route to the target private endpoint or resource.
- Run `azure/login@v3` before this action using OIDC. Grant the workflow
  `id-token: write` permission.
- Ensure Azure CLI is installed on the runner.
- Grant the federated identity read access to the resource group and NSG, and
  permission to create, read, and delete NSG security rules. Scope access to the
  NSG or resource group where practical.
- Use a private runner address or scoped source prefixes. Broad sources require
  the `allow-any-source` opt-in.

The `subscription-id` input identifies the NSG's subscription. It may differ
from the `azure/login` subscription if the logged-in identity can access both.
The action explicitly selects and scopes CLI operations to the target.

## Example

This example reads the IPv4 address on the runner's default-route interface.

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
          subscription-id: ${{ secrets.AZURE_LOGIN_SUBSCRIPTION_ID }}

      - name: Resolve runner private IP
        id: runner_ip
        shell: bash
        run: |
          set -euo pipefail
          runner_interface="$(ip -4 route show default | awk 'NR == 1 {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
          if [[ -z "$runner_interface" ]]; then
            echo "Could not identify the runner's default-route network interface." >&2
            exit 1
          fi
          runner_private_ip="$(ip -4 -o addr show dev "$runner_interface" scope global | awk 'NR == 1 {split($4, address, "/"); print address[1]}')"
          if ! python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$runner_private_ip"; then
            echo "Could not resolve a valid IPv4 address on interface $runner_interface." >&2
            exit 1
          fi
          echo "runner_private_ip=$runner_private_ip" >> "$GITHUB_OUTPUT"

      - name: Open temporary NSG access
        id: nsg_rule
        uses: bcgov/azure-lz-actions/actions/nsg-jit-rule@v1.2.0
        with:
          subscription-id: ${{ secrets.AZURE_TARGET_SUBSCRIPTION_ID }}
          resource-group: private-network-rg
          nsg-name: private-endpoint-nsg
          rule-name: github-runner-https
          source-ip: ${{ steps.runner_ip.outputs.runner_private_ip }}
          destination-prefixes: 10.20.4.10/32
          destination-ports: 443
          protocol: Tcp
          direction: Inbound
          cleanup-enabled: 'true'

      - name: Use the private resource
        run: curl --fail https://10.20.4.10/health
```

Associate the NSG with the relevant subnet or network interface, and match the
rule direction to the traffic. Other NSGs, route tables, firewalls, and private
endpoint policies can still block connectivity. The lookup selects the first
global IPv4 address on the interface used by the runner's default route. If a
runner has multiple network interfaces or routes, adapt the step to select the
interface that reaches the intended subnet.

## Multiple NSG Targets

Run one matrix job per target NSG. Each job can select its runner label, target
subscription, and NSG independently. Set `fail-fast: false`
so one target's failure does not cancel other jobs before their post-action
cleanup runs. The [example workflow](../../example_workflows/nsg-jit-rule/example-action-workflow.yaml)
accepts JSON target records with required `name`, `runner`, `subscriptionId`,
`resourceGroup`, and `nsgName` fields. The runner IP is discovered separately
inside each matrix job. It also supports
optional `loginSubscriptionId` and per-target `ruleName`, `sourcePrefixes`,
`destinationPrefixes`, `destinationPorts`, `protocol`, `direction`, and `priority`
overrides. Prefix and port overrides are comma-separated strings.

For example, provide this JSON as the workflow's `targets` input:

```json
[
  {
    "name": "private-app-east",
    "runner": "ubuntu-latest",
    "subscriptionId": "00000000-0000-0000-0000-000000000001",
    "resourceGroup": "network-east",
    "nsgName": "private-app-east-nsg",
    "destinationPrefixes": "10.20.4.10/32",
    "destinationPorts": "443"
  },
  {
    "name": "private-app-west",
    "runner": "ubuntu-latest",
    "subscriptionId": "00000000-0000-0000-0000-000000000002",
    "resourceGroup": "network-west",
    "nsgName": "private-app-west-nsg",
    "destinationPrefixes": "10.40.4.10/32",
    "destinationPorts": "443"
  }
]
```

Each action invocation stores cleanup values with GitHub Actions state instead
of shared environment variables. Its post-step receives only that invocation's
target data. The authenticated identity must have access to every target
subscription.

## Inputs

| Input | Required | Description | Default |
| --- | --- | --- | --- |
| `subscription-id` | Yes | NSG subscription; independent of the login subscription | None |
| `resource-group` | Yes | Target resource group | None |
| `nsg-name` | Yes | Target Network Security Group | None |
| `rule-name` | Yes | Base name; the action adds a unique operation suffix | None |
| `destination-ports` | Yes | Ports, ordered ranges, or `*`; ports must be 1-65535 | None |
| `protocol` | Yes | `Tcp`, `Udp`, or `*` | `Tcp` |
| `direction` | Yes | `Inbound` or `Outbound` | `Inbound` |
| `source-ip` | No | Caller-resolved private IPv4; defaults to a `/32` source prefix | Empty |
| `source-prefixes` | No | Comma-separated IPv4 addresses/CIDRs; overrides the `source-ip` default | `source-ip/32` |
| `allow-any-source` | No | Permit `*` or `0.0.0.0/0` sources; avoid unless required | `false` |
| `destination-prefixes` | No | Comma-separated IPv4 addresses/CIDRs or `*` | `*` |
| `priority` | No | NSG rule priority from 100 through 4096 | `3000` |
| `cleanup-enabled` | No | Remove this operation's rule after the job | `true` |

If `source-ip` is omitted, provide a `source-prefixes` value. Wildcard sources
and `0.0.0.0/0` require `allow-any-source: 'true'` and are not recommended.

## Outputs

| Output | Description |
| --- | --- |
| `rule-id` | Azure resource ID of the created rule |
| `rule-name` | Actual unique rule name, including the operation suffix |
| `nsg-name`, `resource-group`, `subscription-id` | Target resource identifiers |
| `source-ip`, `source-cidr`, `source-prefixes` | Source input and effective source scope |
| `destination-prefixes` | Effective destination scope |
| `pre-state`, `post-state` | NSG state before creation and rule state after creation, as JSON |
| `status`, `error` | Main operation result and error; cleanup failure separately fails the job |
| `timestamp`, `operation-id` | Creation timestamp and operation correlation ID |
| `github-run-id`, `github-run-attempt` | GitHub run correlation values |

The action writes creation and cleanup details to the job summary. Each rule
description includes an operation marker; cleanup deletes only a matching rule.
Existing rules are not updated. If removal cannot be verified, the job fails
with manual remediation guidance.

Setting `cleanup-enabled: 'false'` retains the rule and transfers cleanup
responsibility to the caller. Avoid this for temporary access unless required.

## Troubleshooting

- **The runner cannot reach the target:** Confirm VNet connectivity and route
  lookup to a private target. Check NSG association, direction, priority, and
  intervening network controls.
- **Subscription selection fails:** Confirm the OIDC identity can access the
  target `subscription-id`. It may differ from the login subscription.
- **Rule creation is denied:** Check the identity's NSG read/write permissions and resource-group access.
- **Cleanup fails:** The job fails when deletion cannot be verified. Inspect the
  rule name and operation ID, then remove the rule manually if it remains.
- **The actual rule name differs from the input:** The action appends a unique
  suffix. Use the `rule-name` output for verification or later cleanup.

## Maintainer Checks

Run the same validation used in CI and rebuild the committed bundles:

```bash
npm ci
npm test
npm run verify
npm run build
```
