# NSG JIT Rule Usage Notes

The [action README](README.md) contains the input/output reference, VNet runner
prerequisites, OIDC setup, and workflow example.

Key integration requirements:

- Resolve the runner's private IPv4 address in the calling workflow. The example
  reads it from the global IPv4 address on the default-route interface.
- If a runner has multiple interfaces or routes, select the interface that
  reaches the target subnet before passing `source-ip` to the action.
- Set `subscription-id` to the NSG's subscription. It may differ from the
  `azure/login` subscription if the identity can access both.
- The action creates a unique rule and removes only a rule with its ownership
  marker. Cleanup failures fail the job.
- For multiple NSGs, use the [matrix example workflow](../../example_workflows/nsg-jit-rule/example-action-workflow.yaml)
  to give each target an independent runner and cleanup lifecycle.
- Commit the regenerated `dist/index.js` and `dist-cleanup/cleanup.js` bundles after source changes.
