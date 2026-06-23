/**
 * NSG JIT Rule GitHub Action
 *
 * This action creates or updates a Network Security Group (NSG) just-in-time (JIT)
 * access rule in Azure. It manages the lifecycle of temporary access rules for
 * security and compliance purposes.
 *
 * Enterprise Features:
 * - Input validation with detailed error messages
 * - Retry logic with exponential backoff for transient failures
 * - Pre-flight resource verification
 * - Structured audit logging
 * - Safe cleanup integration
 * - Idempotency support
 *
 * @author BC Government
 * @version 1.0.0
 */

const core = require('@actions/core');
const crypto = require('crypto');
const { execSync } = require('child_process');
const { DefaultAzureCredential } = require('@azure/identity');

// Constants
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 1000;
const PRIORITY_MIN = 100;
const PRIORITY_MAX = 4096;
const VALID_PROTOCOLS = ['TCP', 'UDP', '*'];
const VALID_DIRECTIONS = ['Inbound', 'Outbound'];

function toBoolean(value, defaultValue = true) {
  if (value === undefined || value === null || String(value).trim() === '') {
    return defaultValue;
  }
  return String(value).trim().toLowerCase() === 'true';
}

function buildExecutionContext(operationId) {
  return {
    operation_id: operationId,
    run_id: process.env.GITHUB_RUN_ID || '',
    run_attempt: process.env.GITHUB_RUN_ATTEMPT || '',
    actor: process.env.GITHUB_ACTOR || '',
    repository: process.env.GITHUB_REPOSITORY || '',
    workflow: process.env.GITHUB_WORKFLOW || ''
  };
}

function logWithContext(level, message, execution) {
  const prefix = `[op=${execution.operation_id} run=${execution.run_id}/${execution.run_attempt}]`;
  core[level](`${prefix} ${message}`);
}

async function writeSuccessSummary(inputs, sourceIP, duration, execution) {
  const sourceIpDisplay = sourceIP || '(not provided)';
  const sourceCidrDisplay = sourceIP ? `${sourceIP}/32` : '(not derived)';
  await core.summary
    .addHeading('NSG JIT Rule Created')
    .addTable([
      [{ data: 'Property', header: true }, { data: 'Value', header: true }],
      ['Operation ID', execution.operation_id],
      ['Run ID / Attempt', `${execution.run_id} / ${execution.run_attempt}`],
      ['Rule Name', inputs.ruleName],
      ['NSG', inputs.nsgName],
      ['Resource Group', inputs.resourceGroup],
      ['Source IP', sourceIpDisplay],
      ['Source CIDR', sourceCidrDisplay],
      ['Source Prefixes', inputs.sourcePrefixes.join(', ')],
      ['Destination Prefixes', inputs.destinationPrefixes.join(', ')],
      ['Destination Ports', inputs.destinationPorts],
      ['Protocol', inputs.protocol],
      ['Priority', inputs.priority],
      ['Cleanup Enabled', String(inputs.cleanupEnabled)],
      ['Duration', `${duration}s`]
    ])
    .addRaw('Rule cleanup is managed by the action post-step.')
    .write();
}

async function writeFailureSummary(errorMessage, phase, execution) {
  await core.summary
    .addHeading('NSG JIT Rule Failed')
    .addTable([
      [{ data: 'Property', header: true }, { data: 'Value', header: true }],
      ['Operation ID', execution.operation_id],
      ['Run ID / Attempt', `${execution.run_id} / ${execution.run_attempt}`],
      ['Phase', phase],
      ['Error', errorMessage]
    ])
    .addRaw('Suggested checks: OIDC auth, subscription context, resource-group/NSG existence, and RBAC role assignments.')
    .write();
}

/**
 * Retry wrapper with exponential backoff
 */
async function retryWithBackoff(fn, context = '') {
  let lastError;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const isTransient = error.code === 'RequestTimeout' ||
                         error.code === 'ServiceUnavailable' ||
                         error.message?.includes('timeout');

      if (!isTransient || attempt === MAX_RETRIES) {
        throw error;
      }

      const backoffMs = INITIAL_BACKOFF_MS * Math.pow(2, attempt - 1);
      core.warning(`${context} failed (attempt ${attempt}/${MAX_RETRIES}), retrying in ${backoffMs}ms: ${error.message}`);
      await new Promise(resolve => setTimeout(resolve, backoffMs));
    }
  }
  throw lastError;
}

/**
 * Validate and sanitize inputs
 */
function validateInputs(inputs) {
  const errors = [];

  // Validate subscription ID (UUID format)
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(inputs.subscriptionId)) {
    errors.push('Invalid subscription ID format (must be UUID)');
  }

  // Validate resource group name
  if (!/^[a-zA-Z0-9._()-]{1,90}$/.test(inputs.resourceGroup)) {
    errors.push('Invalid resource group name (alphanumeric, dots, underscores, hyphens only, 1-90 chars)');
  }

  // Validate NSG name
  if (!/^[a-zA-Z0-9._()-]{1,80}$/.test(inputs.nsgName)) {
    errors.push('Invalid NSG name (alphanumeric, dots, underscores, hyphens only, 1-80 chars)');
  }

  // Validate rule name
  if (!/^[a-zA-Z0-9._()-]{1,80}$/.test(inputs.ruleName)) {
    errors.push('Invalid rule name (alphanumeric, dots, underscores, hyphens only, 1-80 chars)');
  }

  if (!inputs.sourceIp && !inputs.sourcePrefixesRaw) {
    errors.push('Either source-ip or source-prefixes must be provided');
  }

  // Validate source IP (IPv4)
  if (inputs.sourceIp && !/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(inputs.sourceIp)) {
    errors.push(`Invalid source IP format: ${inputs.sourceIp}. Must be IPv4 address (e.g., 10.0.0.15)`);
  }

  // Validate protocol
  if (!VALID_PROTOCOLS.includes(inputs.protocol.toUpperCase())) {
    errors.push(`Invalid protocol: ${inputs.protocol}. Must be one of: ${VALID_PROTOCOLS.join(', ')}`);
  }

  // Validate direction
  if (!VALID_DIRECTIONS.includes(inputs.direction)) {
    errors.push(`Invalid direction: ${inputs.direction}. Must be 'Inbound' or 'Outbound'`);
  }

  // Validate priority if provided
  if (inputs.priority) {
    const p = parseInt(inputs.priority, 10);
    if (isNaN(p) || p < PRIORITY_MIN || p > PRIORITY_MAX) {
      errors.push(`Invalid priority: ${inputs.priority}. Must be number between ${PRIORITY_MIN}-${PRIORITY_MAX}`);
    }
  }

  // Validate ports format
  if (inputs.destinationPorts !== '*' && !/^([0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*)$/.test(inputs.destinationPorts)) {
    errors.push('Invalid destination ports format. Use single port, range (80-443), or comma-separated list');
  }

  const sourcePrefixDefaults = inputs.sourceIp ? [`${inputs.sourceIp}/32`] : [];
  const sourcePrefixes = normalizePrefixes(inputs.sourcePrefixesRaw, sourcePrefixDefaults);
  const destinationPrefixes = normalizePrefixes(inputs.destinationPrefixesRaw, ['*']);

  for (const prefix of sourcePrefixes) {
    if (!isValidAddressPrefix(prefix)) {
      errors.push(`Invalid source prefix: ${prefix}`);
    }
  }

  for (const prefix of destinationPrefixes) {
    if (!isValidAddressPrefix(prefix)) {
      errors.push(`Invalid destination prefix: ${prefix}`);
    }
  }

  return errors;
}

function isValidAddressPrefix(prefix) {
  if (prefix === '*') return true;
  return /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/.test(prefix);
}

function normalizePrefixes(raw, defaults) {
  const parsed = String(raw || '')
    .split(',')
    .map(p => p.trim())
    .filter(Boolean);

  if (parsed.length > 0) {
    return parsed;
  }

  return defaults;
}

/**
 * Verify Azure context and permissions
 */
async function verifyAzureContext(credential, subscriptionId) {
  try {
    core.debug('Verifying Azure authentication context...');
    await retryWithBackoff(async () => {
      const token = await credential.getToken('https://management.azure.com/.default');
      return token;
    }, 'Azure authentication');
    core.info('Azure authentication verified');
  } catch (error) {
    throw new Error(`Azure authentication failed: ${error.message}. Ensure OIDC is configured correctly.`);
  }
}

/**
 * Check if resource group exists
 */
async function verifyResourceGroup(resourceGroup) {
  try {
    core.debug(`Verifying resource group exists: ${resourceGroup}`);
    // Validate resource group existence via Azure CLI to avoid SDK private internals.
    await retryWithBackoff(async () => {
      const existsOutput = execSync(
        `az group exists --name "${resourceGroup}"`,
        { encoding: 'utf8' }
      ).trim().toLowerCase();

      if (existsOutput !== 'true') {
        throw new Error(`Resource group not found: ${resourceGroup}`);
      }

      // Permission check: list NSGs in the RG to ensure access to Network resources.
      execSync(
        `az network nsg list --resource-group "${resourceGroup}" --query "[].name" -o json`,
        { encoding: 'utf8' }
      );

      return true;
    }, `Verify resource group ${resourceGroup}`);
    core.info(`Resource group verified: ${resourceGroup}`);
  } catch (error) {
    throw new Error(`Resource group verification failed: ${error.message}. Ensure RG exists and you have Network Contributor role.`);
  }
}

/**
 * Check if NSG exists and get current rules
 */
async function getNSGState(resourceGroup, nsgName) {
  try {
    core.debug(`Checking NSG state: ${nsgName}`);
    const output = execSync(
      `az network nsg show --resource-group "${resourceGroup}" --name "${nsgName}" --query '{name:name, id:id, location:location, securityRules:securityRules[].name}' -o json`,
      { encoding: 'utf8' }
    );
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`NSG not found or inaccessible: ${nsgName}. Verify it exists in RG ${resourceGroup}.`);
  }
}

/**
 * Check for existing rule conflicts or stale rules
 */
async function checkExistingRules(resourceGroup, nsgName, ruleBaseName) {
  try {
    core.debug(`Checking for existing rules matching: ${ruleBaseName}`);
    const output = execSync(
      `az network nsg rule list --resource-group "${resourceGroup}" --nsg-name "${nsgName}" --query "[?starts_with(name, '${ruleBaseName}')]" -o json`,
      { encoding: 'utf8' }
    );
    const rules = JSON.parse(output);
    return rules;
  } catch (error) {
    core.warning(`Could not check for existing rules: ${error.message}`);
    return [];
  }
}

/**
 * Create or update NSG rule
 */
async function createOrUpdateRule(inputs, sourceIP) {
  try {
    core.info(`Creating NSG rule: ${inputs.ruleName}`);
    core.debug(
      `Rule configuration: direction=${inputs.direction}, protocol=${inputs.protocol}, ports=${inputs.destinationPorts}, sourcePrefixes=${inputs.sourcePrefixes.join(',')}, destinationPrefixes=${inputs.destinationPrefixes.join(',')}`
    );

    const ruleName = inputs.ruleName;
    const sourceAddressPrefixesArg = inputs.sourcePrefixes.map(prefix => `"${prefix}"`).join(' ');
    const destinationAddressPrefixesArg = inputs.destinationPrefixes.map(prefix => `"${prefix}"`).join(' ');

    const output = execSync(
      `az network nsg rule create ` +
      `--resource-group "${inputs.resourceGroup}" ` +
      `--nsg-name "${inputs.nsgName}" ` +
      `--name "${ruleName}" ` +
      `--priority ${inputs.priority} ` +
      `--direction ${inputs.direction} ` +
      `--access Allow ` +
      `--protocol ${inputs.protocol.toUpperCase()} ` +
      `--source-address-prefixes ${sourceAddressPrefixesArg} ` +
      `--destination-address-prefixes ${destinationAddressPrefixesArg} ` +
      `--destination-port-ranges ${inputs.destinationPorts} ` +
      `--query '{id:id, name:name, priority:priority, direction:direction, sourceAddressPrefix:sourceAddressPrefix}' -o json`,
      { encoding: 'utf8' }
    );

    const rule = JSON.parse(output);
    core.info(`✓ NSG rule created successfully: ${ruleName}`);
    return rule;
  } catch (error) {
    throw new Error(`Failed to create NSG rule: ${error.message}`);
  }
}

/**
 * Verify rule was created and is active
 */
async function verifyRuleCreation(resourceGroup, nsgName, ruleName) {
  try {
    core.debug(`Verifying rule creation: ${ruleName}`);
    const output = execSync(
      `az network nsg rule show --resource-group "${resourceGroup}" --nsg-name "${nsgName}" --name "${ruleName}" -o json`,
      { encoding: 'utf8' }
    );
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`Rule verification failed: ${ruleName} not found after creation`);
  }
}

/**
 * Generate audit log entry
 */
function generateAuditLog(inputs, sourceIP, rule) {
  const sourceCidr = sourceIP ? `${sourceIP}/32` : '';
  return {
    timestamp: new Date().toISOString(),
    action: 'nsg-jit-rule-created',
    operation_id: inputs.operationId,
    github: {
      run_id: process.env.GITHUB_RUN_ID,
      run_attempt: process.env.GITHUB_RUN_ATTEMPT,
      actor: process.env.GITHUB_ACTOR,
      repository: process.env.GITHUB_REPOSITORY,
      workflow: process.env.GITHUB_WORKFLOW,
    },
    azure: {
      subscription_id: inputs.subscriptionId,
      resource_group: inputs.resourceGroup,
      nsg_name: inputs.nsgName,
      rule: {
        name: inputs.ruleName,
        id: rule.id,
        priority: rule.priority,
        direction: rule.direction,
        protocol: inputs.protocol,
        source_ip: sourceIP,
        source_cidr: sourceCidr,
        source_prefixes: inputs.sourcePrefixes,
        destination_ports: inputs.destinationPorts,
        destination_prefixes: inputs.destinationPrefixes,
      }
    },
    status: 'success'
  };
}

function logAuditSummary(audit, execution) {
  const sourcePrefixes = (audit.azure.rule.source_prefixes || []).join(', ');
  const destinationPrefixes = (audit.azure.rule.destination_prefixes || []).join(', ');

  logWithContext('info', 'Audit summary', execution);
  core.info(`  Operation ID: ${audit.operation_id}`);
  core.info(`  Timestamp: ${audit.timestamp}`);
  core.info(`  Subscription: ${audit.azure.subscription_id}`);
  core.info(`  Resource Group: ${audit.azure.resource_group}`);
  core.info(`  NSG: ${audit.azure.nsg_name}`);
  core.info(`  Rule Name: ${audit.azure.rule.name}`);
  core.info(`  Direction/Protocol: ${audit.azure.rule.direction}/${audit.azure.rule.protocol}`);
  core.info(`  Source Prefixes: ${sourcePrefixes}`);
  core.info(`  Destination Prefixes: ${destinationPrefixes}`);
  core.info(`  Destination Ports: ${audit.azure.rule.destination_ports}`);
  core.info(`  Status: ${audit.status}`);

  // Keep full audit data available without cluttering default logs.
  core.debug(`Audit JSON: ${JSON.stringify(audit)}`);
}

/**
 * Main action entry point
 */
async function run() {
  const startTime = Date.now();
  const operationId = crypto.randomUUID();
  const execution = buildExecutionContext(operationId);
  let failurePhase = 'startup';

  try {
    logWithContext('info', 'Starting NSG JIT rule action', execution);

    core.startGroup('📋 Input Validation');
    failurePhase = 'input-validation';

    // Extract and validate inputs
    const inputs = {
      subscriptionId: core.getInput('subscription-id', { required: true }),
      resourceGroup: core.getInput('resource-group', { required: true }),
      nsgName: core.getInput('nsg-name', { required: true }),
      ruleName: core.getInput('rule-name', { required: true }),
      sourceIp: core.getInput('source-ip') || '',
      sourcePrefixesRaw: core.getInput('source-prefixes') || '',
      destinationPorts: core.getInput('destination-ports', { required: true }),
      protocol: core.getInput('protocol', { required: true }),
      direction: core.getInput('direction', { required: true }),
      destinationPrefixesRaw: core.getInput('destination-prefixes') || '',
      priority: core.getInput('priority') || '3000',
      cleanupEnabled: toBoolean(core.getInput('cleanup-enabled')),
      operationId,
    };

    // Validate all inputs
    const validationErrors = validateInputs(inputs);
    if (validationErrors.length > 0) {
      core.endGroup();
      throw new Error(`Validation failed:\n  - ${validationErrors.join('\n  - ')}`);
    }
    core.info('✓ All inputs validated');
    core.endGroup();

    core.startGroup('🔐 Azure Authentication');
    failurePhase = 'azure-authentication';

    // Initialize Azure client and verify context
    const credential = new DefaultAzureCredential();
    await verifyAzureContext(credential, inputs.subscriptionId);

    core.endGroup();

    core.startGroup('🔍 Pre-flight Validation');
    failurePhase = 'preflight-validation';

    // Verify resource group and NSG exist
    await verifyResourceGroup(inputs.resourceGroup);
    const nsgState = await getNSGState(inputs.resourceGroup, inputs.nsgName);
    core.info(`NSG verified: ${nsgState.name} (Location: ${nsgState.location})`);

    // Check for existing/stale rules
    const existingRules = await checkExistingRules(inputs.resourceGroup, inputs.nsgName, inputs.ruleName);
    if (existingRules.length > 0) {
      core.warning(`Found ${existingRules.length} existing rule(s) matching pattern: ${existingRules.map(r => r.name).join(', ')}`);
    }

    core.endGroup();

    core.startGroup('🏃 Source IP Configuration');
    failurePhase = 'source-ip-configuration';

    const sourceIP = inputs.sourceIp;
    const sourcePrefixDefaults = sourceIP ? [`${sourceIP}/32`] : [];
    inputs.sourcePrefixes = normalizePrefixes(inputs.sourcePrefixesRaw, sourcePrefixDefaults);
    inputs.destinationPrefixes = normalizePrefixes(inputs.destinationPrefixesRaw, ['*']);
    if (sourceIP) {
      core.info(`Using provided source IP: ${sourceIP}`);
    } else {
      core.info('No source-ip provided; using explicit source-prefixes only');
    }
    core.info(`Effective source prefixes: ${inputs.sourcePrefixes.join(', ')}`);
    core.info(`Effective destination prefixes: ${inputs.destinationPrefixes.join(', ')}`);

    core.endGroup();

    core.startGroup('🚀 Creating NSG Rule');
    failurePhase = 'rule-create';

    // Create rule with retry logic
    const rule = await retryWithBackoff(
      () => createOrUpdateRule(inputs, sourceIP),
      'NSG rule creation'
    );

    // Verify rule creation
    const verifiedRule = await retryWithBackoff(
      () => verifyRuleCreation(inputs.resourceGroup, inputs.nsgName, inputs.ruleName),
      'Rule verification'
    );

    core.endGroup();

    core.startGroup('📊 Setting Outputs');
    failurePhase = 'outputs';

    // Generate and log audit trail
    const audit = generateAuditLog(inputs, sourceIP, rule);
    logAuditSummary(audit, execution);

    // Set outputs for subsequent steps and cleanup
    core.setOutput('rule-id', rule.id);
    core.setOutput('rule-name', inputs.ruleName);
    core.setOutput('nsg-name', inputs.nsgName);
    core.setOutput('resource-group', inputs.resourceGroup);
    core.setOutput('subscription-id', inputs.subscriptionId);
    core.setOutput('source-ip', sourceIP);
    core.setOutput('source-cidr', sourceIP ? `${sourceIP}/32` : '');
    core.setOutput('source-prefixes', inputs.sourcePrefixes.join(','));
    core.setOutput('destination-prefixes', inputs.destinationPrefixes.join(','));
    core.setOutput('pre-state', JSON.stringify(nsgState));
    core.setOutput('post-state', JSON.stringify(verifiedRule));
    core.setOutput('status', 'created');
    core.setOutput('timestamp', new Date().toISOString());
    core.setOutput('operation-id', execution.operation_id);
    core.setOutput('github-run-id', execution.run_id);
    core.setOutput('github-run-attempt', execution.run_attempt);

    // Export to environment for post-action cleanup
    core.exportVariable('NSG_RULE_NAME', inputs.ruleName);
    core.exportVariable('NSG_NAME', inputs.nsgName);
    core.exportVariable('RESOURCE_GROUP', inputs.resourceGroup);
    core.exportVariable('SUBSCRIPTION_ID', inputs.subscriptionId);
    core.exportVariable('NSG_CLEANUP_ENABLED', String(inputs.cleanupEnabled));
    core.exportVariable('NSG_OPERATION_ID', execution.operation_id);

    core.endGroup();

    const duration = Math.round((Date.now() - startTime) / 1000);
    await writeSuccessSummary(inputs, sourceIP, duration, execution);

  } catch (error) {
    logWithContext('error', `❌ Action failed: ${error.message}`, execution);
    core.setOutput('status', 'failed');
    core.setOutput('error', error.message);
    core.setOutput('operation-id', execution.operation_id);
    core.setOutput('github-run-id', execution.run_id);
    core.setOutput('github-run-attempt', execution.run_attempt);
    // Still export cleanup params even on failure so post-action can attempt cleanup
    const inputs = {
      subscriptionId: core.getInput('subscription-id', { required: false }),
      resourceGroup: core.getInput('resource-group', { required: false }),
      nsgName: core.getInput('nsg-name', { required: false }),
      ruleName: core.getInput('rule-name', { required: false }),
      cleanupEnabled: toBoolean(core.getInput('cleanup-enabled')),
    };
    if (inputs.ruleName && inputs.nsgName && inputs.resourceGroup) {
      core.exportVariable('NSG_RULE_NAME', inputs.ruleName);
      core.exportVariable('NSG_NAME', inputs.nsgName);
      core.exportVariable('RESOURCE_GROUP', inputs.resourceGroup);
      core.exportVariable('SUBSCRIPTION_ID', inputs.subscriptionId);
      core.exportVariable('NSG_CLEANUP_ENABLED', String(inputs.cleanupEnabled));
      core.exportVariable('NSG_OPERATION_ID', execution.operation_id);
    }
    await writeFailureSummary(error.message, failurePhase, execution);
    core.setFailed(error.message);
  }
}

// Execute the action
run();
