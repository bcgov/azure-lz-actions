/**
 * NSG JIT Rule GitHub Action
 *
 * This action creates a uniquely named Network Security Group (NSG) rule in Azure
 * and removes it after the workflow job completes.
 *
 * Enterprise Features:
 * - Input validation with detailed error messages
 * - Retry logic with exponential backoff for transient failures
 * - Pre-flight resource verification
 * - Structured audit logging
 * - Ownership-checked cleanup
 *
 * @author BC Government
 * @version 1.0.0
 */

const core = require('@actions/core');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const {
  buildCreateRuleArgs,
  isNotFoundError,
  normalizeDirection,
  normalizePrefixes,
  operationRuleName,
  ownershipDescription,
  selectPriority,
  toBoolean,
  validateInputs
} = require('./validation');

// Constants
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 1000;

function runAzureCli(args, subscriptionId, execFile = execFileSync) {
  const scopedArgs = subscriptionId ? [...args, '--subscription', subscriptionId] : args;
  return execFile('az', scopedArgs, { encoding: 'utf8', windowsHide: true });
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
  const sourceCidr = inputs.sourcePrefixes.length === 1 && inputs.sourcePrefixes[0] !== '*'
    ? (inputs.sourcePrefixes[0].includes('/') ? inputs.sourcePrefixes[0] : `${inputs.sourcePrefixes[0]}/32`)
    : '';
  const sourceCidrDisplay = sourceCidr || '(not singular)';
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
 * Verify Azure context and permissions
 */
async function verifyAzureContext(subscriptionId) {
  try {
    core.debug(`Verifying Azure CLI authentication and target subscription ${subscriptionId}...`);
    await retryWithBackoff(async () => {
      const selectedSubscription = runAzureCli(['account', 'show', '--query', 'id', '-o', 'tsv'], subscriptionId).trim();
      if (selectedSubscription.toLowerCase() !== subscriptionId.toLowerCase()) {
        throw new Error(`Azure CLI selected subscription ${selectedSubscription}, expected ${subscriptionId}`);
      }
      const token = runAzureCli([
        'account', 'get-access-token', '--resource', 'https://management.azure.com/',
        '--query', 'accessToken', '-o', 'tsv'
      ], subscriptionId).trim();
      if (!token) throw new Error('Azure CLI returned an empty management token');
    }, 'Azure CLI authentication');
    core.info(`Azure authentication and subscription verified: ${subscriptionId}`);
  } catch (error) {
    throw new Error(`Azure CLI authentication or target subscription access failed: ${error.message}. Ensure azure/login completed and the identity can access the target subscription.`);
  }
}

/**
 * Check if NSG exists and get current rules
 */
async function getNSGState(resourceGroup, nsgName, subscriptionId) {
  try {
    core.debug(`Checking NSG state: ${nsgName}`);
    const output = runAzureCli([
      'network', 'nsg', 'show', '--resource-group', resourceGroup, '--name', nsgName,
      '--query', '{name:name, id:id, location:location, securityRules:securityRules[].{priority:priority,direction:direction}}', '-o', 'json'
    ], subscriptionId);
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`NSG not found or inaccessible: ${nsgName}. Verify it exists in RG ${resourceGroup}.`);
  }
}

async function getRule(resourceGroup, nsgName, ruleName, subscriptionId) {
  try {
    const output = runAzureCli([
      'network', 'nsg', 'rule', 'show', '--resource-group', resourceGroup,
      '--nsg-name', nsgName, '--name', ruleName, '-o', 'json'
    ], subscriptionId);
    return JSON.parse(output);
  } catch (error) {
    if (isNotFoundError(error)) return null;
    throw error;
  }
}

async function createRule(inputs, subscriptionId) {
  try {
    core.info(`Creating NSG rule: ${inputs.ruleName}`);
    core.debug(
      `Rule configuration: direction=${inputs.direction}, protocol=${inputs.protocol}, ports=${inputs.destinationPorts}, sourcePrefixes=${inputs.sourcePrefixes.join(',')}, destinationPrefixes=${inputs.destinationPrefixes.join(',')}`
    );

    const output = runAzureCli(buildCreateRuleArgs(inputs), subscriptionId);

    const rule = JSON.parse(output);
    core.info(`NSG rule created successfully: ${inputs.ruleName}`);
    return rule;
  } catch (error) {
    throw new Error(`Failed to create NSG rule: ${error.message}`);
  }
}

async function createRuleWithAvailablePriority(inputs, subscriptionId, requestedPriority) {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await retryWithBackoff(() => createRule(inputs, subscriptionId), 'NSG rule creation');
    } catch (error) {
      const priorityConflict = /SecurityRuleConflict|priority/i.test(error.message || '');
      if (requestedPriority || !priorityConflict || attempt === MAX_RETRIES) throw error;

      const currentState = await getNSGState(inputs.resourceGroup, inputs.nsgName, subscriptionId);
      inputs.priority = selectPriority(currentState.securityRules, inputs.direction, '');
      core.warning(`Priority conflict; retrying with available priority ${inputs.priority}`);
    }
  }
}

/**
 * Verify rule was created and is active
 */
async function verifyRuleCreation(resourceGroup, nsgName, ruleName, subscriptionId) {
  try {
    core.debug(`Verifying rule creation: ${ruleName}`);
    const output = runAzureCli([
      'network', 'nsg', 'rule', 'show', '--resource-group', resourceGroup,
      '--nsg-name', nsgName, '--name', ruleName, '-o', 'json'
    ], subscriptionId);
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

function saveCleanupState(inputs, execution, actionCore = core) {
  actionCore.saveState('rule-name', inputs.ruleName);
  actionCore.saveState('nsg-name', inputs.nsgName);
  actionCore.saveState('resource-group', inputs.resourceGroup);
  actionCore.saveState('subscription-id', inputs.subscriptionId);
  actionCore.saveState('ownership-description', inputs.ownershipDescription);
  actionCore.saveState('cleanup-enabled', String(inputs.cleanupEnabled));
  actionCore.saveState('operation-id', execution.operation_id);
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
      allowAnySource: core.getInput('allow-any-source'),
      destinationPorts: core.getInput('destination-ports', { required: true }),
      protocol: core.getInput('protocol'),
      direction: core.getInput('direction'),
      destinationPrefixesRaw: core.getInput('destination-prefixes') || '',
      priority: core.getInput('priority'),
      cleanupEnabled: core.getInput('cleanup-enabled'),
      operationId,
    };

    // Validate all inputs
    const validationErrors = validateInputs(inputs);
    if (validationErrors.length > 0) {
      core.endGroup();
      throw new Error(`Validation failed:\n  - ${validationErrors.join('\n  - ')}`);
    }
    inputs.cleanupEnabled = toBoolean(inputs.cleanupEnabled);
    inputs.direction = normalizeDirection(inputs.direction);
    core.info('✓ All inputs validated');
    core.endGroup();

    core.startGroup('🔐 Azure Authentication');
    failurePhase = 'azure-authentication';

    await verifyAzureContext(inputs.subscriptionId);

    core.endGroup();

    core.startGroup('🔍 Pre-flight Validation');
    failurePhase = 'preflight-validation';

    // Verify the target NSG directly; this also works with NSG-scoped RBAC.
    const nsgState = await getNSGState(inputs.resourceGroup, inputs.nsgName, inputs.subscriptionId);
    core.info(`NSG verified: ${nsgState.name} (Location: ${nsgState.location})`);

    core.endGroup();

    core.startGroup('🏃 Source IP Configuration');
    failurePhase = 'source-ip-configuration';

    const sourceIP = inputs.sourceIp;
    const sourcePrefixDefaults = sourceIP ? [`${sourceIP}/32`] : [];
    inputs.sourcePrefixes = normalizePrefixes(inputs.sourcePrefixesRaw, sourcePrefixDefaults);
    inputs.destinationPrefixes = normalizePrefixes(inputs.destinationPrefixesRaw, ['*']);
    const requestedPriority = inputs.priority;
    inputs.priority = selectPriority(nsgState.securityRules, inputs.direction, requestedPriority);
    inputs.ruleName = operationRuleName(inputs.ruleName, operationId);
    inputs.ownershipDescription = ownershipDescription(operationId);
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

    const existingRule = await getRule(inputs.resourceGroup, inputs.nsgName, inputs.ruleName, inputs.subscriptionId);
    if (existingRule) {
      throw new Error(`Generated NSG rule name already exists: ${inputs.ruleName}. Refusing to modify an existing rule.`);
    }

    saveCleanupState(inputs, execution);

    // Create rule with retry logic
    const rule = await createRuleWithAvailablePriority(inputs, inputs.subscriptionId, requestedPriority);

    // Verify rule creation
    const verifiedRule = await retryWithBackoff(
      () => verifyRuleCreation(inputs.resourceGroup, inputs.nsgName, inputs.ruleName, inputs.subscriptionId),
      'Rule verification'
    );
    if (verifiedRule.description !== inputs.ownershipDescription) {
      throw new Error(`Created rule ownership check failed for ${inputs.ruleName}`);
    }

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
    core.setOutput('source-cidr', inputs.sourcePrefixes.length === 1 && inputs.sourcePrefixes[0] !== '*'
      ? (inputs.sourcePrefixes[0].includes('/') ? inputs.sourcePrefixes[0] : `${inputs.sourcePrefixes[0]}/32`)
      : '');
    core.setOutput('source-prefixes', inputs.sourcePrefixes.join(','));
    core.setOutput('destination-prefixes', inputs.destinationPrefixes.join(','));
    core.setOutput('pre-state', JSON.stringify({
      ...nsgState,
      securityRules: nsgState.securityRules.map(rule => rule.name)
    }));
    core.setOutput('post-state', JSON.stringify(verifiedRule));
    core.setOutput('status', 'created');
    core.setOutput('timestamp', new Date().toISOString());
    core.setOutput('operation-id', execution.operation_id);
    core.setOutput('github-run-id', execution.run_id);
    core.setOutput('github-run-attempt', execution.run_attempt);

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
    await writeFailureSummary(error.message, failurePhase, execution);
    core.setFailed(error.message);
  }
}

if (require.main === module) {
  run();
}

module.exports = { run, runAzureCli, saveCleanupState, validateInputs };
