/**
 * NSG JIT Rule Cleanup Post-Action
 *
 * Automatically reverts (deletes) NSG rules created by the nsg-jit-rule action.
 * This is designed to run as a post-action for automatic cleanup/garbage collection.
 *
 * Enterprise Features:
 * - Graceful handling of missing rules
 * - Cleanup verification
 * - Comprehensive audit logging
 * - Safe error recovery
 *
 * @author BC Government
 * @version 1.0.0
 */

const core = require('@actions/core');
const { execFileSync } = require('child_process');
const { isNotFoundError } = require('./validation');

const MAX_CLEANUP_RETRIES = 3;
const MAX_VERIFY_ATTEMPTS = 12;

function runAzureCli(args, subscriptionId) {
  const scopedArgs = subscriptionId ? [...args, '--subscription', subscriptionId] : args;
  return execFileSync('az', scopedArgs, { encoding: 'utf8', windowsHide: true });
}

/**
 * Retry wrapper for cleanup operations
 */
async function retryCleanup(fn, context = '') {
  let lastError;
  for (let attempt = 1; attempt <= MAX_CLEANUP_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const isTransient = ['RequestTimeout', 'ServiceUnavailable', 'ECONNRESET', 'ETIMEDOUT'].includes(error.code) ||
        /timeout|temporarily unavailable/i.test(error.message || '');
      if (isTransient && attempt < MAX_CLEANUP_RETRIES) {
        const backoffMs = 500 * Math.pow(2, attempt - 1);
        core.warning(`${context} attempt ${attempt} failed, retrying in ${backoffMs}ms: ${error.message}`);
        await new Promise(resolve => setTimeout(resolve, backoffMs));
      } else {
        throw error;
      }
    }
  }
  throw lastError;
}

/**
 * Delete NSG rule
 */
async function getRule(resourceGroup, nsgName, ruleName, subscriptionId, runAz) {
  try {
    const output = runAz([
      'network', 'nsg', 'rule', 'show', '--resource-group', resourceGroup,
      '--nsg-name', nsgName, '--name', ruleName, '-o', 'json'
    ], subscriptionId);
    return JSON.parse(output);
  } catch (error) {
    if (isNotFoundError(error)) return null;
    throw error;
  }
}

async function deleteRule({ resourceGroup, nsgName, ruleName, subscriptionId, expectedDescription, runAz }) {
  core.debug(`Checking ownership before deleting rule: ${ruleName}`);
  const rule = await getRule(resourceGroup, nsgName, ruleName, subscriptionId, runAz);
  if (!rule) {
    core.info(`Rule is already absent: ${ruleName}`);
    return false;
  }

  if (rule.description !== expectedDescription) {
    throw new Error(`Refusing to delete ${ruleName}: operation ownership marker does not match`);
  }

  runAz([
    'network', 'nsg', 'rule', 'delete', '--resource-group', resourceGroup,
    '--nsg-name', nsgName, '--name', ruleName
  ], subscriptionId);
  return true;
}

async function verifyCleanup({ resourceGroup, nsgName, ruleName, subscriptionId, expectedDescription, runAz, sleep }) {
  for (let attempt = 1; attempt <= MAX_VERIFY_ATTEMPTS; attempt++) {
    const rule = await getRule(resourceGroup, nsgName, ruleName, subscriptionId, runAz);
    if (!rule) {
      core.info(`Rule deletion verified: ${ruleName}`);
      return;
    }
    if (rule.description !== expectedDescription) {
      throw new Error(`Rule ${ruleName} changed ownership during cleanup; refusing further action`);
    }

    const waitTime = Math.min(1000 * attempt, 5000);
    core.debug(`Rule still exists (attempt ${attempt}/${MAX_VERIFY_ATTEMPTS}), waiting ${waitTime}ms`);
    await sleep(waitTime);
  }

  throw new Error(`Failed to verify deletion of rule ${ruleName} after ${MAX_VERIFY_ATTEMPTS} attempts`);
}

async function cleanup({ actionCore = core, runAz = runAzureCli, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  const startTime = Date.now();
  const operationId = actionCore.getState('operation-id') || 'unknown';
  const cleanupLog = {
    start_time: new Date().toISOString(),
    action: 'nsg-jit-rule-cleanup',
    operation_id: operationId
  };

  try {
    actionCore.startGroup('Cleanup: Removing NSG Rule');

    const ruleName = actionCore.getState('rule-name');
    const nsgName = actionCore.getState('nsg-name');
    const resourceGroup = actionCore.getState('resource-group');
    const subscriptionId = actionCore.getState('subscription-id');
    const expectedDescription = actionCore.getState('ownership-description');
    const cleanupEnabled = (actionCore.getState('cleanup-enabled') || 'true').toLowerCase() === 'true';

    if (!cleanupEnabled) {
      actionCore.warning('Cleanup explicitly disabled by input. Rule will be retained.');
      await actionCore.summary
        .addHeading('NSG JIT Rule Cleanup Skipped')
        .addTable([
          [{ data: 'Property', header: true }, { data: 'Value', header: true }],
          ['Operation ID', operationId],
          ['Reason', 'cleanup-enabled input set to false']
        ])
        .write();
      actionCore.endGroup();
      return;
    }

    if (!ruleName || !nsgName || !resourceGroup) {
      actionCore.warning('No rule was registered for cleanup; no NSG rule was changed.');
      actionCore.endGroup();
      return;
    }
    if (!subscriptionId || !expectedDescription) {
      throw new Error('Cleanup subscription or ownership marker is missing; refusing to delete any rule');
    }

    actionCore.info(`Cleanup target: ${subscriptionId}/${resourceGroup}/${nsgName}/${ruleName}`);

    await retryCleanup(
      () => deleteRule({ resourceGroup, nsgName, ruleName, subscriptionId, expectedDescription, runAz }),
      'Rule deletion'
    );

    await retryCleanup(
      () => verifyCleanup({ resourceGroup, nsgName, ruleName, subscriptionId, expectedDescription, runAz, sleep }),
      'Cleanup verification'
    );

    actionCore.endGroup();

    const duration = Math.round((Date.now() - startTime) / 1000);

    actionCore.info(`Cleanup complete for operation ${operationId}; removed rule ${ruleName} in ${duration}s`);

    await actionCore.summary
      .addHeading('NSG JIT Rule Cleanup Complete')
      .addTable([
        [{ data: 'Property', header: true }, { data: 'Value', header: true }],
        ['Operation ID', operationId],
        ['Rule Name', ruleName],
        ['NSG', nsgName],
        ['Resource Group', resourceGroup],
        ['Duration', `${duration}s`],
        ['Status', 'Removed']
      ])
      .write();

    cleanupLog.status = 'success';
    cleanupLog.duration_ms = Date.now() - startTime;
    cleanupLog.rule_removed = ruleName;

    actionCore.endGroup();

  } catch (error) {
    actionCore.error(`Cleanup failed: ${error.message}`);
    cleanupLog.status = 'error';
    cleanupLog.error = error.message;
    cleanupLog.duration_ms = Date.now() - startTime;

    actionCore.warning('The workflow will fail because temporary NSG access could not be confirmed as removed. Check the rule and remove it manually if it remains.');
    actionCore.setFailed(`NSG JIT cleanup failed: ${error.message}`);
  }

  cleanupLog.end_time = new Date().toISOString();
  actionCore.debug(`Cleanup audit log: ${JSON.stringify(cleanupLog)}`);
}

if (require.main === module) {
  cleanup().catch(error => {
    core.setFailed(`NSG JIT cleanup failed: ${error.message}`);
  });
}

module.exports = { cleanup, deleteRule, getRule, runAzureCli, verifyCleanup };
